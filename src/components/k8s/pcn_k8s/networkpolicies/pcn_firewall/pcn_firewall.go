package pcnfirewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	//	TODO-ON-MERGE: change these to the polycube path
	pcn_controllers "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/controllers"
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"

	log "github.com/sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"
)

const (
	polycubePath string = "/polycube/v1/"
	firewallPath string = "firewall/"
)

// PcnFirewall is the interface of the firewall manager.
type PcnFirewall interface {
	Link(*core_v1.Pod) bool
	Unlink(*core_v1.Pod, UnlinkOperation) (bool, int)
	LinkedPods() map[k8s_types.UID]string
	IsPolicyEnforced(string) bool
	Selector() (map[string]string, string)
	Name() string
	EnforcePolicy(string, string, meta_v1.Time, []k8sfirewall.ChainRule, []k8sfirewall.ChainRule, []pcn_types.FirewallAction)
	CeasePolicy(string)
	Destroy()
}

// FirewallManager is the implementation of the firewall manager.
type FirewallManager struct {
	// podController is the pod controller
	podController pcn_controllers.PodController
	// fwAPI is the low level firewall api
	fwAPI k8sfirewall.FirewallAPI
	// ingressRules contains the ingress rules divided by policy
	//ingressRules map[string]map[int32]k8sfirewall.ChainRule
	ingressRules map[string][]k8sfirewall.ChainRule
	// egressRules contains the egress rules divided by policy
	//egressRules map[string]map[int32]k8sfirewall.ChainRule
	egressRules map[string][]k8sfirewall.ChainRule
	// ingressIPs serves as a cache for finding deleting rules without looping through all ingress rules
	//ingressIPs map[string]map[int32]string
	// egressIPs serves as a cache for finding deleting rules without looping through all egress rules
	//egressIPs map[string]map[int32]string
	// linkedPods is a map of pods monitored by this firewall manager
	linkedPods map[k8s_types.UID]string
	// Name is the name of this firewall manager
	name string
	// log is a new entry in logger
	log *log.Logger
	// lock is firewall manager's main lock
	lock sync.Mutex
	// ingressID is the first usable ingress ID
	//ingressID int32
	// egressID is the first usable egress ID
	//egressID int32
	// ingressDefaultAction is the default action for ingress
	ingressDefaultAction string
	// egressDefaultAction is the default action for egress
	egressDefaultAction string
	// ingressPoliciesCount is the count of ingress policies enforced
	ingressPoliciesCount int
	// egressPoliciesCount is the count of egress policies enforced
	egressPoliciesCount int
	// policyTypes is a map of policies types enforced. Used to know how the default action should be handled.
	policyTypes map[string]string
	// policyActions contains a map of actions to be taken when a pod event occurs
	policyActions map[string]*subscriptions
	// selector defines what kind of pods this firewall is monitoring
	selector selector
	// node is the node in which we are currently running
	node *core_v1.Node
	// priorities is the list of priorities
	priorities []policyPriority
}

type policyPriority struct {
	policyName string
	timestamp  time.Time
}

// ruleIDs acts as a cache for knowing the rule IDs to which an IP is linked to,
// so we can delete them instantly, no need to loop through all rules to find them.
type ruleIDs struct {
	ingress []int32
	egress  []int32
}

// subscriptions contains the templates (here called actions) that should be used when a pod event occurs,
// and the functions to be called when we need to unsubscribe.
type subscriptions struct {
	actions        map[string]*pcn_types.ParsedRules
	unsubscriptors []func()
}

// selector is the
type selector struct {
	namespace string
	labels    map[string]string
}

// StartFirewall will start a new firewall manager
func StartFirewall(API k8sfirewall.FirewallAPI, podController pcn_controllers.PodController, name, namespace string, labels map[string]string, node *core_v1.Node) PcnFirewall {
	//	This method is unexported by design: *only* the network policy manager is supposed to create firewall managers.
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": FWM, "method": "StartFirewall()"})
	l.Infoln("Starting Firewall Manager, with name", name)

	manager := &FirewallManager{
		//	Rules
		//ingressRules: map[string]map[int32]k8sfirewall.ChainRule{},
		//egressRules:  map[string]map[int32]k8sfirewall.ChainRule{},
		ingressRules: map[string][]k8sfirewall.ChainRule{},
		egressRules:  map[string][]k8sfirewall.ChainRule{},
		//	External APIs
		fwAPI:         API,
		podController: podController,
		//	Logger and name
		log:  log.New(),
		name: "FirewallManager-" + name,
		//	Selector
		selector: selector{
			namespace: namespace,
			labels:    labels,
		},
		//	The counts
		ingressPoliciesCount: 0,
		egressPoliciesCount:  0,
		//	Policy types and actions
		policyTypes:   map[string]string{},
		policyActions: map[string]*subscriptions{},
		//	The IDs
		//ingressID: FirstIngressID,
		//egressID:  FirstEgressID,
		//	Linked pods
		linkedPods: map[k8s_types.UID]string{},
		//	The default actions
		ingressDefaultAction: pcn_types.ActionForward,
		egressDefaultAction:  pcn_types.ActionForward,
		//	IPs caches
		//ingressIPs: map[string]map[int32]string{},
		//egressIPs:  map[string]map[int32]string{},
		node:       node,
		priorities: []policyPriority{},
	}

	return manager
}

// Link adds a new pod to the list of pods that must be managed by this firewall manager.
// Best practice is to only link similar pods (e.g.: same labels, same namespace, same node) to a firewall manager.
// It returns TRUE if the pod was inserted, FALSE if it already existed or an error occurred
func (d *FirewallManager) Link(pod *core_v1.Pod) bool {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "Link(" + pod.Name + ")"})

	d.lock.Lock()
	defer d.lock.Unlock()

	podIP := pod.Status.PodIP
	podUID := pod.UID
	//name := "fw-" + podIP
	//name := podIP

	//-------------------------------------
	//	Check firewall health and pod presence
	//-------------------------------------
	/*if ok, err := d.isFirewallOk(name); !ok {
		l.Errorf("Could not link firewall for pod %s: %s", podIP, err.Error())
		return false
	}*/
	_, alreadyLinked := d.linkedPods[podUID]
	if alreadyLinked {
		return false
	}

	// init its firewall
	d.initFirewall(podIP)

	//-------------------------------------
	//	Extract the rules
	//-------------------------------------
	//	We are going to get all rules regardless of the policy they belong to, so we can make a single http request.
	ingressRules := []k8sfirewall.ChainRule{}
	egressRules := []k8sfirewall.ChainRule{}

	if len(d.ingressRules) > 0 || len(d.egressRules) > 0 {
		var waiter sync.WaitGroup
		waiter.Add(2)

		// -- ingress
		go func() {
			defer waiter.Done()
			for _, rules := range d.ingressRules {
				for _, rule := range rules {
					ingressRules = append(ingressRules, rule)
				}
			}
		}()

		// -- egress
		go func() {
			defer waiter.Done()
			for _, rules := range d.egressRules {
				for _, rule := range rules {
					egressRules = append(egressRules, rule)
				}
			}
		}()
		waiter.Wait()
	}

	//-------------------------------------
	//	Inject rules and change default actions
	//-------------------------------------
	if len(ingressRules) > 0 || len(egressRules) > 0 {
		if err := d.injecter(podIP, ingressRules, egressRules, nil, 1, 1); err != nil {
			//	injecter fails only if pod's firewall is not ok (it is dying or crashed or not found), so there's no point in going on.
			l.Warningf("Injecter encountered an error upon linking the pod: %s. Will stop here.", err)
			return false
		}
	}

	// -- ingress
	err := d.updateDefaultAction(podIP, "ingress", d.ingressDefaultAction)
	if err != nil {
		l.Errorln("Could not update the default ingress action:", err)
	} else {
		_, err := d.applyRules(podIP, "ingress")
		if err != nil {
			l.Errorln("Could not apply ingress rules:", err)
		}
	}

	// -- egress
	err = d.updateDefaultAction(podIP, "egress", d.egressDefaultAction)
	if err != nil {
		l.Errorln("Could not update the default egress action:", err)
	} else {
		_, err := d.applyRules(podIP, "egress")
		if err != nil {
			l.Errorln("Could not apply egress rules:", err)
		}
	}

	//-------------------------------------
	//	Finally, link it
	//-------------------------------------
	//	From now on, when this firewall manager will react to events, this pod's firewall will be updated as well.
	d.linkedPods[podUID] = podIP
	return true
}

func (d *FirewallManager) marshal(rule k8sfirewall.ChainRule) ([]byte, error) {
	data, err := json.Marshal(&rule)
	if err != nil {
		log.Errorln("Cannot marshal to json:", err)
		return nil, err
	}
	return data, nil
}

func (d *FirewallManager) initFirewall(ip string) error {
	//	Create the firewall
	createFirewall := func(ip string) error {
		resp, err := http.Post("http://"+ip+":9000"+polycubePath+firewallPath+"fw", "application/json", nil)
		if err != nil {
			log.Infoln("Could not create firewall:", err, resp)
			return err
		}

		return nil
	}

	//	Append the default rules
	appendDefaultIngressRule := func(ip string) error {
		endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/ingress/append/"
		rule := k8sfirewall.ChainRule{
			Action: "forward",
			Dport:  9000,
		}
		data, err := d.marshal(rule)
		if err != nil {
			return err
		}

		req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer(data))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{}
		_, err = client.Do(req)
		if err != nil {
			log.Errorln("Error while trying to send request:", err)
			return err
		}
		return nil
	}

	appendDefaultEgressRule := func(ip string) error {
		endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/egress/append/"
		rule := k8sfirewall.ChainRule{
			Action: "forward",
			Sport:  9000,
		}
		data, err := d.marshal(rule)
		if err != nil {
			return err
		}
		req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer(data))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{}
		_, err = client.Do(req)
		if err != nil {
			log.Errorln("Error while trying to send request:", err)
			return err
		}

		return nil
	}

	//	Set it as async
	setAsync := func(ip string) bool {
		jsonStr := []byte(`true`)
		client := http.Client{}

		req, err := http.NewRequest("PATCH", "http://"+ip+":9000"+polycubePath+firewallPath+"fw/interactive", bytes.NewBuffer(jsonStr))
		if err != nil {
			log.Infoln("Could not set firewall as asynchronous", err, req)
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			log.Infoln("Could not set firewall as asynchronous", err, resp)
			return false
		}
		defer resp.Body.Close()
		return true
	}

	// Attach it
	attach := func(ip string) error {
		var jsonStr = []byte(`{"cube":"fw", "port":"eth0"}`)
		resp, err := http.Post("http://"+ip+":9000"+polycubePath+"attach", "application/json", bytes.NewBuffer(jsonStr))
		if err != nil {
			log.Errorln("Could not attach firewall:", err, resp)
			return err
		}

		return nil
	}

	//-------------------------------------
	//	Entry Point
	//-------------------------------------

	if err := createFirewall(ip); err != nil {
		return err
	}

	if err := appendDefaultIngressRule(ip); err != nil {
		return err
	}

	if err := appendDefaultEgressRule(ip); err != nil {
		return err
	}

	setAsync(ip)

	if err := attach(ip); err != nil {
		return err
	}

	return nil
}

// Unlink removes the provided pod from the list of monitored ones by this firewall manager.
// If the second argument is TRUE, then the provided pod's firewall will be destroyed as well.
// It returns FALSE if the pod was not among the monitored ones, and the number of remaining pods linked.
func (d *FirewallManager) Unlink(pod *core_v1.Pod, then UnlinkOperation) (bool, int) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "Unlink(" + pod.Name + ")"})

	d.lock.Lock()
	defer d.lock.Unlock()

	podUID := pod.UID
	//name := "fw-" + pod.Status.PodIP
	name := pod.Status.PodIP

	_, ok := d.linkedPods[podUID]
	if !ok {
		//	This pod was not even linked
		return false, len(d.linkedPods)
	}

	//	Should I also destroy its firewall?
	switch then {
	case CleanFirewall:
		if i, e := d.cleanFw(name); i != nil || e != nil {
			l.Warningln("Could not properly clean firewall for the provided pod.")
		} else {
			d.updateDefaultAction(name, "ingress", pcn_types.ActionForward)
			d.applyRules(name, "ingress")
			d.updateDefaultAction(name, "egress", pcn_types.ActionForward)
			d.applyRules(name, "egress")
		}
	case DestroyFirewall:
		if err := d.destroyFw(name); err != nil {
			l.Warningln("Could not delete firewall for the provided pod.")
		}
	}

	delete(d.linkedPods, podUID)
	return true, len(d.linkedPods)
}

// LinkedPods returns a map of pods monitored by this firewall manager.
func (d *FirewallManager) LinkedPods() map[k8s_types.UID]string {
	d.lock.Lock()
	defer d.lock.Unlock()

	return d.linkedPods
}

// Name returns the name of this firewall manager
func (d *FirewallManager) Name() string {
	return d.name
}

// EnforcePolicy enforces a new policy (e.g.: injects rules in all linked firewalls)
func (d *FirewallManager) EnforcePolicy(policyName, policyType string, policyTime meta_v1.Time, ingress, egress []k8sfirewall.ChainRule, actions []pcn_types.FirewallAction) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "EnforcePolicy"})
	l.Infof("firewall %s is going to enforce policy %s", d.name, policyName)

	//	Only one policy at a time, please
	d.lock.Lock()
	defer d.lock.Unlock()

	//-------------------------------------
	//	Define the actions
	//-------------------------------------

	d.definePolicyActions(policyName, actions)

	//-------------------------------------
	//	Calculate the IDs concurrently
	//-------------------------------------

	ingressIDs, egressIDs := d.buildIDs(policyName, "", ingress, egress)

	//-------------------------------------
	//	Update default actions
	//-------------------------------------

	//	So we just enforced a new policy. The final step is to change default actions (if needed)
	d.policyTypes[policyName] = policyType
	d.updateCounts("increase", policyType)

	//-------------------------------------
	//	Set its priority
	//-------------------------------------

	t := 0
	iStartFrom := int32(1)
	eStartFrom := int32(1)
	for i, thisPolicy := range d.priorities {
		if policyTime.Time.Before(thisPolicy.timestamp) {
			t = i
			break
		}
		t++

		// jump the rules
		iStartFrom += int32(len(d.ingressRules[thisPolicy.policyName]))
		eStartFrom += int32(len(d.egressRules[thisPolicy.policyName]))
	}

	temp := []policyPriority{}
	temp = append(temp, d.priorities[:t]...)
	temp = append(temp, policyPriority{
		policyName: policyName,
		timestamp:  policyTime.Time,
	})
	temp = append(temp, d.priorities[t:]...)
	d.priorities = temp

	//-------------------------------------
	//	Inject the rules on each firewall
	//-------------------------------------

	if len(d.linkedPods) < 1 {
		l.Infoln("There are no linked pods. Stopping here.")
		return
	}

	var injectWaiter sync.WaitGroup
	injectWaiter.Add(len(d.linkedPods))

	for _, ip := range d.linkedPods {
		//name := "fw-" + ip
		name := ip
		go d.injecter(name, ingressIDs, egressIDs, &injectWaiter, iStartFrom, eStartFrom)
	}
	injectWaiter.Wait()
}

// updateCounts updates the internal counts of policies types enforced, making sure default actions are respected.
// This is just a convenient method used to keep core methods (EnforcePolicy and CeasePolicy) as clean and readable as possible.
// When possible, this function is used in place of increaseCount or decreaseCount, as it is preferrable to do it like this.
func (d *FirewallManager) updateCounts(operation, policyType string) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "updateCounts(" + operation + "," + policyType + ")"})

	//-------------------------------------
	//	Increase
	//-------------------------------------

	increase := func() {
		directions := []string{}

		//	-- Increase the counts and append the directions to update accordingly.
		if (policyType == "ingress" || policyType == "*") && d.increaseCount("ingress") {
			directions = append(directions, "ingress")
		}
		if (policyType == "egress" || policyType == "*") && d.increaseCount("egress") {
			directions = append(directions, "egress")
		}

		if len(directions) < 1 {
			return
		}

		// -- Let's now update the default actions.
		for _, ip := range d.linkedPods {
			//name := "fw-" + ip
			name := ip
			for _, direction := range directions {
				err := d.updateDefaultAction(name, direction, pcn_types.ActionDrop)
				if err != nil {
					l.Errorf("Could not update default action for firewall %s: %s", name, direction)
				} else {
					if _, err := d.applyRules(name, direction); err != nil {
						l.Errorf("Could not apply rules for firewall %s: %s", name, direction)
					}
				}
			}
		}
	}

	//-------------------------------------
	//	Decrease
	//-------------------------------------

	decrease := func() {
		directions := []string{}

		//	-- Decrease the counts and append the directions to update accordingly.
		if (policyType == "ingress" || policyType == "*") && d.decreaseCount("ingress") {
			directions = append(directions, "ingress")
		}
		if (policyType == "egress" || policyType == "*") && d.decreaseCount("egress") {
			directions = append(directions, "egress")
		}

		if len(directions) < 1 {
			return
		}

		// -- Let's now update the default actions.
		for _, ip := range d.linkedPods {
			//name := "fw-" + ip
			name := ip
			for _, direction := range directions {
				err := d.updateDefaultAction(name, direction, pcn_types.ActionForward)
				if err != nil {
					l.Errorf("Could not update default action for firewall %s: %s", name, direction)
				} else {
					if _, err := d.applyRules(name, direction); err != nil {
						l.Errorf("Could not apply rules for firewall %s: %s", name, direction)
					}
				}
			}
		}
	}

	switch operation {
	case "increase":
		increase()
	case "decrease":
		decrease()
	}
}

// increaseCount increases the count of policies enforced and changes the default action for the provided direction, if needed.
// It returns TRUE if the corresponding action should be updated
func (d *FirewallManager) increaseCount(which string) bool {
	//	Brief: this function is called when a new policy is deployed with the appropriate direction.
	//	If there are no policies, the default action is FORWARD.
	//	If there is at least one, then the default action should be updated to DROP, because only what is allowed is forwarded.
	//	This function returns true when there is only one policy, because that's when we should actually switch to DROP (we were in FORWARD)

	// Ingress
	if which == "ingress" {
		d.ingressPoliciesCount++

		if d.ingressPoliciesCount > 0 {
			d.ingressDefaultAction = pcn_types.ActionDrop

			if d.ingressPoliciesCount == 1 {
				return true
			}
		}
	}

	//	Egress
	if which == "egress" {
		d.egressPoliciesCount++

		if d.egressPoliciesCount > 0 {
			d.egressDefaultAction = pcn_types.ActionDrop

			if d.egressPoliciesCount == 1 {
				return true
			}
		}
	}

	return false
}

// decreaseCount decreases the count of policies enforced and changes the default action for the provided direction, if needed.
// It returns TRUE if the corresponding action should be updated
func (d *FirewallManager) decreaseCount(which string) bool {
	//	Brief: this function is called when a policy must be ceased.
	//	If - after ceasing it - we have no policies enforced, then the default action must be FORWARD.
	//	If there is at least one, then the default action should remain DROP
	//	This function returns true when there are no policies enforced, because that's when we should actually switch to FORWARD (we were in DROP)

	if which == "ingress" {
		d.ingressPoliciesCount--

		if d.ingressPoliciesCount == 0 {
			d.ingressDefaultAction = pcn_types.ActionForward
			return true
		}
	}

	if which == "egress" {
		if d.egressPoliciesCount--; d.egressPoliciesCount == 0 {
			d.egressDefaultAction = pcn_types.ActionForward
			return true
		}
	}

	return false
}

// buildIDs calculates IDs for each rule provided, updating the first usable ids accordingly.
// It returns the rules with the appropriate ID, so they can be instantly injected.
func (d *FirewallManager) buildIDs(policyName, target string, ingress, egress []k8sfirewall.ChainRule) ([]k8sfirewall.ChainRule, []k8sfirewall.ChainRule) {
	var applyWait sync.WaitGroup
	applyWait.Add(2)
	defer applyWait.Wait()

	// The rules in memory
	/*if _, exists := d.ingressRules[policyName]; !exists {
		d.ingressRules[policyName] = map[int32]k8sfirewall.ChainRule{}
	}
	if _, exists := d.egressRules[policyName]; !exists {
		d.egressRules[policyName] = map[int32]k8sfirewall.ChainRule{}
	}*/
	if _, exists := d.ingressRules[policyName]; !exists {
		d.ingressRules[policyName] = []k8sfirewall.ChainRule{}
	}
	if _, exists := d.egressRules[policyName]; !exists {
		d.egressRules[policyName] = []k8sfirewall.ChainRule{}
	}

	description := "policy=" + policyName

	// --- calculate ingress ids
	/*go func() {
		defer applyWait.Done()
		i := 0
		for ; i < len(ingress); i++ {
			ingress[i].Id = d.ingressID + int32(i)
			ingress[i].Description = description
			if len(target) > 0 {
				ingress[i].Src = target
			}
			//	Store its ID in memory, so we can delete it instantly without looping through rules
			if _, exists := d.ingressIPs[ingress[i].Src]; !exists {
				d.ingressIPs[ingress[i].Src] = map[int32]string{}
			}
			d.ingressIPs[ingress[i].Src][ingress[i].Id] = policyName
			d.ingressRules[policyName][d.ingressID+int32(i)] = ingress[i]
		}

		//d.ingressID += int32(i)
	}()*/
	go func() {
		defer applyWait.Done()
		i := 0
		for ; i < len(ingress); i++ {
			ingress[i].Description = description
			if len(target) > 0 {
				ingress[i].Src = target
			}
		}
	}()

	// --- calculate egress ids
	/*go func() {
		defer applyWait.Done()
		i := 0
		for ; i < len(egress); i++ {
			egress[i].Id = d.egressID + int32(i)
			egress[i].Description = description
			if len(target) > 0 {
				egress[i].Dst = target
			}
			//	Store its ID in memory, so we can delete it instantly without looping through rules
			if _, exists := d.egressIPs[egress[i].Dst]; !exists {
				d.egressIPs[egress[i].Dst] = map[int32]string{}
			}
			d.egressIPs[egress[i].Dst][egress[i].Id] = policyName
			d.egressRules[policyName][d.egressID+int32(i)] = egress[i]
		}

		//d.egressID += int32(i)
	}()*/
	go func() {
		defer applyWait.Done()
		i := 0
		for ; i < len(ingress); i++ {
			egress[i].Description = description
			if len(target) > 0 {
				egress[i].Src = target
			}
		}
	}()

	return ingress, egress
}

// injecter is a convenient method for injecting ingress and egress rules for a single firewall
func (d *FirewallManager) injecter(firewall string, ingressRules, egressRules []k8sfirewall.ChainRule, waiter *sync.WaitGroup, iStartFrom, eStartFrom int32) error {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "Injecter(" + firewall + ", ...)"})

	//	Should I notify caller when I'm done?
	if waiter != nil {
		defer waiter.Done()
	}

	//	Is firewall ok?
	/*if ok, err := d.isFirewallOk(firewall); !ok {
		//	TODO: define an array with rules not injected?
		l.Errorln("Could not inject rules. Firewall is not ok:", err)
		return err
	}*/

	//-------------------------------------
	//	Inject rules direction concurrently
	//-------------------------------------
	var injectWaiter sync.WaitGroup
	injectWaiter.Add(2)
	defer injectWaiter.Wait()

	//	TODO: how to handle these if they have errors?
	go d.injectRules(firewall, "ingress", ingressRules, &injectWaiter, iStartFrom)
	go d.injectRules(firewall, "egress", egressRules, &injectWaiter, eStartFrom)

	return nil
}

// injectRules is a wrapper for firewall's CreateFirewallChainRuleListByID and CreateFirewallChainApplyRulesByID methods.
func (d *FirewallManager) injectRules(firewall, direction string, rules []k8sfirewall.ChainRule, waiter *sync.WaitGroup, startFrom int32) error {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "injectRules(" + firewall + "," + direction + ",...)"})

	//	Should I notify caller when I'm done?
	if waiter != nil {
		defer waiter.Done()
	}

	//-------------------------------------
	//	Inject & apply
	//-------------------------------------

	endPoint := "http://" + firewall + ":9000/polycube/v1/firewall/fw/chain/" + direction + "/insert/"
	len := len(rules)
	for i := len - 1; i > -1; i-- {
		rule := rules[i]
		rule.Id = startFrom
		data, err := d.marshal(rule)
		if err == nil {
			req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer(data))
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			_, err = client.Do(req)
			if err != nil {
				log.Errorln("Error while trying to send request:", err)
			}
		}
	}

	/*response, err := d.fwAPI.CreateFirewallChainRuleListByID(nil, firewall, direction, rules)
	if err != nil {
		l.Errorln("Error while trying to inject rules:", err, response)
		return err
	}
	if response, err := d.applyRules(firewall, direction); err != nil {
		l.Errorln("Error while trying to apply rules:", err, response)
		return err
	}*/

	return nil
}

// definePolicyActions subscribes to the appropriate events and defines the actions to be taken when that event happens.
func (d *FirewallManager) definePolicyActions(policyName string, actions []pcn_types.FirewallAction) {
	for _, action := range actions {
		shouldSubscribe := false

		//	Create the action if does not exist
		if _, exists := d.policyActions[action.Key]; !exists {
			d.policyActions[action.Key] = &subscriptions{
				actions: map[string]*pcn_types.ParsedRules{},
			}
			shouldSubscribe = true
		}

		d.log.Infof("actions: %+v\n", action)

		//	Define the action...
		if _, exists := d.policyActions[action.Key].actions[policyName]; !exists {
			d.policyActions[action.Key].actions[policyName] = &pcn_types.ParsedRules{}
		}
		d.policyActions[action.Key].actions[policyName].Ingress = append(d.policyActions[action.Key].actions[policyName].Ingress, action.Templates.Ingress...)
		d.policyActions[action.Key].actions[policyName].Egress = append(d.policyActions[action.Key].actions[policyName].Egress, action.Templates.Egress...)

		//	... And subscribe to events
		if shouldSubscribe {
			//	Prepare the subscription query
			podQuery := pcn_types.ObjectQuery{}
			if len(action.PodLabels) > 0 {
				podQuery.Labels = action.PodLabels
			}
			nsQuery := pcn_types.ObjectQuery{}
			if len(action.NamespaceName) > 0 {
				nsQuery.Name = action.NamespaceName
			} else {
				nsQuery.Labels = action.NamespaceLabels
			}

			//	Finally, susbcribe
			//	-- To update events
			updateUnsub, err := d.podController.Subscribe(pcn_types.Update, podQuery, nsQuery, pcn_types.PodRunning, func(pod *core_v1.Pod) {
				d.reactToPod(pcn_types.Update, pod, action.Key)
			})
			//	-- To delete events
			deleteUnsub, err := d.podController.Subscribe(pcn_types.Delete, podQuery, nsQuery, pcn_types.PodAnyPhase, func(pod *core_v1.Pod) {
				d.reactToPod(pcn_types.Delete, pod, "")
			})

			if err == nil {
				d.policyActions[action.Key].unsubscriptors = append(d.policyActions[action.Key].unsubscriptors, updateUnsub)
				d.policyActions[action.Key].unsubscriptors = append(d.policyActions[action.Key].unsubscriptors, deleteUnsub)
			}
		}
	}
}

// reactToPod is called whenever a monitored pod event occurs. E.g.: I should accept connections from Pod A, and a new Pod A is born.
// This function knows what to do when that event happens.
func (d *FirewallManager) reactToPod(event pcn_types.EventType, pod *core_v1.Pod, actionKey string) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "reactToPod(" + string(event) + ", " + pod.Status.PodIP + ", " + actionKey + "...)"})

	d.lock.Lock()
	defer d.lock.Unlock()

	//-------------------------------------
	//	Update
	//-------------------------------------

	update := func(ip string) {

		//	Basic checks
		actions, exist := d.policyActions[actionKey]
		if !exist {
			l.Warningln("Could not find any actions with this key")
			return
		}
		if len(actions.actions) < 1 {
			l.Warningln("There are no actions to be taken!")
			return
		}

		//	NOTE: read the note on checkedPods.
		ingress := []k8sfirewall.ChainRule{}
		egress := []k8sfirewall.ChainRule{}

		//	Build all rules regardless of the policy, so we can inject them at once and apply only once.
		//	Usually an update only consists of few rules, so this should be very fast.
		for policy, rules := range actions.actions {
			ingressRules, egressRules := d.buildIDs(policy, ip, rules.Ingress, rules.Egress)
			ingress = append(ingress, ingressRules...)
			egress = append(egress, egressRules...)

			// calculate the priority
			iStartFrom := int32(1)
			eStartFrom := int32(1)
			for _, thisPolicy := range d.priorities {
				// jump the rules
				iStartFrom += int32(len(d.ingressRules[thisPolicy.policyName]))
				eStartFrom += int32(len(d.egressRules[thisPolicy.policyName]))

				if thisPolicy.policyName == policy {
					break
				}
			}

			//	Now inject the rules in all firewalls linked.
			for _, f := range d.linkedPods {
				//name := "fw-" + f
				name := f
				d.injecter(name, ingress, egress, nil, iStartFrom, eStartFrom)
			}
		}
	}

	//-------------------------------------
	//	Delete
	//-------------------------------------

	delete := func(ip string) {
		var waiter sync.WaitGroup
		waiter.Add(2)

		//	--- Ingress
		go func() {
			defer waiter.Done()
			rulesToDelete := []k8sfirewall.ChainRule{}
			rulesToKeep := []k8sfirewall.ChainRule{}
			for policy, rulesToDelete := range d.ingressRules {
				for _, rule := range rulesToDelete {
					if rule.Src == ip {
						rulesToDelete = append(rulesToDelete, rule)
					} else {
						rulesToKeep = append(rulesToKeep, rule)
					}
				}

				d.ingressRules[policy] = rulesToKeep
			}

			//	Is it even listed on my rules?
			if len(rulesToDelete) > 0 {
				//ingressIDs := make([]k8sfirewall.ChainRule, len(rules))
				/*i := 0
				for id, policy := range rules {
					//ingressIDs[i] = id
					if _, exists := d.ingressRules[policy]; exists {
						//	Delete this rule from the policies rules
						if _, exists := d.ingressRules[policy]; exists {
							delete(d.ingressRules[policy], id)
						} else {
							//	This may happend if CeasePolicy was called and this function was queued
							l.Warningln(policy, "was not present in ingress rules!")
						}
					}
					i++
				}*/

				//	Delete the rules on each linked pod
				for _, ip := range d.linkedPods {
					//name := "fw-" + ip
					name := ip
					d.deleteRules(name, "ingress", rulesToDelete)
					d.applyRules(name, "ingress")
				}
			}

		}()

		//	--- Egress
		go func() {
			defer waiter.Done()
			rulesToDelete := []k8sfirewall.ChainRule{}
			rulesToKeep := []k8sfirewall.ChainRule{}
			for policy, rulesToDelete := range d.egressRules {
				for _, rule := range rulesToDelete {
					if rule.Dst == ip {
						rulesToDelete = append(rulesToDelete, rule)
					} else {
						rulesToKeep = append(rulesToKeep, rule)
					}
				}

				d.egressRules[policy] = rulesToKeep
			}

			//	Is it even listed on my rules?
			if len(rulesToDelete) > 0 {
				/*egressIDs := make([]int32, len(rules))
				i := 0
				for id, policy := range rules {
					egressIDs[i] = id
					if _, exists := d.egressRules[policy]; exists {
						//	Delete this rule from the policies rules
						if _, exists := d.egressRules[policy]; exists {
							delete(d.egressRules[policy], id)
						} else {
							l.Warningln(policy, "was not present in egress rules!")
						}
					}
					i++
				}*/

				for _, ip := range d.linkedPods {
					name := ip
					//TODO
					d.deleteRules(name, "egress", rulesToDelete)
					d.applyRules(name, "egress")
				}
			}
		}()

		waiter.Wait()
	}

	//-------------------------------------
	//	What to do?
	//-------------------------------------

	switch event {
	case pcn_types.Update:
		update(pod.Status.PodIP)
	case pcn_types.Delete:
		delete(pod.Status.PodIP)
	}
}

// deleteAllPolicyRules deletes all rules mentioned in a policy
func (d *FirewallManager) deleteAllPolicyRules(policy string) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "deleteAllPolicyRules(" + policy + ")"})
	var waiter sync.WaitGroup
	waiter.Add(2)

	//-------------------------------------
	//	Ingress
	//-------------------------------------
	go func() {
		defer waiter.Done()
		rules := d.ingressRules[policy]
		if len(rules) > 0 {
			/*ingressIDs := make([]k8sfirewall.ChainRule, len(rules))
			i := 0
			for id, rule := range rules {
				ingressIDs[i] = rule
				ip := rule.Src
				if _, exists := d.ingressIPs[ip]; exists {
					delete(d.ingressIPs[ip], id)
					if len(d.ingressIPs[ip]) < 1 {
						delete(d.ingressIPs, ip)
					}
				} else {
					l.Warningln(ip, "was not in the ingress ip structure!")
				}
				i++
			}*/

			//	Delete the found rules from each linked pod
			for _, ip := range d.linkedPods {
				//name := "fw-" + ip
				name := ip
				d.deleteRules(name, "ingress", rules)
			}

			delete(d.ingressRules, policy)
		}
	}()

	//-------------------------------------
	//	Egress
	//-------------------------------------
	go func() {
		defer waiter.Done()
		rules := d.egressRules[policy]
		if len(rules) > 0 {
			/*egressIDs := make([]k8sfirewall.ChainRule, len(rules))
			i := 0
			for id, rule := range rules {
				egressIDs[i] = rule
				ip := rule.Dst
				if _, exists := d.egressIPs[ip]; exists {
					delete(d.egressIPs[ip], id)
					if len(d.egressIPs[ip]) < 1 {
						//	If this IP is not mentioned in any rule anymore, than remove it
						delete(d.egressIPs, ip)
					}
				} else {
					l.Warningln(ip, "was not in the egress ip structure!")
				}
				i++
			}*/

			//	Delete the found rules from each linked pod
			for _, ip := range d.linkedPods {
				//name := "fw-" + ip
				name := ip
				d.deleteRules(name, "egress", rules)
			}

			delete(d.egressRules, policy)
		}
	}()

	waiter.Wait()
}

// deleteAllPolicyTemplates delete all templates generated by a specific policy.
// So that the firewall manager will not generate those rules anymore when it will react to a certain pod.
func (d *FirewallManager) deleteAllPolicyTemplates(policy string) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "deleteAllPolicyActions(" + policy + ")"})

	flaggedForDeletion := []string{}

	//-------------------------------------
	//	Delete this policy from the actions
	//-------------------------------------
	for key, action := range d.policyActions {
		delete(action.actions, policy)

		//	This action belongs to no policies anymore?
		if len(action.actions) < 1 {
			flaggedForDeletion = append(flaggedForDeletion, key)
		}
	}

	//-------------------------------------
	//	Delete actions with no policies
	//-------------------------------------
	//	If, after deletion the policy from the actions, the action has no policy anymore then we need to stop monitoring that pod!
	for _, flaggedKey := range flaggedForDeletion {
		for _, unsubscribe := range d.policyActions[flaggedKey].unsubscriptors {
			unsubscribe()
		}

		delete(d.policyActions, flaggedKey)
	}
}

// CeasePolicy will cease a policy, removing all rules generated by it and won't react to pod events included by it anymore.
func (d *FirewallManager) CeasePolicy(policyName string) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "CeasePolicy(" + policyName + ")"})

	d.lock.Lock()
	defer d.lock.Unlock()

	//-------------------------------------
	//	Delete all rules generated by this policy
	//-------------------------------------

	d.deleteAllPolicyRules(policyName)

	//-------------------------------------
	//	Remove this policy's templates from the actions
	//-------------------------------------

	d.deleteAllPolicyTemplates(policyName)

	//-------------------------------------
	//	Update the default actions
	//-------------------------------------
	//	So we just ceased a policy, we now need to update the default actions
	if _, exists := d.policyTypes[policyName]; exists {
		policyType := d.policyTypes[policyName]
		d.updateCounts("decrease", policyType)
	} else {
		l.Warningln(policyName, "was not listed among policy types!")
	}
}

// deleteRules is a wrapper for DeleteFirewallChainRuleByID method, deleting multiple rules.
func (d *FirewallManager) deleteRules(fw, direction string, rules []k8sfirewall.ChainRule) error {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "deleteRules()"})

	//var err error

	//	No need to do this with separate threads...
	for _, rule := range rules {
		endPoint := "http://" + fw + ":9000/polycube/v1/firewall/fw/chain/ingress/delete/"
		data, err := d.marshal(rule)
		req, err := http.NewRequest("POST", endPoint, bytes.NewBuffer(data))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{}

		_, err = client.Do(req)
		if err != nil {
			fmt.Println("Error while trying to apply rules:", err)
			return err
		}
		/*if response, err := d.fwAPI.DeleteFirewallChainRuleByID(nil, fw, direction, id); err != nil {
			l.Errorf("Error while trying to delete rule %d, in %s for firewall %s. Error %s, response: %+v\n", id, direction, fw, err.Error(), response)
		}*/
	}

	//	This is just temporary
	return nil
}

// IsPolicyEnforced returns true if this firewall enforces this policy
func (d *FirewallManager) IsPolicyEnforced(name string) bool {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, exists := d.policyTypes[name]
	return exists
}

// Selector returns the namespace and labels of the pods monitored by this firewall manager
func (d *FirewallManager) Selector() (map[string]string, string) {
	return d.selector.labels, d.selector.namespace
}

// isFirewallOk checks if the firewall is ok. Used to check if firewall exists and is healthy
func (d *FirewallManager) isFirewallOk(firewall string) (bool, error) {
	//	We are going to do that by reading its uuid
	if _, _, err := d.fwAPI.ReadFirewallUuidByID(nil, firewall); err != nil {
		return false, err
	}
	return true, nil
}

// updateDefaultAction is a wrapper for UpdateFirewallChainDefaultByID method.
func (d *FirewallManager) updateDefaultAction(ip, direction, to string) error {
	jsonStr := []byte(`"forward"`)
	client := http.Client{}
	req, err := http.NewRequest("PATCH", "http://"+ip+":9000"+polycubePath+firewallPath+"fw/chain/"+direction+"/default", bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Infoln("Could not change default action in", direction, err, req)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Infoln("Could not change default action in", direction, err, resp)
		return err
	}
	defer resp.Body.Close()
	return nil
}

// applyRules is a wrapper for CreateFirewallChainApplyRulesByID method.
func (d *FirewallManager) applyRules(ip, direction string) (bool, error) {
	endPoint := "http://" + ip + ":9000/polycube/v1/firewall/fw/chain/ingress/apply-rules/"
	req, err := http.NewRequest("POST", endPoint, nil)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}

	_, err = client.Do(req)
	if err != nil {
		log.Errorln("Error while trying to apply rules:", err)
		return false, err
	}

	return true, nil
}

// destroyFw destroy a firewall linked by this firewall manager
func (d *FirewallManager) destroyFw(name string) error {
	/*_, err := d.fwAPI.DeleteFirewallByID(nil, name)
	return err*/
	return nil
}

// cleanFw cleans the firewall linked by this firewall manager
func (d *FirewallManager) cleanFw(name string) (error, error) {
	var iErr error
	var eErr error

	/*if _, err := d.fwAPI.DeleteFirewallChainRuleListByID(nil, name, "ingress"); err != nil {
		iErr = err
	}
	if _, err := d.fwAPI.DeleteFirewallChainRuleListByID(nil, name, "egress"); err != nil {
		eErr = err
	}*/

	return iErr, eErr
}

// Destroy destroys to current firewall manager. This function should not be called manually,
// as it is called automatically after a certain time has passed while monitoring no pods.
// To destroy a particular firewall, see the Unlink function.
func (d *FirewallManager) Destroy() {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "Destroy()"})

	d.lock.Lock()
	defer d.lock.Unlock()

	//-------------------------------------
	//	Unsubscribe from all actions
	//-------------------------------------
	//	Actually this is duplicated code, it does the same as deleteAllPolicyTemplates.
	//	But it is more convenient to do it like this, since we delete everything no matter the policy
	keysToDelete := make([]string, len(d.policyActions))
	i := 0

	//	-- Unsubscribe
	for key, action := range d.policyActions {
		for _, unsubscribe := range action.unsubscriptors {
			unsubscribe()
		}
		keysToDelete[i] = key
		i++
	}

	//	-- Delete the action.
	//	We do this so that queued actions will instantly return with no harm.
	for _, key := range keysToDelete {
		delete(d.policyActions, key)
	}

	l.Infoln("Good bye!")
}
