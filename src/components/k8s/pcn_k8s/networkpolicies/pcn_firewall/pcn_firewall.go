package pcnfirewall

import (
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
	fwAPI *k8sfirewall.FirewallApiService
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

// policyPriority is the priority of this policy: most recently deployed policies take precedence over the older ones.
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

// selector is the selector for the pods this firewall manager is managing
type selector struct {
	namespace string
	labels    map[string]string
}

// StartFirewall will start a new firewall manager
func StartFirewall(API *k8sfirewall.FirewallApiService, podController pcn_controllers.PodController, name, namespace string, labels map[string]string, node *core_v1.Node) PcnFirewall {
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
	name := "fw-" + podIP

	//-------------------------------------
	//	Check firewall health and pod presence
	//-------------------------------------
	if ok, err := d.isFirewallOk(name); !ok {
		l.Errorf("Could not link firewall for pod %s: %s", podIP, err.Error())
		return false
	}
	_, alreadyLinked := d.linkedPods[podUID]
	if alreadyLinked {
		return false
	}

	//-------------------------------------
	//	Extract the rules
	//-------------------------------------
	//	We are going to get all rules regardless of the policy they belong to
	ingressRules := []k8sfirewall.ChainRule{}
	egressRules := []k8sfirewall.ChainRule{}

	if len(d.ingressRules) > 0 || len(d.egressRules) > 0 {
		var waiter sync.WaitGroup
		waiter.Add(2)

		// -- ingress
		go func() {
			defer waiter.Done()
			for _, rules := range d.ingressRules {
				ingressRules = append(ingressRules, rules...)
			}
		}()

		// -- egress
		go func() {
			defer waiter.Done()
			for _, rules := range d.egressRules {
				egressRules = append(egressRules, rules...)
			}
		}()
		waiter.Wait()
	}

	//-------------------------------------
	//	Inject rules and change default actions
	//-------------------------------------
	if len(ingressRules) > 0 || len(egressRules) > 0 {
		if err := d.injecter(podIP, ingressRules, egressRules, nil, 0, 0); err != nil {
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

// Unlink removes the provided pod from the list of monitored ones by this firewall manager.
// If the second argument is TRUE, then the provided pod's firewall will be destroyed as well.
// It returns FALSE if the pod was not among the monitored ones, and the number of remaining pods linked.
func (d *FirewallManager) Unlink(pod *core_v1.Pod, then UnlinkOperation) (bool, int) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "Unlink(" + pod.Name + ")"})

	d.lock.Lock()
	defer d.lock.Unlock()

	podUID := pod.UID
	name := "fw-" + pod.Status.PodIP

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

	log.Infoln("###before setting policy priority")
	iStartFrom, eStartFrom := d.setPolicyPriority(policyName, policyTime)
	log.Infoln("###aftersetting policy priority", iStartFrom, eStartFrom)
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
		name := "fw-" + ip
		go d.injecter(name, ingressIDs, egressIDs, &injectWaiter, iStartFrom, eStartFrom)
	}
	injectWaiter.Wait()
}

// setPolicyPriority sets the priority of the policy in the rules list
func (d *FirewallManager) setPolicyPriority(policyName string, policyTime meta_v1.Time) (int32, int32) {
	//	Ingress and egress first useful ids
	iStartFrom := 0
	eStartFrom := 0

	//	NOTE: we can't use a map for this operation, because we need to know how many rules to skip.
	//	calculateInsertionIDs has an example of this.

	//	Loop through all policies
	t := 0
	for i, currentPolicy := range d.priorities {
		//	If the policy we're going to enforce has been deployed AFTER the one we're checking, then it tkes precedence
		if policyTime.After(currentPolicy.timestamp) {
			t = i
			break
		}
		t++

		// jump the rules
		iStartFrom += len(d.ingressRules[currentPolicy.policyName])
		eStartFrom += len(d.egressRules[currentPolicy.policyName])
	}

	//	Reformat the priorities list:
	// 1) first insert the policies up to the new found index (t)
	// 2) then insert this policy
	// 3) finally, insert all other policies
	// 4) update the priorities with the new one.
	temp := []policyPriority{}
	temp = append(temp, d.priorities[:t]...) // 1)
	temp = append(temp, policyPriority{      // 2)
		policyName: policyName,
		timestamp:  policyTime.Time,
	})
	temp = append(temp, d.priorities[t:]...) // 3)
	d.priorities = temp                      // 4)

	return int32(iStartFrom), int32(eStartFrom)
}

// removePolicyPriority removes the policy from the list of the priorities and reformats it.
func (d *FirewallManager) removePolicyPriority(policyName string) {
	//	Loop through all policies to find it
	i := 0
	for ; d.priorities[i].policyName != policyName; i++ {
	}

	//	Reformat the priorities list:
	// 1) first insert the policies up to the new found index (t)
	// 2) then copy from the found index +1
	// 4) update the priorities with the new one.
	temp := []policyPriority{}
	temp = append(temp, d.priorities[:i]...)   // 1)
	temp = append(temp, d.priorities[i+1:]...) // 2)
	d.priorities = temp                        // 3)
}

// calculateInsertionIDs gets the first useful rules IDs for insertion, based on the policy's priority
func (d *FirewallManager) calculateInsertionIDs(policyName string) (int32, int32) {
	iStartFrom := 0
	eStartFrom := 0

	/* Example: we want to insert 2 rules for policy my-policy, this is the current list of priorities:
	0) my-other-policy (it has 2 rules)
	2) my-policy (it has 1 rule)
	3) yet-another-policy (it has 2 rules)

	On each iteration we count the number of rules for that policy, and we stop when the policy is the one we need.
	First iteration: 2 rules -> 0 + 2 = start from id 2 -> the policy is not the one we need -> go on.
	Second iteration: 1 rule -> 2 + 1 = start from id 3 -> the policy is ok > stop.
	We're going to insert from id 3.
	*/

	for _, currentPolicy := range d.priorities {
		// jump the rules
		iStartFrom += len(d.ingressRules[currentPolicy.policyName])
		eStartFrom += len(d.egressRules[currentPolicy.policyName])

		if currentPolicy.policyName == policyName {
			break
		}
	}

	return int32(iStartFrom), int32(eStartFrom)
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
// UPDATE: this is not true anymore: we're not going to add rules based on ID, but rathern on their policy's priority now.
// So, this function has been kept with this name, but it now just adds rules on memory.
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
	newIngress := make([]k8sfirewall.ChainRule, len(ingress))
	newEgress := make([]k8sfirewall.ChainRule, len(egress))

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

		for i, rule := range ingress {
			newIngress[i] = rule
			newIngress[i].Description = description
			if len(target) > 0 {
				newIngress[i].Src = target
			}

			d.ingressRules[policyName] = append(d.ingressRules[policyName], newIngress[i])
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

		for i, rule := range egress {
			newEgress[i] = rule
			newEgress[i].Description = description
			if len(target) > 0 {
				newEgress[i].Src = target
			}

			d.egressRules[policyName] = append(d.egressRules[policyName], newEgress[i])
		}
	}()

	return newIngress, newEgress
}

// injecter is a convenient method for injecting rules for a single firewall for both directions
func (d *FirewallManager) injecter(firewall string, ingressRules, egressRules []k8sfirewall.ChainRule, waiter *sync.WaitGroup, iStartFrom, eStartFrom int32) error {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "Injecter(" + firewall + ", ...)"})

	//	Should I notify caller when I'm done?
	if waiter != nil {
		defer waiter.Done()
	}

	//	Is firewall ok?
	if ok, err := d.isFirewallOk(firewall); !ok {
		l.Errorln("Could not inject rules. Firewall is not ok:", err)
		return err
	}

	//-------------------------------------
	//	Inject rules direction concurrently
	//-------------------------------------
	var injectWaiter sync.WaitGroup
	injectWaiter.Add(2)
	defer injectWaiter.Wait()

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

	// We are using the insert call here, which adds the rule on the startFrom id and pushes the other rules downwards.
	// In order to preserve original order, we're going to start injecting from the last to the first.

	len := len(rules)
	for i := len - 1; i > -1; i-- {
		ruleToInsert := k8sfirewall.ChainInsertInput(rules[i])
		ruleToInsert.Id = startFrom
		_, response, err := d.fwAPI.CreateFirewallChainInsertByID(nil, firewall, direction, ruleToInsert)
		if err != nil {
			l.Errorln("Error while trying to inject rule:", err, response)
			//	This rule had an error, but we still gotta push the other ones man...
			//return err
		}
	}

	//	Now apply the changes
	if response, err := d.applyRules(firewall, direction); err != nil {
		l.Errorln("Error while trying to apply rules:", err, response)
		return err
	}

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

		//	Build rules according to the policy's priority
		for policy, rules := range actions.actions {
			ingressRules, egressRules := d.buildIDs(policy, ip, rules.Ingress, rules.Egress)
			ingress = append(ingress, ingressRules...)
			egress = append(egress, egressRules...)

			// calculate the priority
			iStartFrom, eStartFrom := d.calculateInsertionIDs(policy)

			//	Now inject the rules in all firewalls linked.
			//	This usually is a matter of 1-2 rules, so no need to do this in a separate goroutine.
			for _, f := range d.linkedPods {
				name := "fw-" + f
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

			//	For each policy, go get all the rules in which this ip was present.
			rulesToDelete := []k8sfirewall.ChainRule{}
			rulesToKeep := []k8sfirewall.ChainRule{}
			for policy := range d.ingressRules {
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
					name := "fw-" + ip
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
					name := "fw-" + ip
					d.deleteRules(name, "egress", rulesToDelete)
					d.applyRules(name, "egress")
				}
			}
		}()

		waiter.Wait()
	}

	//-------------------------------------
	//	Main entrypoint: what to do?
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
		defer delete(d.ingressRules, policy)
		defer waiter.Done()

		rules := d.ingressRules[policy]
		if len(rules) < 1 {
			return
		}
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
			name := "fw-" + ip
			d.deleteRules(name, "ingress", rules)
		}
	}()

	//-------------------------------------
	//	Egress
	//-------------------------------------
	go func() {
		defer delete(d.egressRules, policy)
		defer waiter.Done()

		rules := d.egressRules[policy]
		if len(rules) < 1 {
			return
		}
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
			name := "fw-" + ip
			d.deleteRules(name, "egress", rules)
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
	//	If, after deleting the policy from the actions, the action has no policy anymore then we need to stop monitoring that pod!
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
	//	Remove this policy's priority
	//-------------------------------------
	//	This is actually a useless operation... but, you know... just for the sake of clarity.
	d.removePolicyPriority(policyName)

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

	// this is a fake deep copy-cast.
	cast := func(rule k8sfirewall.ChainRule) k8sfirewall.ChainDeleteInput {
		return k8sfirewall.ChainDeleteInput{
			Src:         rule.Src,
			Dst:         rule.Dst,
			L4proto:     rule.L4proto,
			Sport:       rule.Sport,
			Dport:       rule.Dport,
			Tcpflags:    rule.Tcpflags,
			Conntrack:   rule.Conntrack,
			Action:      rule.Action,
			Description: rule.Description,
		}
	}

	//	No need to do this with separate threads...
	for _, rule := range rules {
		// Delete the rule not by its ID, but by the fields it is composed of.
		response, err := d.fwAPI.CreateFirewallChainDeleteByID(nil, fw, direction, cast(rule))
		if err != nil {
			l.Errorf("Error while trying to delete this rule: %+v, in %s for firewall %s. Error %s, response: %+v\n", rule, direction, fw, err.Error(), response)
		}
	}

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

// isFirewallOk checks if the firewall is ok. Used to check if firewall exists and is healthy.
func (d *FirewallManager) isFirewallOk(firewall string) (bool, error) {
	//	We are going to do that by reading its uuid
	if _, _, err := d.fwAPI.ReadFirewallUuidByID(nil, firewall); err != nil {
		return false, err
	}
	return true, nil
}

// updateDefaultAction is a wrapper for UpdateFirewallChainDefaultByID method.
func (d *FirewallManager) updateDefaultAction(firewall, direction, to string) error {
	_, err := d.fwAPI.UpdateFirewallChainDefaultByID(nil, firewall, direction, to)
	return err
}

// applyRules is a wrapper for CreateFirewallChainApplyRulesByID method.
func (d *FirewallManager) applyRules(firewall, direction string) (bool, error) {
	out, _, err := d.fwAPI.CreateFirewallChainApplyRulesByID(nil, firewall, direction)
	return out.Result, err
}

// destroyFw destroy a firewall linked by this firewall manager
func (d *FirewallManager) destroyFw(name string) error {
	_, err := d.fwAPI.DeleteFirewallByID(nil, name)
	return err
}

// cleanFw cleans the firewall linked by this firewall manager
func (d *FirewallManager) cleanFw(name string) (error, error) {
	var iErr error
	var eErr error

	if _, err := d.fwAPI.DeleteFirewallChainRuleListByID(nil, name, "ingress"); err != nil {
		iErr = err
	}
	if _, err := d.fwAPI.DeleteFirewallChainRuleListByID(nil, name, "egress"); err != nil {
		eErr = err
	}

	return iErr, eErr
}

// Destroy destroys the current firewall manager. This function should not be called manually,
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
