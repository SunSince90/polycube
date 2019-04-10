package pcnfirewall

import (
	"sync"

	//	TODO-ON-MERGE: change these to the polycube path
	pcn_controllers "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/controllers"
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"

	log "github.com/sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"
)

type PcnFirewall interface {
	Link(*core_v1.Pod) bool
	Unlink(*core_v1.Pod, bool) (bool, int)
	LinkedPods() map[k8s_types.UID]string
	IsPodLinked(k8s_types.UID) bool
	IsPolicyEnforced(string) bool

	EnforcePolicy(string, string, []k8sfirewall.ChainRule, []k8sfirewall.ChainRule, pcn_types.FirewallActions) (error, error)
	CeasePolicy(string)

	ForPod() k8s_types.UID
	RemoveRules(string, []k8sfirewall.ChainRule) []k8sfirewall.ChainRule
	RemoveIPReferences(string, string)
	Destroy() error
}

type DeployedFirewall struct {
	// podController is the pod controller
	podController pcn_controllers.PodController
	// fwAPI is the low level firewall api
	fwAPI k8sfirewall.FirewallAPI
	// ingressRules contains the ingress rules divided by policy
	ingressRules map[string]map[int32]k8sfirewall.ChainRule
	// egressRules contains the egress rules divided by policy
	egressRules map[string]map[int32]k8sfirewall.ChainRule
	// linkedPods is a map of pods monitored by this firewall manager
	linkedPods map[k8s_types.UID]string
	// name is the name of this firewall manager
	name string
	// log is a new entry in logger
	log *log.Logger
	// lock is firewall manager's main lock
	lock sync.Mutex
	// ingressID is the first usable ingress ID
	ingressID int32
	// egressID is the first usable egress ID
	egressID int32
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

	policyActions map[string]*policyActions
	checkLock     sync.Mutex
	checkedPods   map[string]bool
	//	TODO: remove the following two
	podUID   k8s_types.UID
	podIP    string
	firewall *k8sfirewall.Firewall

	//	TODO: check if this link lock is useful
	//linkLock sync.Mutex
	//	For caching.
	/*lastIngressID int32
	lastEgressID int32*/
}

type policyActions struct {
	ingress []func()
	egress  []func()
}

// StartFirewall will start a new firewall manager
//	TODO: review this function
func StartFirewall(API k8sfirewall.FirewallAPI, podController pcn_controllers.PodController, name string) *DeployedFirewall {
	//	This method is unexported by design: *only* the network policy manager is supposed to create firewall managers.

	//-------------------------------------
	//	Init
	//-------------------------------------
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": FWM, "method": "StartFirewall()"})
	l.Infoln("Starting Firewall Manager, with name", name)

	//	The name of the firewall
	//name := "fw-" + pod.Status.PodIP

	//	Main structure
	deployedFw := DeployedFirewall{}

	//	Rules
	deployedFw.ingressRules = map[string]map[int32]k8sfirewall.ChainRule{}
	deployedFw.egressRules = map[string]map[int32]k8sfirewall.ChainRule{}

	//	The firewall API
	deployedFw.fwAPI = API

	// TODO: remove the following
	/*deployedFw.podUID = pod.UID
	deployedFw.podIP = pod.Status.PodIP*/

	deployedFw.ingressPoliciesCount = 0
	deployedFw.egressPoliciesCount = 0
	deployedFw.policyTypes = map[string]string{}
	deployedFw.policyActions = map[string]*policyActions{}
	deployedFw.checkedPods = map[string]bool{}

	deployedFw.ingressID = FirstIngressID
	deployedFw.egressID = FirstEgressID
	deployedFw.linkedPods = map[k8s_types.UID]string{}
	deployedFw.podController = podController
	deployedFw.name = "FirewallManager-" + name
	deployedFw.ingressDefaultAction = pcn_types.ActionForward
	deployedFw.egressDefaultAction = pcn_types.ActionForward
	deployedFw.log = log.New()

	//-------------------------------------
	//	Get the firewall
	//-------------------------------------

	/*fw, response, err := deployedFw.fwAPI.ReadFirewallByID(nil, name)

	if err != nil {
		l.Errorln("Could not get firewall with name", name, ":", err, response)

		if response.StatusCode != 200 {
			l.Errorln("The firewall is nil. Will stop now.")
			return nil
		}
	}

	deployedFw.firewall = &fw

	// Since Interactive is not sent in the request, we will do it again now
	response, err = deployedFw.fwAPI.UpdateFirewallInteractiveByID(nil, name, false)

	if err != nil {
		l.Warningln("Could not set interactive to false for firewall", name, ":", err, response, ". Applying rules may take some time!")
	}*/

	return &deployedFw
}

// Link adds a new pod to the list of pods that must be managed by this firewall manager.
// Best practice is to only link similar pods (e.g.: same labels, same namespace, same node) to a firewall manager.
// It returns TRUE if the pod was inserted, FALSE if it already existed or an error occurred
func (d *DeployedFirewall) Link(pod *core_v1.Pod) bool {
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
	//	We are going to get all rules regardless of the policy they belong to, so we can make a single http request.
	ingressRules := []k8sfirewall.ChainRule{}
	egressRules := []k8sfirewall.ChainRule{}

	if len(ingressRules) > 0 || len(egressRules) > 0 {
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
		if err := d.injecter(name, ingressRules, egressRules, nil); err != nil {
			//	injecter fails only if pod's firewall is not ok (it is dying or crashed or not found), so there's no point in going on.
			l.Warningf("Injecter encountered an error upon linking the pod: %s. Will stop here.", err)
			return false
		}
	}

	// -- ingress
	err := d.updateDefaultAction(name, "ingress", d.ingressDefaultAction)
	if err != nil {
		l.Errorln("Could not update the default ingress action:", err)
	} else {
		_, err := d.applyRules(name, "ingress")
		if err != nil {
			l.Errorln("Could not apply ingress rules:", err)
		}
	}

	// -- egress
	err = d.updateDefaultAction(name, "egress", d.egressDefaultAction)
	if err != nil {
		l.Errorln("Could not update the default egress action:", err)
	} else {
		_, err := d.applyRules(name, "egress")
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
func (d *DeployedFirewall) Unlink(pod *core_v1.Pod, destroy bool) (bool, int) {
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
	if destroy {
		if err := d.destroyFw(name); err != nil {
			l.Warningln("Could not delete firewall for the provided pod.")
		}
	}
	delete(d.linkedPods, podUID)

	return true, len(d.linkedPods)
}

// IsPodLinked returns true if the provided pod ID is linked and currently monitored by this firewall manager.
func (d *DeployedFirewall) IsPodLinked(id k8s_types.UID) bool {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, linked := d.linkedPods[id]
	return linked
}

// LinkedPods returns a map of pods monitored by this firewall manager.
func (d *DeployedFirewall) LinkedPods() map[k8s_types.UID]string {
	d.lock.Lock()
	defer d.lock.Unlock()

	return d.linkedPods
}

//	TODO: remove this
func (d *DeployedFirewall) ForPod() k8s_types.UID {
	return d.podUID
}

func (d *DeployedFirewall) EnforcePolicy(policyName, policyType string, ingress, egress []k8sfirewall.ChainRule, actions pcn_types.FirewallActions) (error, error) {
	//-------------------------------------
	//	Init
	//-------------------------------------
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "EnforcePolicy"})
	l.Infof("firewall %s is going to enforce policy %s", d.name, policyName)

	var iError error
	var eError error

	//	Only one policy at a time, please
	d.lock.Lock()
	defer d.lock.Unlock()

	//-------------------------------------
	//	Define the actions
	//-------------------------------------

	//	TODO: define the policy actions

	//-------------------------------------
	//	Calculate the IDs concurrently
	//-------------------------------------

	ingressIDs, egressIDs := d.buildIDs(policyName, ingress, egress)

	//-------------------------------------
	//	Inject the rules on each firewall
	//-------------------------------------

	if len(d.linkedPods) < 1 {
		l.Infoln("There are no linked pods. Stopping here.")
		return nil, nil
	}

	var injectWaiter sync.WaitGroup
	injectWaiter.Add(len(d.linkedPods))

	for _, ip := range d.linkedPods {
		go d.injecter("fw-"+ip, ingressIDs, egressIDs, &injectWaiter)
	}
	injectWaiter.Wait()
	// TODO: inject the rules...

	/*if ok, _ := d.isFirewallOk(d.podIP); !ok {
		l.Errorln("Firewall seems not to be ok! Will not inject rules.")
		return errors.New("Firewall is not ok"), errors.New("Firewall is not ok")
	}*/

	//	Ingress
	/*if len(ingress) > 0 {
		go func() {
			defer applyWait.Done()

			if rulesWithIds, err := d.injectRules("ingress", ingress); err == nil {
				injectedRules.ingress = rulesWithIds
			} else {
				iError = err
			}
		}()
	}*/

	//	Egress
	/*if len(egress) > 0 {
		go func() {
			defer applyWait.Done()

			if rulesWithIds, err := d.injectRules("egress", egress); err == nil {
				injectedRules.egress = rulesWithIds
			} else {
				eError = err
			}
		}()
	}*/

	//applyWait.Wait()

	//-------------------------------------
	//	Update rules struct
	//-------------------------------------

	//	If at least something succeded, then we can specify that this firewall implements this policy
	/*if iError == nil || eError == nil {
		//	Add the newly created rules on our struct, so we can reference them at all times

		//	Ingress
		if len(injectedRules.ingress) > 0 {
			if _, exists := d.ingressRules[policyName]; !exists {
				d.ingressRules[policyName] = []k8sfirewall.ChainRule{}
			}
			d.ingressRules[policyName] = append(d.ingressRules[policyName], injectedRules.ingress...)
		}

		//	Egress
		if len(injectedRules.egress) > 0 {
			if _, exists := d.egressRules[policyName]; !exists {
				d.egressRules[policyName] = []k8sfirewall.ChainRule{}
			}
			d.egressRules[policyName] = append(d.egressRules[policyName], injectedRules.egress...)
		}
	}*/

	//-------------------------------------
	//	Update default actions
	//-------------------------------------

	//	So we just enforced a new policy. The final step is to change actions (if needed)
	//	But only if we did not do that already!
	if _, exists := d.policyTypes[policyName]; !exists {
		d.policyTypes[policyName] = policyType
		d.updateCounts("increase", policyType)

		//	---	React to pod events
		/*d.policyActions[policyName] = &policyActions{}
		if len(actions.Ingress) > 0 || len(actions.Egress) > 0 {
			d.definePolicyActions(policyName, actions.Ingress, actions.Egress)
		}*/
	}

	return iError, eError
}

// updateCounts updates the internal counts of policies types enforced, making sure default actions are respected.
// This is just a convenient method used to keep core methods (EnforcePolicy and CeasePolicy) as clean and readable as possible.
// When possible, this function is used in place of increaseCount or decreaseCount, as it is preferrable to do it like this.
func (d *DeployedFirewall) updateCounts(operation, policyType string) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "updateCounts(" + operation + "," + policyType + ")"})

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
			name := "fw-" + ip
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
			name := "fw-" + ip
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
func (d *DeployedFirewall) increaseCount(which string) bool {
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
func (d *DeployedFirewall) decreaseCount(which string) bool {
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
func (d *DeployedFirewall) buildIDs(policyName string, ingress, egress []k8sfirewall.ChainRule) ([]k8sfirewall.ChainRule, []k8sfirewall.ChainRule) {
	var applyWait sync.WaitGroup
	applyWait.Add(2)
	defer applyWait.Wait()

	// The rules in memory
	d.ingressRules[policyName] = map[int32]k8sfirewall.ChainRule{}
	d.egressRules[policyName] = map[int32]k8sfirewall.ChainRule{}

	description := "policy=" + policyName

	// --- calculate ingress ids
	go func() {
		defer applyWait.Done()
		i := 0
		for ; i < len(ingress); i++ {
			ingress[i].Id = d.ingressID + int32(i)
			ingress[i].Description = description
			d.ingressRules[policyName][d.ingressID+int32(i)] = ingress[i]
		}

		d.ingressID += int32(i)
	}()

	// --- calculate egress ids
	go func() {
		defer applyWait.Done()
		i := 0
		for ; i < len(egress); i++ {
			egress[i].Id = d.egressID + int32(i)
			egress[i].Description = description
			d.egressRules[policyName][d.ingressID+int32(i)] = egress[i]
		}

		d.egressID += int32(i)
	}()

	return ingress, egress
}

// injecter is a convenient method for injecting ingress and egress rules for a single firewall
func (d *DeployedFirewall) injecter(firewall string, ingressRules, egressRules []k8sfirewall.ChainRule, waiter *sync.WaitGroup) error {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "Injecter(" + firewall + ", ...)"})

	//	Should I notify caller when I'm done?
	if waiter != nil {
		defer waiter.Done()
	}

	//	Is firewall ok?
	if ok, err := d.isFirewallOk(firewall); !ok {
		//	TODO: define an array with rules not injected?
		l.Errorln("Could not inject rules. Firewall is not ok:", err)
		return err
	}

	//-------------------------------------
	//	Inject rules direction concurrently
	//-------------------------------------
	var injectWaiter sync.WaitGroup
	injectWaiter.Add(2)
	defer injectWaiter.Wait()

	//	TODO: how to handle these if they have errors?
	go d.injectRules(firewall, "ingress", ingressRules, &injectWaiter)
	go d.injectRules(firewall, "egress", egressRules, &injectWaiter)

	return nil
}

// injectRules is a wrapper for firewall's CreateFirewallChainRuleListByID and CreateFirewallChainApplyRulesByID methods.
func (d *DeployedFirewall) injectRules(firewall, direction string, rules []k8sfirewall.ChainRule, waiter *sync.WaitGroup) error {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "injectRules(" + firewall + "," + direction + ",...)"})

	//	Should I notify caller when I'm done?
	if waiter != nil {
		defer waiter.Done()
	}

	//-------------------------------------
	//	Inject & apply
	//-------------------------------------
	response, err := d.fwAPI.CreateFirewallChainRuleListByID(nil, firewall, direction, rules)
	if err != nil {
		l.Errorln("Error while trying to inject rules:", err, response)
		return err
	}
	if response, err := d.applyRules(firewall, direction); err != nil {
		l.Errorln("Error while trying to apply rules:", err, response)
		return err
	}

	return nil
}

func (d *DeployedFirewall) definePolicyActions(policyName string, ingress, egress []pcn_types.FirewallAction) {
	// TODO: implement this
	//-------------------------------------
	//	Ingress
	//-------------------------------------
	/*for _, i := range ingress {

		//	Subscribe to the pod controller for this specific object
		//	---	When the pod is born
		bornSubscription, err := d.podController.Subscribe(pcn_types.Update, pcn_types.ObjectQuery{
			Labels: i.PodLabels,
		}, pcn_types.ObjectQuery{
			Name:   i.NamespaceName,
			Labels: i.NamespaceLabels,
		}, pcn_types.PodRunning, func(pod *core_v1.Pod) {
			d.reactToPod(pod, policyName, i.Actions)
		})

		if err == nil {
			d.policyActions[policyName].ingress = append(d.policyActions[policyName].ingress, bornSubscription)
		}

		//	---	When the pod dies
		dieSubscription, err := d.podController.Subscribe(pcn_types.Delete, pcn_types.ObjectQuery{
			Labels: i.PodLabels,
		}, pcn_types.ObjectQuery{
			Name:   i.NamespaceName,
			Labels: i.NamespaceLabels,
		}, pcn_types.PodRunning, func(pod *core_v1.Pod) {
			d.RemoveIPReferences(pod.Status.PodIP, policyName)
		})

		if err == nil {
			d.policyActions[policyName].ingress = append(d.policyActions[policyName].ingress, dieSubscription)
		}
	}

	//-------------------------------------
	//	Egress
	//-------------------------------------
	for _, e := range egress {

		bornSubscription, err := d.podController.Subscribe(pcn_types.Update, pcn_types.ObjectQuery{
			Labels: e.PodLabels,
		}, pcn_types.ObjectQuery{
			Name:   e.NamespaceName,
			Labels: e.NamespaceLabels,
		}, pcn_types.PodRunning, func(pod *core_v1.Pod) {
			log.Printf("###egress###%+v\n", e)
			d.reactToPod(pod, policyName, e.Actions)
		})

		if err == nil {
			d.policyActions[policyName].egress = append(d.policyActions[policyName].egress, bornSubscription)
		}
	}*/
}

func (d *DeployedFirewall) reactToPod(pod *core_v1.Pod, policyName string, action pcn_types.ParsedRules) {
	// TODO: implement this, and make exported
	//	Does the policy exist?
	/*if !d.IsPolicyEnforced(policyName) {
		return
	}

	ingress := make([]k8sfirewall.ChainRule, len(action.Ingress))
	egress := make([]k8sfirewall.ChainRule, len(action.Egress))

	//	Have I already checked this pod?
	//	In an anoymous function, so we can use defer
	func(ip string) {
		d.checkLock.Lock()
		defer d.checkLock.Unlock()

		key := policyName + ":" + pod.Status.PodIP
		if _, exists := d.checkedPods[key]; exists {
			//	This pod has been already checked. Stop here.
			return
		}
		d.checkedPods[ip] = true
	}(pod.Status.PodIP)

	//	Ingress
	for i := 0; i < len(action.Ingress); i++ {
		ingress[i] = action.Ingress[i]
		ingress[i].Src = pod.Status.PodIP
	}

	//	Egress
	for i := 0; i < len(action.Egress); i++ {
		egress[i] = action.Egress[i]
		egress[i].Dst = pod.Status.PodIP
	}

	//	No need to specify a policy type
	d.EnforcePolicy(policyName, "", ingress, egress, pcn_types.FirewallActions{})*/
}

func (d *DeployedFirewall) CeasePolicy(policyName string) {
	// TODO: implement this
	/*var l = log.WithFields(log.Fields{
		"by":     d.firewall.Name,
		"method": "CeasePolicy(" + policyName + ")",
	})

	var deleteWait sync.WaitGroup
	deleteNumber := 0

	d.lock.Lock()
	defer d.lock.Unlock()

	//	Do they exist?
	policyIngress, iexists := d.ingressRules[policyName]
	policyEgress, eexists := d.ingressRules[policyName]
	if !iexists && !eexists {
		l.Infoln("fw", d.firewall.Name, "has no", policyName, "in its list of implemented policies rules")
		return
	}

	//	What type was this policy?
	policyType := d.policyTypes[policyName]

	//-------------------------------------
	//	Are there any rules on this policy?
	//-------------------------------------
	//	NOTE: check on exists and len are actually useless (read EnforcePolicy). But since I'm paranoid, I'll do it anyway.

	//	Check for ingress rules
	if iexists && len(policyIngress) < 1 {
		delete(d.ingressRules, policyName)
	}
	//	Check for egress rules
	if eexists && len(policyEgress) < 1 {
		delete(d.ingressRules, policyName)
	}

	//	After the above, policy is not even listed anymore? (which means: both ingress and egress were actually empty?)
	policyIngress, iexists = d.ingressRules[policyName]
	policyEgress, eexists = d.ingressRules[policyName]
	if !iexists && !eexists {

		//	They were empty: no point in going on. Let's now decrease counts.
		switch policyType {
		case "ingress":
			d.decreaseCount("ingress")
		case "egress":
			d.decreaseCount("egress")
		case "*":
			d.decreaseCount("ingress")
			d.decreaseCount("egress")
		}

		return
	}

	//-------------------------------------
	//	Remove the rules
	//-------------------------------------

	if ok, _ := d.isFirewallOk(d.podIP); !ok {
		l.Errorln("Firewall seems not to be ok! Will not remove rules.")
		return
	}

	if iexists && len(policyIngress) > 0 {
		deleteNumber++
	}
	if eexists && len(policyEgress) > 0 {
		deleteNumber++
	}
	deleteWait.Add(deleteNumber)

	//	Ingress
	if iexists && len(policyIngress) > 0 {
		go func(rules []k8sfirewall.ChainRule) {
			defer deleteWait.Done()

			iFailedRules := d.RemoveRules("ingress", rules)
			if len(iFailedRules) > 0 {
				failedRules.ingress = iFailedRules
			}
		}(policyIngress)
	}

	//	Egress
	if eexists && len(policyEgress) > 0 {
		go func(rules []k8sfirewall.ChainRule) {
			defer deleteWait.Done()

			eFailedRules := d.RemoveRules("egress", rules)
			if len(eFailedRules) > 0 {
				failedRules.egress = eFailedRules
			}
		}(policyEgress)
	}

	deleteWait.Wait()

	//-------------------------------------
	//	Update the enforced policies
	//-------------------------------------

	if len(failedRules.ingress) < 1 && len(failedRules.egress) < 1 {
		//	All rules were delete successfully: we may delete the entry
		delete(d.ingressRules, policyName)
		delete(d.egressRules, policyName)

		delete(d.policyTypes, policyName)

	} else {
		//	Some rules were not deleted. We can't delete the entry: we need to change it with the still active rules.
		d.ingressRules[policyName] = failedRules.ingress
		d.egressRules[policyName] = failedRules.egress
	}

	//-------------------------------------
	//	Update the actions
	//-------------------------------------

	//	We just removed a policy. We must change the actions (if needed: that's what decreaseCount does)
	switch policyType {
	case "ingress":
		d.decreaseCount("ingress")
	case "egress":
		d.decreaseCount("egress")
	case "*":
		d.decreaseCount("ingress")
		d.decreaseCount("egress")
	}

	d.unsubscribeToAllActions(policyName)
	delete(d.policyActions, policyName)*/
}

func (d *DeployedFirewall) unsubscribeToAllActions(policyName string) {
	// TODO: implement this
	/*actions, exists := d.policyActions[policyName]

	if !exists {
		return
	}

	d.lock.Lock()
	defer d.lock.Unlock()

	for _, i := range actions.ingress {
		i()
	}

	for _, e := range actions.egress {
		e()
	}*/
}

func (d *DeployedFirewall) RemoveRules(direction string, rules []k8sfirewall.ChainRule) []k8sfirewall.ChainRule {
	//	TODO: implement this
	return []k8sfirewall.ChainRule{}
	/*var l = log.WithFields(log.Fields{
		"by":     d.firewall.Name,
		"method": "RemoveRules(" + direction + ")",
	})

	//	Just in case...
	if rules == nil {
		err := errors.New("Rules is nil")
		l.Errorln(err.Error())
		return nil
	}

	//	Make sure to call this function after checking for rules
	if len(rules) < 1 {
		l.Warningln("There are no rules to remove.")
		return []k8sfirewall.ChainRule{}
	}

	//	1) delete the rule
	//	2) if successful, do nothing
	//	3) if not, add this rule to the failed ones
	failedRules := []k8sfirewall.ChainRule{}

	//	No need to do this with separate threads...
	for _, rule := range rules {
		response, err := d.fwAPI.DeleteFirewallChainRuleByID(nil, d.firewall.Name, direction, rule.Id)
		if err != nil {
			l.Errorln("Error while trying to delete rule", rule.Id, "in", direction, "for firewall", d.firewall.Name, err, response)
			failedRules = append(failedRules, rule)
		}
	}

	if _, err := d.applyRules(direction); err != nil {
		l.Errorln("Error while trying to apply rules", d.firewall.Name, "in", direction, ":", err)
	}

	//	Hopefully this is empty
	return failedRules*/
}

func (d *DeployedFirewall) RemoveIPReferences(ip, policyName string) {

	//	TODO: implement this

	/*ingressIDs := []k8sfirewall.ChainRule{}
	egressIDs := []k8sfirewall.ChainRule{}

	d.lock.Lock()
	defer d.lock.Unlock()

	//	Does this policy exists?
	policyRules, exists := d.rules[policyName]
	if !exists {
		return
	}

	//-------------------------------------
	//	Look for it
	//-------------------------------------

	var directionsWait sync.WaitGroup
	directionsWait.Add(2)

	//	---	Ingress
	go func() {
		defer directionsWait.Done()

		for _, rule := range policyRules.ingress {
			if rule.Src == ip {
				ingressIDs = append(ingressIDs, rule)
			}
		}
	}()

	//	---	Egress
	go func() {
		defer directionsWait.Done()

		for _, rule := range policyRules.egress {
			if rule.Dst == ip {
				ingressIDs = append(ingressIDs, rule)
			}
		}
	}()

	directionsWait.Wait()

	//-------------------------------------
	//	Remove it
	//-------------------------------------

	if len(ingressIDs) < 1 && len(egressIDs) < 1 {
		return
	}
	if len(ingressIDs) > 0 {
		d.RemoveRules("ingress", ingressIDs)
	}
	if len(egressIDs) > 0 {
		d.RemoveRules("egress", egressIDs)
	}

	//-------------------------------------
	//	Update the checked pods
	//-------------------------------------

	d.checkLock.Lock()
	defer d.checkLock.Unlock()
	key := policyName + ":" + ip
	if _, exists := d.checkedPods[key]; exists {
		delete(d.checkedPods, key)
	}*/
}

// IsPolicyEnforced returns true if this firewall enforces this policy
func (d *DeployedFirewall) IsPolicyEnforced(name string) bool {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, iexists := d.ingressRules[name]
	_, eexists := d.egressRules[name]

	return iexists || eexists
}

// isFirewallOk checks if the firewall is ok. Used to check if firewall exists and is healthy
func (d *DeployedFirewall) isFirewallOk(firewall string) (bool, error) {
	//	We are going to do that by reading its uuid
	if _, _, err := d.fwAPI.ReadFirewallUuidByID(nil, firewall); err != nil {
		return false, err
	}
	return true, nil
}

// updateDefaultAction is a wrapper for UpdateFirewallChainDefaultByID method.
func (d *DeployedFirewall) updateDefaultAction(firewall, direction, to string) error {
	_, err := d.fwAPI.UpdateFirewallChainDefaultByID(nil, firewall, direction, to)
	return err
}

// applyRules is a wrapper for CreateFirewallChainApplyRulesByID method.
func (d *DeployedFirewall) applyRules(firewall, direction string) (bool, error) {
	out, _, err := d.fwAPI.CreateFirewallChainApplyRulesByID(nil, firewall, direction)
	return out.Result, err
}

// destroyFw destroy a firewall linked by this firewall manager
func (d *DeployedFirewall) destroyFw(name string) error {
	_, err := d.fwAPI.DeleteFirewallByID(nil, name)
	return err
}

func (d *DeployedFirewall) Destroy() error {
	// TODO: implement this
	return nil
	/*var l = log.WithFields(log.Fields{
		"by":     d.firewall.Name,
		"method": "Destroy()",
	})

	d.lock.Lock()
	defer d.lock.Unlock()

	//-------------------------------------
	//	Unsubscribe from all actions first
	//-------------------------------------

	//	We first unsubscribe from all actions, so that if an event is triggered after we remove, they won't do any harm
	for _, action := range d.policyActions {
		for _, unsubscribe := range action.ingress {
			unsubscribe()
		}
		for _, unsubscribe := range action.egress {
			unsubscribe()
		}
	}

	//-------------------------------------
	//	Actually destroy the firewall
	//-------------------------------------

	if response, err := d.fwAPI.DeleteFirewallByID(nil, d.firewall.Name); err != nil {
		l.Errorln("Failed to destroy firewall,", d.firewall.Name, ":", err, response)
		return err
	}

	return nil*/
}
