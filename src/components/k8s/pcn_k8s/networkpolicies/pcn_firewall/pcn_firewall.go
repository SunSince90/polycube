package pcnfirewall

import (
	"strings"
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
	EnforcePolicy(string, string, meta_v1.Time, []k8sfirewall.ChainRule, []k8sfirewall.ChainRule)
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
	ingressRules map[string][]k8sfirewall.ChainRule
	// egressRules contains the egress rules divided by policy
	egressRules map[string][]k8sfirewall.ChainRule
	// linkedPods is a map of pods monitored by this firewall manager
	linkedPods map[k8s_types.UID]string
	// Name is the name of this firewall manager
	name string
	// log is a new entry in logger
	log *log.Logger
	// lock is firewall manager's main lock
	lock sync.Mutex
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
		//	Policy types
		policyTypes: map[string]string{},
		//	Linked pods
		linkedPods: map[k8s_types.UID]string{},
		//	The default actions
		ingressDefaultAction: pcn_types.ActionForward,
		egressDefaultAction:  pcn_types.ActionForward,
		node:                 node,
		//	The priorities
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
		l.Errorf("Could not link firewall for pod %s: %s", name, err.Error())
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
		if err := d.injecter(name, ingressRules, egressRules, nil, 0, 0); err != nil {
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
// The second arguments specifies if the pod's firewall should be cleaned or destroyed.
// It returns FALSE if the pod was not among the monitored ones, and the number of remaining pods linked.
func (d *FirewallManager) Unlink(pod *core_v1.Pod, then UnlinkOperation) (bool, int) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "Unlink(" + pod.Name + ")"})

	d.lock.Lock()
	defer d.lock.Unlock()

	podUID := pod.UID

	_, ok := d.linkedPods[podUID]
	if !ok {
		//	This pod was not even linked
		return false, len(d.linkedPods)
	}

	podIP := d.linkedPods[pod.UID]
	name := "fw-" + podIP

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
			l.Warningln("Could not delete firewall for the provided pod:", err)
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
func (d *FirewallManager) EnforcePolicy(policyName, policyType string, policyTime meta_v1.Time, ingress, egress []k8sfirewall.ChainRule) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "EnforcePolicy"})
	l.Infof("firewall %s is going to enforce policy %s", d.name, policyName)

	//	Only one policy at a time, please
	d.lock.Lock()
	defer d.lock.Unlock()

	//-------------------------------------
	//	Store the rules
	//-------------------------------------

	ingressIDs, egressIDs := d.storeRules(policyName, "", ingress, egress)

	//-------------------------------------
	//	Update default actions
	//-------------------------------------

	//	update the policy type, so that later - if this policy is removed - we can enforce isolation mode correctly
	d.policyTypes[policyName] = policyType
	d.updateCounts("increase", policyType)

	//-------------------------------------
	//	Set its priority
	//-------------------------------------
	//	By setting its priority, we know where to start injecting rules from
	iStartFrom, eStartFrom := d.setPolicyPriority(policyName, policyTime)

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

// updateCounts updates the internal counts of policies types enforced, making sure default actions are respected.
// This is just a convenient method used to keep core methods (EnforcePolicy and CeasePolicy) as clean and readable as possible.
// When possible, this function is used in place of increaseCount or decreaseCount, as it is preferrable to do it like this.
func (d *FirewallManager) updateCounts(operation, policyType string) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "updateCounts(" + operation + "," + policyType + ")"})

	//	BRIEF: read increaseCounts and decreaseCounts for an explanation of when and why
	//	these functions are called.

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
			//	If this is the *first* ingress policy, then switch to drop, otherwise no need to do that (it's already DROP)
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
		//	Return to default=FORWARD only if there are no policies anymore after removing this
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

// storeRules stores rules in memory according to their policy
func (d *FirewallManager) storeRules(policyName, target string, ingress, egress []k8sfirewall.ChainRule) ([]k8sfirewall.ChainRule, []k8sfirewall.ChainRule) {
	var applyWait sync.WaitGroup
	applyWait.Add(2)
	defer applyWait.Wait()

	if _, exists := d.ingressRules[policyName]; !exists {
		d.ingressRules[policyName] = []k8sfirewall.ChainRule{}
	}
	if _, exists := d.egressRules[policyName]; !exists {
		d.egressRules[policyName] = []k8sfirewall.ChainRule{}
	}

	description := "policy=" + policyName
	newIngress := make([]k8sfirewall.ChainRule, len(ingress))
	newEgress := make([]k8sfirewall.ChainRule, len(egress))

	// --- ingress
	go func() {
		defer applyWait.Done()

		for i, rule := range ingress {
			newIngress[i] = rule
			newIngress[i].Description = description
			if len(target) > 0 {
				//newIngress[i].Src = target
				newIngress[i].Dst = target
			}

			d.ingressRules[policyName] = append(d.ingressRules[policyName], newIngress[i])
		}
	}()

	// --- egress
	go func() {
		defer applyWait.Done()

		for i, rule := range egress {
			newEgress[i] = rule
			newEgress[i].Description = description
			if len(target) > 0 {
				newEgress[i].Src = target
				//newEgress[i].Dst = target
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
	//	The ip of the pod we are protecting. Used for the SRC or the DST
	me := strings.Split(firewall, "-")[1]

	// We are using the insert call here, which adds the rule on the startFrom id and pushes the other rules downwards.
	// In order to preserve original order, we're going to start injecting from the last to the first.

	len := len(rules)
	for i := len - 1; i > -1; i-- {
		ruleToInsert := k8sfirewall.ChainInsertInput(rules[i])
		ruleToInsert.Id = startFrom

		//	This is useless because there's only the pod on the other link, but... let's do it anyway
		if direction == "ingress" {
			ruleToInsert.Src = me
		} else {
			ruleToInsert.Dst = me
		}

		_, response, err := d.fwAPI.CreateFirewallChainInsertByID(nil, firewall, direction, ruleToInsert)
		if err != nil {
			l.Errorln("Error while trying to inject rule:", err, response)
			//	This rule had an error, but we still gotta push the other ones dude...
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

		//	Delete the found rules from each linked pod
		for _, ip := range d.linkedPods {
			name := "fw-" + ip
			d.deleteRules(name, "ingress", rules)
			d.applyRules(name, "ingress")
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

		//	Delete the found rules from each linked pod
		for _, ip := range d.linkedPods {
			name := "fw-" + ip
			d.deleteRules(name, "egress", rules)
			d.applyRules(name, "egress")
		}
	}()

	waiter.Wait()
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

	me := strings.Split(fw, "-")[1]

	// this is a fake deep copy-cast.
	cast := func(rule k8sfirewall.ChainRule) k8sfirewall.ChainDeleteInput {

		src := rule.Src
		dst := rule.Dst

		if direction == "ingress" {
			src = me
		} else {
			dst = me
		}

		return k8sfirewall.ChainDeleteInput{
			Src:         src,
			Dst:         dst,
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

	l.Infoln("Good bye!")
}
