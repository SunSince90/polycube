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
	Link(k8s_types.UID, string) bool
	Unlink(k8s_types.UID, bool) (bool, int)
	LinkedPods() map[k8s_types.UID]string

	EnforcePolicy(string, string, []k8sfirewall.ChainRule, []k8sfirewall.ChainRule, pcn_types.FirewallActions) (error, error)
	CeasePolicy(string)

	ForPod() k8s_types.UID
	RemoveRules(string, []k8sfirewall.ChainRule) []k8sfirewall.ChainRule
	RemoveIPReferences(string, string)
	IsPolicyEnforced(string) bool
	Destroy() error
}

type DeployedFirewall struct {
	podController pcn_controllers.PodController

	ingressRules map[string]map[int32]k8sfirewall.ChainRule
	egressRules  map[string]map[int32]k8sfirewall.ChainRule

	/*ingressChain *k8sfirewall.Chain
	egressChain  *k8sfirewall.Chain*/
	fwAPI k8sfirewall.FirewallAPI

	//	TODO: remove the following two
	podUID   k8s_types.UID
	podIP    string
	firewall *k8sfirewall.Firewall

	//	TODO: check if this link lock is useful
	//linkLock sync.Mutex

	// linkedPods is a map of pods monitored by this firewall manager
	linkedPods map[k8s_types.UID]linkedPod
	// name is the name of this firewall manager
	name string
	// log is a new entry in logger
	log *log.Logger
	// lock is firewall manager's main lock
	lock sync.Mutex
	// ingressID is the first usable ingress ID
	ingressID int32
	//	egressID is the first usable egress ID
	egressID int32

	policyTypes          map[string]string
	policyActions        map[string]*policyActions
	ingressPoliciesCount int
	egressPoliciesCount  int

	checkLock   sync.Mutex
	checkedPods map[string]bool
	//	For caching.
	/*lastIngressID int32
	lastEgressID int32*/
}

type linkedPod struct {
	ip string
	sync.Mutex
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

	deployedFw.ingressID = 1
	deployedFw.egressID = 1
	deployedFw.linkedPods = map[k8s_types.UID]linkedPod{}
	deployedFw.podController = podController
	deployedFw.name = name
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

// Link adds a new pod to the list of pods that must be handled by this firewall manager.
// Best practice is to only link pods with the same labels on the same namespace and node to a firewall manager.
// It returns TRUE if the pod was inserted, FALSE if it already existed or an error occurred
func (d *DeployedFirewall) Link(podUID k8s_types.UID, podIP string) bool {
	d.lock.Lock()
	defer d.lock.Unlock()

	//	Is the firewall ok?
	if ok, err := d.isFirewallOk(podIP); !ok {
		d.log.Errorf("Could not link firewall for pod %s: %s", podIP, err.Error())
		return false
	}

	//	Link it, if not already there
	_, existed := d.linkedPods[podUID]
	if !existed {
		d.linkedPods[podUID] = linkedPod{
			ip: podIP,
		}
	}

	//	TODO: inject the rules for it.
	//	inject(name)
	//	TODO: remove this
	d.log.Infoln("Pod with IP", podIP, "has been linked")

	return existed
}

// Unlink removes the provided pod from the list of monitored ones by this firewall manager.
// If the second argument is TRUE, then the provided pod's firewall will be destroyed as well.
// It returns FALSE if the pod was not among the monitored ones and the number of remaining pods linked.
func (d *DeployedFirewall) Unlink(podUID k8s_types.UID, destroy bool) (bool, int) {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, ok := d.linkedPods[podUID]
	if !ok {
		//	This pod was not even linked
		return false, len(d.linkedPods)
	}

	if destroy {
		//	TODO: d.destroy(podUID)
	}
	delete(d.linkedPods, podUID)

	//	TODO: remove this
	log.Infoln("Pod with IP", d.linkedPods[podUID], "has been unlinked")

	return true, len(d.linkedPods)
}

// LinkedPods returns a map of pods monitored by this firewall manager.
func (d *DeployedFirewall) LinkedPods() map[k8s_types.UID]string {
	d.lock.Lock()
	defer d.lock.Unlock()

	podsInside := make(map[k8s_types.UID]string, len(d.linkedPods))
	for k, v := range d.linkedPods {
		podsInside[k] = v.ip
	}

	return podsInside
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
	l.WithFields(log.Fields{"by": d.firewall.Name, "method": "EnforcePolicy"})
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

	var applyWait sync.WaitGroup
	applyWait.Add(2)

	d.ingressRules[policyName] = map[int32]k8sfirewall.ChainRule{}
	d.egressRules[policyName] = map[int32]k8sfirewall.ChainRule{}

	// --- calculate ingress ids
	go func() {
		defer applyWait.Done()
		i := 0
		for ; i < len(ingress); i++ {
			ingress[i].Id = d.ingressID + int32(i)
		}

		d.ingressID += int32(i)
	}()

	// --- calculate egress ids
	go func() {
		defer applyWait.Done()
		i := 0
		for ; i < len(egress); i++ {
			egress[i].Id = d.egressID + int32(i)
		}

		d.egressID += int32(i)
	}()

	applyWait.Wait()

	//-------------------------------------
	//	Inject the rules on each firewall
	//-------------------------------------

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
	//	Update Reactions & default action
	//-------------------------------------

	//	So we just enforced a new policy. The final step is to change actions (if needed: that's what increaseCount does)
	//	But only if we did not do that already!
	if _, exists := d.policyTypes[policyName]; !exists {

		//	---	Update default actions
		d.policyTypes[policyName] = policyType
		switch policyType {
		case "ingress":
			d.increaseCount("ingress")
		case "egress":
			d.increaseCount("egress")
		case "*":
			d.increaseCount("ingress")
			d.increaseCount("egress")
		}

		//	---	React to pod events
		d.policyActions[policyName] = &policyActions{}
		if len(actions.Ingress) > 0 || len(actions.Egress) > 0 {
			d.definePolicyActions(policyName, actions.Ingress, actions.Egress)
		}
	}

	return iError, eError
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
	// TODO: implement this
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

func (d *DeployedFirewall) injectRules(direction string, rules []k8sfirewall.ChainRule) ([]k8sfirewall.ChainRule, error) {

	// TODO: implement this
	return []k8sfirewall.ChainRule{}, nil

	//	UPDATE: it's better to always inject with a policy instead of doing it anonymously.
	//	That's why this function is un-exported now

	/*var l = log.WithFields(log.Fields{
		"by":     d.firewall.Name,
		"method": "injectRules()",
	})

	//	Just in case...
	if rules == nil {
		//l.Errorln("Rules is nil")
		return nil, errors.New("Rules is nil")
	}

	if len(rules) < 1 {
		//l.Errorln("No rules to inject")
		return nil, errors.New("No rules to inject")
	}

	var ID int32 = 1
	rulesToInject := []k8sfirewall.ChainRule{}

	//-------------------------------------
	//	Build the IDs & put my pod's IP
	//-------------------------------------

	chain, response, err := d.fwAPI.ReadFirewallChainByID(nil, d.firewall.Name, direction)
	if err != nil {
		l.Errorln("Error while trying to get chain for firewall", d.firewall.Name, "in", direction, ":", err, response)
		return nil, err
	}

	//	The last ID is always the default one's, which always increments by one as we push rules.
	if len(chain.Rule) > 1 {
		ID = chain.Rule[len(chain.Rule)-2].Id + 1
	}

	//	Modify the rules
	for _, rule := range rules {
		workedRule := k8sfirewall.ChainRule{}
		if direction == "ingress" {
			//	Make sure not to target myself
			if rule.Src != d.podIP {
				workedRule = rule
				workedRule.Dst = d.podIP
			}
		}
		if direction == "egress" {
			//	Make sure not to target myself
			if rule.Dst != d.podIP {
				workedRule = rule
				workedRule.Src = d.podIP
			}
		}

		if len(workedRule.Action) > 0 {
			workedRule.Id = ID
			ID++
			rulesToInject = append(rulesToInject, workedRule)
		}
	}

	if len(rulesToInject) < 1 {
		return rulesToInject, nil
	}

	//-------------------------------------
	//	Actually Inject
	//-------------------------------------

	response, err = d.fwAPI.CreateFirewallChainRuleListByID(nil, d.firewall.Name, direction, rulesToInject)
	if err != nil {
		l.Errorln("Error while trying to inject rules for firewall", d.firewall.Name, "in", direction, ":", err, response)
		return []k8sfirewall.ChainRule{}, err
	}

	if response, err := d.applyRules(direction); err != nil {
		l.Errorln("Error while trying to apply rules", d.firewall.Name, "in", direction, ":", err, response)
	}

	return rulesToInject, nil*/
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

// increaseCount increases the count of policies enforced and changes the default action for the provided direction, if needed.
// It returns the default action after increasing for the provided direction
func (d *DeployedFirewall) increaseCount(which string) string {

	//	NOTE: this function must be called while holding a lock!
	//	If there is at least one policy, then we must switch the default action to DROP for that type
	//	E.g.: if the policy had only INGRESS in its spec, then the ingress chain must be set to drop

	action := pcn_types.ActionForward

	if which != "ingress" && which != "egress" {
		return action
	}

	// Increment
	switch which {
	case "ingress":
		if d.ingressPoliciesCount++; d.ingressPoliciesCount == 1 {
			action = pcn_types.ActionDrop
		}
	case "egress":
		if d.egressPoliciesCount++; d.egressPoliciesCount == 1 {
			action = pcn_types.ActionDrop
		}
	}

	// Should we change action?
	if action == pcn_types.ActionDrop {
		d.updateDefaultAction(which, pcn_types.ActionDrop)
		d.applyRules(which)
	}

	return action
}

// decreaseCount decreases the count of policies enforced and changes the default action for the provided direction, if needed.
// It returns the default action after decreasing for the provided direction
func (d *DeployedFirewall) decreaseCount(which string) string {

	//	NOTE: this function must be called while holding a lock!
	//	If there are no policies enforced, then we must switch the default action to FORWARD for that type
	//	E.g.: if the policy had only INGRESS in its spec, then the ingress chain must be set to FORWARD

	action := pcn_types.ActionDrop

	if which != "ingress" && which != "egress" {
		return action
	}

	switch which {
	case "ingress":
		if d.ingressPoliciesCount--; d.ingressPoliciesCount == 0 {
			action = pcn_types.ActionForward
		}
	case "egress":
		if d.egressPoliciesCount--; d.egressPoliciesCount == 0 {
			action = pcn_types.ActionForward
		}
	}

	// Should we change action?
	if action == pcn_types.ActionForward {
		d.updateDefaultAction(which, pcn_types.ActionForward)
		d.applyRules(which)
	}

	return action
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
func (d *DeployedFirewall) isFirewallOk(ip string) (bool, error) {
	name := "fw-" + ip

	//	We are going to do that by reading its uuid
	if _, _, err := d.fwAPI.ReadFirewallUuidByID(nil, name); err != nil {
		return false, err
	}

	return true, nil
}

func (d *DeployedFirewall) updateDefaultAction(direction, to string) error {
	// TODO: implement this
	return nil
	/*var l = log.WithFields(log.Fields{
		"by":     d.firewall.Name,
		"method": "updateDefaultAction(" + direction + "," + to + ")",
	})

	response, err := d.fwAPI.UpdateFirewallChainDefaultByID(nil, d.firewall.Name, direction, to)

	if err != nil {
		l.Errorln("Could not set default", direction, "action to forward for firewall", d.firewall.Name, ":", err, response)
	}
	return err*/
}

func (d *DeployedFirewall) applyRules(direction string) (bool, error) {
	//	TODO: implement this
	return false, nil
	/*out, _, err := d.fwAPI.CreateFirewallChainApplyRulesByID(nil, d.firewall.Name, direction)
	return out.Result, err*/
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
