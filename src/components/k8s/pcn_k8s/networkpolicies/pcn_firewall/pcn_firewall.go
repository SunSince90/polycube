package pcnfirewall

import (
	"strings"
	"sync"

	//	TODO-ON-MERGE: change these to the polycube path
	pcn_controllers "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/controllers"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"

	log "github.com/sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"
)

// PcnFirewall is the interface of the firewall manager.
type PcnFirewall interface {
	Link(*core_v1.Pod) bool
	Unlink(*core_v1.Pod) (bool, int)
	LinkedPods() map[k8s_types.UID]string
	Selector() (map[string]string, string)
	Name() string
	EnforcePolicy(string, string, []k8sfirewall.ChainRule, []k8sfirewall.ChainRule)
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
	// policyTypes is a map of policies types enforced. Used to know how the default action should be handled.
	policyTypes map[string]string
	// selector defines what kind of pods this firewall is monitoring
	selector selector
	// node is the node in which we are currently running
	node *core_v1.Node
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
		//	Policy types
		policyTypes: map[string]string{},
		//	Linked pods
		linkedPods: map[k8s_types.UID]string{},
		node:       node,
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
	//	Finally, link it
	//-------------------------------------
	//	From now on, when this firewall manager will react to events, this pod's firewall will be updated as well.
	d.linkedPods[podUID] = podIP
	return true
}

// Unlink removes the provided pod from the list of monitored ones by this firewall manager.
// It returns FALSE if the pod was not among the monitored ones, and the number of remaining pods linked.
func (d *FirewallManager) Unlink(pod *core_v1.Pod) (bool, int) {
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
func (d *FirewallManager) EnforcePolicy(policyName, policyType string, ingress, egress []k8sfirewall.ChainRule) {
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": "FirewallManager-" + d.name, "method": "EnforcePolicy"})
	l.Infof("firewall %s is going to enforce policy %s", d.name, policyName)

	//	Only one policy at a time, please
	d.lock.Lock()
	defer d.lock.Unlock()

	//-------------------------------------
	//	Calculate the IDs concurrently
	//-------------------------------------

	ingressIDs, egressIDs := d.storeRules(policyName, "", ingress, egress)

	//-------------------------------------
	//	Update default actions
	//-------------------------------------

	//	update the policy type, so that later - if this policy is removed - we can enforce isolation mode correctly
	d.policyTypes[policyName] = policyType

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
		go d.injecter(name, ingressIDs, egressIDs, &injectWaiter, 0, 0)
	}
	injectWaiter.Wait()
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

// applyRules is a wrapper for CreateFirewallChainApplyRulesByID method.
func (d *FirewallManager) applyRules(firewall, direction string) (bool, error) {
	out, _, err := d.fwAPI.CreateFirewallChainApplyRulesByID(nil, firewall, direction)
	return out.Result, err
}
