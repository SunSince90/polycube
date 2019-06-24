package networkpolicies

import (
	"sort"
	"strings"
	"sync"
	"time"

	//	TODO-ON-MERGE: change these to the polycube path
	pcn_controllers "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/controllers"
	pcn_firewall "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/networkpolicies/pcn_firewall"
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"

	log "github.com/sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	networking_v1 "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"
)

// PcnNetworkPolicyManager is a network policy manager
type PcnNetworkPolicyManager interface {
	DeployK8sPolicy(*networking_v1.NetworkPolicy)
	RemoveK8sPolicy(*networking_v1.NetworkPolicy)
	UpdateK8sPolicy(*networking_v1.NetworkPolicy)
}

// NetworkPolicyManager is the implementation of the policy manager
type NetworkPolicyManager struct {
	// dnpc is the default (from kubernetes) policy controller
	dnpc *pcn_controllers.DefaultNetworkPolicyController
	// podController is the pod controller
	podController pcn_controllers.PodController
	// defaultPolicyParser is the instance of the default policy parser
	defaultPolicyParser PcnDefaultPolicyParser
	// log is the logger instance
	log *log.Logger
	// fwAPI is the firewall API
	fwAPI *k8sfirewall.FirewallApiService
	// node is the node in which we are running
	node *core_v1.Node
	// nodeName is the name of the node in which we are running
	nodeName string
	// lock is the main lock used in the manager
	lock sync.Mutex
	//	localFirewalls is a map of the firewall managers inside this node.
	localFirewalls map[string]pcn_firewall.PcnFirewall
	//	unscheduleThreshold is the number of MINUTES after which a firewall manager should be deleted if no pods are assigned to it.
	unscheduleThreshold int
	//	flaggedForDeletion contains ids of firewall managers that are scheduled to be deleted.
	//	Firewall managers will continue updating rules and parse policies even when they have no pods assigned to them anymore (they just won't inject rules anywhere).
	//  But if this situation persists for at least unscheduleThreshold minutes, then they are going to be deleted.
	flaggedForDeletion map[string]*time.Timer
	// linkedPods is a map linking local pods to local firewalls.
	// It is used to check if a pod has changed and needs to be unlinked. It is a very rare situation, but... you know...
	linkedPods map[k8s_types.UID]string
}

// startFirewall is a pointer to the StartFirewall method of the pcn_firewall package.
// It is both used as a shortcut and for testing purposes (see network_policy_manager_test.go)
var startFirewall = pcn_firewall.StartFirewall

// StartNetworkPolicyManager will start a new network policy manager. This is supposed to be a singleton.
func StartNetworkPolicyManager(basePath string, dnpc *pcn_controllers.DefaultNetworkPolicyController, podController pcn_controllers.PodController, node *core_v1.Node) PcnNetworkPolicyManager {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": PM, "method": "StartNetworkPolicyManager()"})
	l.Infoln("Starting Network Policy Manager")

	cfgK8firewall := k8sfirewall.Configuration{BasePath: basePath}
	srK8firewall := k8sfirewall.NewAPIClient(&cfgK8firewall)
	fwAPI := srK8firewall.FirewallApi

	nodeName := node.Name

	manager := NetworkPolicyManager{
		dnpc:                dnpc,
		podController:       podController,
		node:                node,
		nodeName:            node.Name,
		localFirewalls:      map[string]pcn_firewall.PcnFirewall{},
		unscheduleThreshold: UnscheduleThreshold,
		flaggedForDeletion:  map[string]*time.Timer{},
		linkedPods:          map[k8s_types.UID]string{},
		log:                 log.New(),
		fwAPI:               fwAPI,
	}

	//-------------------------------------
	//	Subscribe to policies events
	//-------------------------------------

	manager.defaultPolicyParser = newDefaultPolicyParser(podController)

	//	Deploy a new k8s policy
	dnpc.Subscribe(pcn_types.New, manager.DeployK8sPolicy)

	//	Remove a default policy
	dnpc.Subscribe(pcn_types.Delete, manager.RemoveK8sPolicy)

	//	Update a policy
	dnpc.Subscribe(pcn_types.Update, manager.UpdateK8sPolicy)

	//-------------------------------------
	//	Subscribe to pod events
	//-------------------------------------

	//podController.Subscribe(pcn_types.New, manager.checkNewPod)
	podController.Subscribe(pcn_types.Update, pcn_types.ObjectQuery{Node: nodeName}, pcn_types.ObjectQuery{}, pcn_types.PodRunning, manager.checkNewPod)
	podController.Subscribe(pcn_types.Delete, pcn_types.ObjectQuery{Node: nodeName}, pcn_types.ObjectQuery{}, pcn_types.PodAnyPhase, manager.manageDeletedPod)

	return &manager
}

// DeployK8sPolicy deploys a kubernetes policy in the appropriate firewall managers
func (manager *NetworkPolicyManager) DeployK8sPolicy(policy *networking_v1.NetworkPolicy) {
	l := log.NewEntry(manager.log)
	l.WithFields(log.Fields{"by": PM, "method": "DeployK8sPolicy(" + policy.Name + ")"})

	manager.lock.Lock()
	defer manager.lock.Unlock()

	if len(manager.localFirewalls) < 1 {
		l.Infoln("There are no active firewall managers in this node. Will stop here.")
		return
	}

	//-------------------------------------
	//	Parse, Deploy & Set Actions
	//-------------------------------------
	var waiter sync.WaitGroup
	waiter.Add(len(manager.localFirewalls))

	//	We are going to loop through all firewall managers, not pods: this way we can further reduce iterations.
	//	Example: 50 similar pods are all managed by the same firewall manager => this is done only once, not 50 times!
	//	Each firewall manager will deploy this policy in its own go routine: no need to do this sequentially.
	for _, fwManager := range manager.localFirewalls {
		go func(fw pcn_firewall.PcnFirewall) {
			defer waiter.Done()
			labels, ns := fw.Selector()

			//	Create a fake pod, so that we can see if this firewall manager should enforce this new policy
			pod := core_v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{
					Namespace: ns,
					Labels:    labels,
				},
			}
			if manager.defaultPolicyParser.DoesPolicyAffectPod(policy, &pod) {
				manager.deployK8sPolicyToFw(policy, fw)
			}
		}(fwManager)
	}

	//	I thought this was useless, but in reality it is very useful! We have to release the lock only if all of them deployed the policy!
	//	Otherwise we would have inconsistencies in rules (and of course race conditions) if the same policy/other policies is/are deployed.
	waiter.Wait()
}

// RemoveK8sPolicy removes (ceases) a kubernetes policy from the appropriate firewall managers
func (manager *NetworkPolicyManager) RemoveK8sPolicy(policy *networking_v1.NetworkPolicy) {
	l := log.NewEntry(manager.log)
	l.WithFields(log.Fields{"by": PM, "method": "RemoveK8sPolicy(" + policy.Name + ")"})

	manager.lock.Lock()
	defer manager.lock.Unlock()

	if len(manager.localFirewalls) < 1 {
		l.Infoln("There are no active firewall managers in this node. Will stop here.")
		return
	}

	//-------------------------------------
	//	Cease this policy
	//-------------------------------------

	var waiter sync.WaitGroup
	waiter.Add(len(manager.localFirewalls))

	//	Loop through all firewall managers and make them cease this policy if they were enforcing it.
	for _, fwManager := range manager.localFirewalls {
		go func(fw pcn_firewall.PcnFirewall) {
			defer waiter.Done()
			if fw.IsPolicyEnforced(policy.Name) {
				fw.CeasePolicy(policy.Name)
			}
		}(fwManager)
	}

	//	Read above in DeployK8sPolicy
	waiter.Wait()
}

// UpdateK8sPolicy updates a kubernetes policy in the appropriate firewall managers
func (manager *NetworkPolicyManager) UpdateK8sPolicy(policy *networking_v1.NetworkPolicy) {
	l := log.NewEntry(manager.log)
	l.WithFields(log.Fields{"by": PM, "method": "UpdateK8sPolicy(" + policy.Name + ")"})

	//	Updating a policy is no trivial task.
	//	We don't know what changed from its previous state: we are forced to re-parse it to know it.
	//	Instead of parsing and checking what's changed and what's stayed, we're going to remove the policy and
	//	redeploy it.

	manager.lock.Lock()
	defer manager.lock.Unlock()

	if len(manager.localFirewalls) < 1 {
		l.Infoln("There are no active firewall managers in this node. Will stop here.")
		return
	}

	//-------------------------------------
	//	Remove and redeploy
	//-------------------------------------
	var waiter sync.WaitGroup
	waiter.Add(len(manager.localFirewalls))

	for _, fwManager := range manager.localFirewalls {
		go func(fw pcn_firewall.PcnFirewall) {
			defer waiter.Done()

			if fw.IsPolicyEnforced(policy.Name) {
				fw.CeasePolicy(policy.Name)
				manager.deployK8sPolicyToFw(policy, fw)
			}
		}(fwManager)
	}

	waiter.Wait()
}

// deployK8sPolicyToFw actually deploys the provided kubernetes policy to the provided fw manager.
func (manager *NetworkPolicyManager) deployK8sPolicyToFw(policy *networking_v1.NetworkPolicy, fw pcn_firewall.PcnFirewall) {
	//	Get the spec, with the ingress & egress rules
	spec := policy.Spec
	ingress, egress, policyType := manager.defaultPolicyParser.ParsePolicyTypes(&spec)

	var parsed pcn_types.ParsedRules
	fwActions := []pcn_types.FirewallAction{}

	var podsWaitGroup sync.WaitGroup
	podsWaitGroup.Add(1)

	//	Get the rules
	go func() {
		defer podsWaitGroup.Done()
		parsed = manager.defaultPolicyParser.ParseRules(ingress, egress, policy.Namespace)
	}()

	podsWaitGroup.Wait()

	//	Firewall is transparent: we need to reverse the directions
	opposedPolicyType := policyType
	if opposedPolicyType != "*" {
		if policyType == "ingress" {
			opposedPolicyType = "egress"
		} else {
			opposedPolicyType = "ingress"
		}
	}

	//	Actually enforce the policy
	fw.EnforcePolicy(policy.Name, opposedPolicyType, policy.CreationTimestamp, parsed.Ingress, parsed.Egress, fwActions)
}

// implode creates a key in the format of namespace_name|key1=value1;key2=value2;.
// This is used to recognize if two pods must share the same rules or must be considered separately.
func (manager *NetworkPolicyManager) implode(labels map[string]string, ns string) string {
	//	The first part of the key is the namespace name and the | separator
	key := ns + "|"

	//	Now we create an array of imploded labels (e.g.: [app=mysql version=2.5 beta=no])
	implodedLabels := []string{}
	for k, v := range labels {
		implodedLabels = append(implodedLabels, k+"="+v)
	}

	//	Now we sort the labels. Why do we sort them? Because maps in go do not preserve an alphabetical order.
	//	As per documentation, order is not fixed. Two pods may have the exact same labels, but the iteration order in them may differ.
	//	So, by sorting them alphabetically we're making them equal.
	sort.Strings(implodedLabels)

	//	Join the key and the labels
	return key + strings.Join(implodedLabels, ",")
}

// checkNewPod will perform some checks on the new pod just updated.
// Specifically, it will check if the pod needs to be protected.
func (manager *NetworkPolicyManager) checkNewPod(pod *core_v1.Pod) {
	l := log.NewEntry(manager.log)
	l.WithFields(log.Fields{"by": PM, "method": "checkNewPod(" + pod.Name + ")"})

	//-------------------------------------
	//	Basic Checks
	//-------------------------------------

	//	Is this pod from the kube-system?
	if pod.Namespace == "kube-system" {
		l.Infoln("Pod", pod.Name, "belongs to the kube-system namespace: no point in checking for policies. Will stop here.")
		return
	}

	//	Get or create the firewall manager for this pod and then link it.
	//	Doing it a lambda so we can use defer, and we can block the thread for as short time as possible
	linkPod := func() (bool, pcn_firewall.PcnFirewall) {
		manager.lock.Lock()
		defer manager.lock.Unlock()

		fw, justCreated := manager.getOrCreateFirewallManager(pod)

		//	Link returns false when the pod was not linked because it was already linked,
		// 	or if the pod's firewall was not ok.
		inserted := fw.Link(pod)

		if inserted {
			manager.linkedPods[pod.UID] = fw.Name()
			manager.unflagForDeletion(fw.Name())
		}

		// If the firewall manager already existed there is no point in going on: policies are already there.
		// But if it was just created we need to parse rules even if the pod was not linked correctly,
		// because it is very probable that the pod will be deployed again, so when it happens it'll have rules ready.
		// This will also prevent us from depleting resources if the pod is unstable: this will be done just once.
		return justCreated, fw
	}

	shouldInit, fw := linkPod()
	if !shouldInit {
		//	Firewall is already inited. You can stop here.
		return
	}

	//	Commenting this because it's highly improbable of race conditions here: we just created a new firewall and no one is going to
	//	destroy it this moment. The only thing that might happen is if someone deletes a policy while we are deploying it, but should be rare.
	//	I might be overthinking here... so, for now, we disable this.
	/*manager.lock.Lock()
	defer manager.lock.Unlock()*/

	//-------------------------------------
	//	Must this pod enforce any policy?
	//-------------------------------------
	k8sPolicies, _ := manager.dnpc.GetPolicies(pcn_types.ObjectQuery{By: "name", Name: "*"}, pod.Namespace)
	for _, kp := range k8sPolicies {
		if manager.defaultPolicyParser.DoesPolicyAffectPod(&kp, pod) {
			manager.deployK8sPolicyToFw(&kp, fw)
		}
	}

	// Do the same for polycube policies
}

// getOrCreateFirewallManager gets a local firewall manager for this pod or creates one if not there.
// Returns the newly created/already existing firewall manager, its key, and TRUE if it was just created.
func (manager *NetworkPolicyManager) getOrCreateFirewallManager(pod *core_v1.Pod) (pcn_firewall.PcnFirewall, bool) {
	l := log.NewEntry(manager.log)
	l.WithFields(log.Fields{"by": PM, "method": "getOrCreateFirewallManager(" + pod.Name + ")"})

	fwKey := manager.implode(pod.Labels, pod.Namespace)

	//-------------------------------------
	//	Already linked?
	//-------------------------------------
	linkedFw, wasLinked := manager.linkedPods[pod.UID]
	if wasLinked && linkedFw != fwKey {
		//	This pod was already linked to a firewall manager, but it's not the one we expected.
		// 	This means that someone (user or plugin) changed this pod's labels, so we now need to unlink the pod from its current fw manager.
		prevFw, exists := manager.localFirewalls[linkedFw]
		if exists {
			unlinked, remaining := prevFw.Unlink(pod, pcn_firewall.CleanFirewall)
			if !unlinked {
				l.Warningln("Pod's was not linked in previous firewall manager!")
			} else {
				if remaining == 0 {
					manager.flagForDeletion(prevFw.Name())
				}
				delete(manager.linkedPods, pod.UID)
			}
		} else {
			l.Warningln("Could not find pod's previous firewall manager!")
		}
	}

	//-------------------------------------
	//	Create and link it
	//-------------------------------------
	fw, exists := manager.localFirewalls[fwKey]
	if !exists {
		manager.localFirewalls[fwKey] = startFirewall(manager.fwAPI, manager.podController, fwKey, pod.Namespace, pod.Labels, manager.node)
		fw = manager.localFirewalls[fwKey]
		return fw, true
	}
	return fw, false
}

// flagForDeletion flags a firewall for deletion
func (manager *NetworkPolicyManager) flagForDeletion(fwKey string) {
	_, wasFlagged := manager.flaggedForDeletion[fwKey]

	//	Was it flagged?
	if !wasFlagged {
		manager.flaggedForDeletion[fwKey] = time.AfterFunc(time.Minute*time.Duration(manager.unscheduleThreshold), func() {
			manager.deleteFirewallManager(fwKey)
		})
	}
}

// unflagForDeletion unflags a firewall manager for deletion
func (manager *NetworkPolicyManager) unflagForDeletion(fwKey string) {
	timer, wasFlagged := manager.flaggedForDeletion[fwKey]

	//	Was it flagged?
	if wasFlagged {
		timer.Stop() // you're going to survive! Be happy!
		delete(manager.flaggedForDeletion, fwKey)
	}
}

// manageDeletedPod makes sure that the appropriate firewall manager will destroy this pod's firewall
func (manager *NetworkPolicyManager) manageDeletedPod(pod *core_v1.Pod) {
	l := log.NewEntry(manager.log)
	l.WithFields(log.Fields{"by": PM, "method": "manageDeletedPod(" + pod.Name + ")"})

	if pod.Namespace == "kube-system" {
		l.Infoln("Pod", pod.Name, "belongs to the kube-system namespace: no point in checking its firewall manager. Will stop here.")
		return
	}

	fwKey := manager.implode(pod.Labels, pod.Namespace)
	defer delete(manager.linkedPods, pod.UID)

	manager.lock.Lock()
	defer manager.lock.Unlock()

	//	First get the firewall
	fw, exists := manager.localFirewalls[fwKey]
	if !exists {
		//	The firewall manager for this pod does not exist. Then who managed it until now? This is a very improbable case.
		l.Warningln("Could not find a firewall manager for dying pod", pod.UID, "!")
		return
	}

	wasLinked, remaining := fw.Unlink(pod, pcn_firewall.DestroyFirewall)
	if !wasLinked {
		//	This pod wasn't even linked to the firewall!
		l.Warningln("Dying pod", pod.UID, "was not linked to its firewall manager", fwKey)
		return
	}

	if remaining == 0 {
		manager.flagForDeletion(fwKey)
	}
}

// deleteFirewallManager will delete a firewall manager.
// Usually this function is called automatically when after a certain threshold.
func (manager *NetworkPolicyManager) deleteFirewallManager(fwKey string) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	//	The garbage collector will take care of destroying everything inside it now that no one points to it anymore.
	//	Goodbye!
	manager.localFirewalls[fwKey].Destroy()
	delete(manager.localFirewalls, fwKey)
	delete(manager.flaggedForDeletion, fwKey)
}
