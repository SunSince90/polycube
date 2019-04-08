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
	k8s_types "k8s.io/apimachinery/pkg/types"
)

type PcnNetworkPolicyManager interface {
}

type NetworkPolicyManager struct {
	dnpc          *pcn_controllers.DefaultNetworkPolicyController
	podController pcn_controllers.PodController

	defaultPolicyParser PcnDefaultPolicyParser
	deployedPolicies    map[string][]k8s_types.UID
	checkedPods         map[k8s_types.UID]*checkedPod

	//	TODO: remove this
	checkPodsLock sync.Mutex
	log           *log.Logger

	// node is the name of the node in which we are running
	node string
	// lock is the main lock used in the manager
	lock sync.Mutex
	//	localFirewalls is a map of the firewall managers inside this node.
	localFirewalls map[string]pcn_firewall.PcnFirewall
	//	unscheduleThreshold is the number of HOURS after which a firewall manager should be deleted if no pods are assigned to it.
	unscheduleThreshold int
	//	flaggedForDeletion contains ids of firewall managers to delete.
	//	If a pod is not scheduled for this node for more than X hours, than its firewall manager will be deleted as well.
	flaggedForDeletion map[string]*time.Timer
	fwAPI              k8sfirewall.FirewallAPI
}

type checkedPod struct {
	lastKnownIP string
	sync.Mutex
}

func StartNetworkPolicyManager(basePath string, dnpc *pcn_controllers.DefaultNetworkPolicyController, podController pcn_controllers.PodController, nodeName string) PcnNetworkPolicyManager {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": PM, "method": "StartNetworkPolicyManager()"})
	l.Infoln("Starting Network Policy Manager")

	cfgK8firewall := k8sfirewall.Configuration{BasePath: basePath}
	srK8firewall := k8sfirewall.NewAPIClient(&cfgK8firewall)
	fwAPI := srK8firewall.FirewallApi

	manager := NetworkPolicyManager{
		dnpc:                dnpc,
		podController:       podController,
		deployedPolicies:    map[string][]k8s_types.UID{},
		checkedPods:         map[k8s_types.UID]*checkedPod{},
		node:                nodeName,
		localFirewalls:      map[string]pcn_firewall.PcnFirewall{},
		unscheduleThreshold: UnscheduleThreshold,
		flaggedForDeletion:  map[string]*time.Timer{},

		log:   log.New(),
		fwAPI: fwAPI,
	}

	//-------------------------------------
	//	Subscribe to default policies events
	//-------------------------------------

	manager.defaultPolicyParser = newDefaultPolicyParser(podController, nodeName)

	//	Deploy a new default policy
	dnpc.Subscribe(pcn_types.New, manager.DeployDefaultPolicy)

	//	Remove a default policy
	dnpc.Subscribe(pcn_types.Delete, manager.RemoveDefaultPolicy)

	//	Update a policy
	dnpc.Subscribe(pcn_types.Update, manager.UpdateDefaultPolicy)

	//-------------------------------------
	//	Subscribe to pod events
	//-------------------------------------

	//podController.Subscribe(pcn_types.New, manager.checkNewPod)
	podController.Subscribe(pcn_types.Update, pcn_types.ObjectQuery{Node: nodeName}, pcn_types.ObjectQuery{}, pcn_types.PodRunning, manager.checkNewPod)
	podController.Subscribe(pcn_types.Delete, pcn_types.ObjectQuery{Node: nodeName}, pcn_types.ObjectQuery{}, pcn_types.PodAnyPhase, manager.manageDeletedPod)

	return &manager
}

func (manager *NetworkPolicyManager) DeployDefaultPolicy(policy *networking_v1.NetworkPolicy) {
	l := log.NewEntry(manager.log)
	l.WithFields(log.Fields{"by": PM, "method": "DeployDefaultPolicy(" + policy.Name + ")"})

	//-------------------------------------
	//	The basics
	//-------------------------------------
	nsPods, err := manager.defaultPolicyParser.GetPodsAffected(policy)
	if err != nil {
		l.Errorln("Error while trying to get pods affected by policy.", err)
		return
	}

	//	No pods found?
	if len(nsPods) < 1 {
		l.Infoln("No pods found for policy.", err)
		return
	}

	//	Get the spec, with the ingress & egress rules
	spec := policy.Spec
	//ingress, egress, policyType := manager.defaultPolicyParser.ParsePolicyTypes(&spec)
	ingress, egress, _ := manager.defaultPolicyParser.ParsePolicyTypes(&spec)

	//-------------------------------------
	//	Parse, Deploy & Set Actions
	//-------------------------------------
	for ns, pods := range nsPods {

		var parsed pcn_types.ParsedRules
		fwActions := pcn_types.FirewallActions{}

		var podsWaitGroup sync.WaitGroup
		podsWaitGroup.Add(2)

		//	Parse...
		go func() {
			defer podsWaitGroup.Done()
			parsed = manager.defaultPolicyParser.ParseRules(ingress, egress, ns)
		}()

		go func() {
			defer podsWaitGroup.Done()
			fwActions = manager.defaultPolicyParser.BuildActions(ingress, egress, ns)
		}()

		if len(parsed.Ingress) > 0 && len(fwActions.Ingress) > 0 {
			//	Just to shut it up temporarily
		}
		podsWaitGroup.Wait()

		//	Reusing the waitgroup...
		podsWaitGroup.Add(len(pods))
		for _, pod := range pods {

			//	Deploy...
			go func(currentPod core_v1.Pod) {
				defer podsWaitGroup.Done()

				//	If this pod is not ready or is terminating, then don't proceed
				if currentPod.Status.Phase != core_v1.PodRunning || currentPod.DeletionTimestamp != nil {
					return
				}

				//	Deploy...
				//	Create the firewall (or get it if already exists)
				/*fw, exists := manager.localFirewalls[pod.UID]
				if !exists {
					l.Errorln("No firewall exists for pod", pod.Status.PodIP)
					return
				}

				//-------------------------------------
				//	Inject the rules and the actions
				//-------------------------------------

				fw.EnforcePolicy(policy.Name, policyType, parsed.Ingress, parsed.Egress, fwActions)*/

			}(pod)
		}

		podsWaitGroup.Wait()
	}
}

func (manager *NetworkPolicyManager) RemoveDefaultPolicy(policy *networking_v1.NetworkPolicy) {
	//podsAffected, err := manager.defaultPolicyParser.GetPodsAffected(policy)

	/*if err != nil {
		//	err
		return
	}*/

	//	We are iterating only through pods which are here in this node.
	/*for _, pods := range podsAffected {
		for _, pod := range pods {
			fw, exists := manager.localFirewalls[pod.UID]
			if exists && fw.IsPolicyEnforced(policy.Name) {
				fw.CeasePolicy(policy.Name)
			}
		}
	}*/
}

func (manager *NetworkPolicyManager) UpdateDefaultPolicy(policy *networking_v1.NetworkPolicy) {

	manager.RemoveDefaultPolicy(policy)
	manager.DeployDefaultPolicy(policy)
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
	return key + strings.Join(implodedLabels, ";")
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

	//	Did I already create a firewall for this?
	fw, existed := manager.getOrCreateFirewallManager(pod)

	if existed {
		//	The pod is already linked to the firewall: no point to go on.
		return
	}

	//-------------------------------------
	//	Must this pod enforce any policy?
	//-------------------------------------

	k8sPolicies, _ := manager.dnpc.GetPolicies(pcn_types.ObjectQuery{By: "name", Name: "*"}, pod.Namespace)

	//	TODO: in a thread for each of them?
	for _, kp := range k8sPolicies {
		if manager.defaultPolicyParser.DoesPolicyAffectPod(&kp, pod) && !fw.IsPolicyEnforced(kp.Name) {

			var parsed pcn_types.ParsedRules
			fwActions := pcn_types.FirewallActions{}
			ingress, egress, policyType := manager.defaultPolicyParser.ParsePolicyTypes(&kp.Spec)

			var podsWaitGroup sync.WaitGroup
			podsWaitGroup.Add(2)

			//	Parse...
			go func() {
				defer podsWaitGroup.Done()
				parsed = manager.defaultPolicyParser.ParseRules(ingress, egress, pod.Namespace)
			}()

			go func() {
				defer podsWaitGroup.Done()
				fwActions = manager.defaultPolicyParser.BuildActions(ingress, egress, pod.Namespace)
			}()

			podsWaitGroup.Wait()
			fw.EnforcePolicy(kp.Name, policyType, parsed.Ingress, parsed.Egress, fwActions)
		}
	}

	//	Have I already checked this before?
	/*manager.lock.Lock()
	checked, ok := manager.checkedPods[pod.UID]
	if !ok {
		checked = &checkedPod{}
		manager.checkedPods[pod.UID] = checked
	}
	manager.lock.Unlock()*/

	/*checked.Lock()
	defer checked.Unlock()*/

	//	Already checked before?
	/*if checked.lastKnownIP == pod.Status.PodIP {
		//l.Debugln("pod", pod.Name, "has already been checked before: no point in checking it again. Will stop here.")
		return
	}*/

	//l.Debugln("Ok,", pod.Name, "Has never been checked.")

	var policyWait sync.WaitGroup
	policyWait.Add(2)
	//policyWait.Add(2)
	//k8sPolicies, _ := manager.dnpc.GetPolicies(pcn_types.ObjectQuery{By: "name", Name: "*"})
	//	The most recently deployed policies should have precedence, but the firewall doesn't support haed insertion yet.
	//sort.Slice(k8sPolicies, func(i, j int) bool {return k8sPolicies[i].ObjectMeta.CreationTimestamp < k8sPolicies[j].ObjectMeta.CreationTimestamp})

	/*	This is going to be a bit tricky, so here is a brief explanation.
		1) We must see if there are policies that must be applied to this pod.
		2) We must see if there are policies which target this pod: there may be some pods which can accept connections from this new pod,
			but since it is new, they don't have this pod in their rules list.
	*/

	//-------------------------------------
	//	Check if needs policies applied
	//-------------------------------------
	go func(policiesList []networking_v1.NetworkPolicy) {
		defer policyWait.Done()
		/*if pod.Spec.NodeName != manager.node {
			//l.Infoln("pod", pod.Name, "is not in my node: no point in injecting rules. Will stop here.")
			return
		}*/

		//	First start the firewall
		/*fw := manager.firewallManager.GetOrCreate(*pod)
		if fw == nil {
			l.Errorln("Could not get firewall for pod", pod.Name, ": I won't be able to inject rules. Will stop here.")
			return
		}*/

		/*for _, k8sPolicy := range policiesList {
			//	Make sure it doesn't already enforce this policy
			if !fw.IsPolicyEnforced(k8sPolicy.Name) {
				if manager.defaultPolicyParser.DoesPolicyAffectPod(&k8sPolicy, pod) {
					//	Deploy the policy just for this pod
					ingress, egress, policyType := manager.defaultPolicyParser.ParsePolicyTypes(&k8sPolicy.Spec)
					parsed := manager.defaultPolicyParser.ParseRules(ingress, egress, pod.Namespace)

					fw.EnforcePolicy(k8sPolicy.Name, policyType, parsed.Ingress, parsed.Egress, pcn_types.FirewallActions{})
				}
			}
		}*/
	}(k8sPolicies)

	//-------------------------------------
	//	Check if a policy targets it
	//-------------------------------------
	go func(policiesList []networking_v1.NetworkPolicy) {
		defer policyWait.Done()

		/*for _, currentPolicy := range policiesList {
			doesIt := manager.defaultPolicyParser.DoesPolicyTargetPod(&currentPolicy, pod)

			if len(doesIt.Ingress) > 0 || len(doesIt.Egress) > 0 {
				for _, currentFw := range manager.firewallManager.GetAll() {
					if currentFw.ForPod() != pod.UID {
						if currentFw.IsPolicyEnforced(currentPolicy.Name) {
							_, _, policyType := manager.defaultPolicyParser.ParsePolicyTypes(&currentPolicy.Spec)
							currentFw.EnforcePolicy(currentPolicy.Name, policyType, doesIt.Ingress, doesIt.Egress)
						}
					}
				}
			}
		}*/

	}(k8sPolicies)

	policyWait.Wait()

	//checked.lastKnownIP = pod.Status.PodIP
	return
}

// getOrCreateFirewallManager gets a local firewall manager for this pod or creates one if not there.
// Returns the newly created/already existing firewall manager and TRUE if this pod was already linked.
func (manager *NetworkPolicyManager) getOrCreateFirewallManager(pod *core_v1.Pod) (pcn_firewall.PcnFirewall, bool) {
	fwKey := manager.implode(pod.Labels, pod.Namespace)
	manager.lock.Lock()
	defer manager.lock.Unlock()

	//	First get the firewall
	_fw, exists := manager.localFirewalls[fwKey]
	if !exists {
		manager.localFirewalls[fwKey] = pcn_firewall.StartFirewall(manager.fwAPI, manager.podController, fwKey)
	}

	if _fw == nil {
		log.Infoln("fw is nil")
	}
	//	If Link returns false it means that the pod was not linked because it was already linked.
	inserted := _fw.Link(pod.UID, pod.Status.PodIP)

	//	So, if it was actually inserted, than we can unflag this firewall for deletion (if it ever was)
	if inserted {
		if timer, wasFlagged := manager.flaggedForDeletion[fwKey]; wasFlagged {
			timer.Stop() // you're going to survive! Be happy!
			delete(manager.flaggedForDeletion, fwKey)
		}
	}

	return _fw, !inserted
}

// manageDeletedPod makes sure that the appropriate firewall manager will destroy this pod's firewall
func (manager *NetworkPolicyManager) manageDeletedPod(pod *core_v1.Pod) {
	l := log.NewEntry(manager.log)
	l.WithFields(log.Fields{"by": PM, "method": "manageDeletePod(" + pod.Name + ")"})

	if pod.Namespace == "kube-system" {
		l.Infoln("Pod", pod.Name, "belongs to the kube-system namespaces: no point in checking its firewall manager. Will stop here.")
		return
	}

	fwKey := manager.implode(pod.Labels, pod.Namespace)

	//	Does the firewall manager exist for this pod?
	//	This is actually useless, but who knows...
	//	Let's do it in a lambda, so we can use defer
	checkExists := func() (pcn_firewall.PcnFirewall, bool) {
		fwKey := manager.implode(pod.Labels, pod.Namespace)
		manager.lock.Lock()
		defer manager.lock.Unlock()

		//	First get the firewall
		fw, exists := manager.localFirewalls[fwKey]
		return fw, exists
	}

	fw, exists := checkExists()
	if !exists {
		//	The firewall manager for this pod does not exist. Then who managed it until now?? This is a very improbable case.
		l.Warningln("Could not find a firewall manager for dying pod", pod.UID, "!")
		return
	}

	existed, remaining := fw.Unlink(pod.UID, true)
	if !existed {
		//	This pod wasn't even linked to the firewall!
		l.Warningln("Dying pod", pod.UID, "was not linked to its firewall manager", fwKey)
		return
	}

	if remaining == 0 {
		//	This firewall manager is not monitoring anyone anymore. Let's flag it for deletion.
		manager.flaggedForDeletion[fwKey] = time.AfterFunc(time.Hour*time.Duration(manager.unscheduleThreshold), func() {
			manager.deleteFirewallManager(fwKey)
		})
	}
}

// deleteFirewallManager will delete a firewall manager.
// Usually this function is called automatically when after a certain threshold.
func (manager *NetworkPolicyManager) deleteFirewallManager(fwKey string) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	//	The garbage collector will take care of destroying everything inside it now that no one points to it anymore.
	//	Goodbye!
	delete(manager.localFirewalls, fwKey)
}
