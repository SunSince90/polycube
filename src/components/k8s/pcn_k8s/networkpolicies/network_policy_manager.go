package networkpolicies

import (
	"sort"
	"strings"
	"sync"

	//	TODO-ON-MERGE: change these to the polycube path
	pcn_controllers "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/controllers"
	pcn_firewall "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/networkpolicies/pcn_firewall"
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"

	log "github.com/sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"
)

// PcnNetworkPolicyManager is a network policy manager
type PcnNetworkPolicyManager interface {
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
		dnpc:           dnpc,
		podController:  podController,
		node:           node,
		nodeName:       node.Name,
		localFirewalls: map[string]pcn_firewall.PcnFirewall{},
		linkedPods:     map[k8s_types.UID]string{},
		log:            log.New(),
		fwAPI:          fwAPI,
	}

	//-------------------------------------
	//	Subscribe to pod events
	//-------------------------------------

	//podController.Subscribe(pcn_types.New, manager.checkNewPod)
	podController.Subscribe(pcn_types.Update, pcn_types.ObjectQuery{Node: nodeName}, pcn_types.ObjectQuery{}, pcn_types.PodRunning, manager.checkNewPod)
	podController.Subscribe(pcn_types.Delete, pcn_types.ObjectQuery{Node: nodeName}, pcn_types.ObjectQuery{}, pcn_types.PodAnyPhase, manager.manageDeletedPod)

	return &manager
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
		}

		// If the firewall manager already existed there is no point in going on: policies are already there.
		// But if it was just created we need to parse rules even if the pod was not linked correctly,
		// because it is very probable that the pod will be deployed again, so when it happens it'll have rules ready.
		// This will also prevent us from depleting resources if the pod is unstable: this will be done just once.
		return justCreated, fw
	}

	shouldInit, _ := linkPod()
	if !shouldInit {
		//	Firewall is already inited. You can stop here.
		return
	}
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
			unlinked, _ := prevFw.Unlink(pod, pcn_firewall.CleanFirewall)
			if !unlinked {
				l.Warningln("Pod's was not linked in previous firewall manager!")
			} else {
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

	wasLinked, _ := fw.Unlink(pod, pcn_firewall.DestroyFirewall)
	if !wasLinked {
		//	This pod wasn't even linked to the firewall!
		l.Warningln("Dying pod", pod.UID, "was not linked to its firewall manager", fwKey)
		return
	}
}
