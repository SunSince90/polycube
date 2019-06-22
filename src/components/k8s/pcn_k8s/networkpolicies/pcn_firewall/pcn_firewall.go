package pcnfirewall

import (
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
}

// FirewallManager is the implementation of the firewall manager.
type FirewallManager struct {
	// podController is the pod controller
	podController pcn_controllers.PodController
	// fwAPI is the low level firewall api
	fwAPI *k8sfirewall.FirewallApiService
	// linkedPods is a map of pods monitored by this firewall manager
	linkedPods map[k8s_types.UID]string
	// Name is the name of this firewall manager
	name string
	// log is a new entry in logger
	log *log.Logger
	// lock is firewall manager's main lock
	lock sync.Mutex
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
		node: node,
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
