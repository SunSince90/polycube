package controllers

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	//	TODO-ON-MERGE: change the path to polycube
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"

	log "github.com/sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	typed_core_v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	workqueue "k8s.io/client-go/util/workqueue"
)

// PodController is the interface of the pod controller
type PodController interface {
	Run()
	Stop()
	Subscribe(pcn_types.EventType, pcn_types.ObjectQuery, pcn_types.ObjectQuery, core_v1.PodPhase, func(*core_v1.Pod)) (func(), error)
	GetPods(pcn_types.ObjectQuery, pcn_types.ObjectQuery) ([]core_v1.Pod, error)
}

// PcnPodController is the implementation of the pod controller
type PcnPodController struct {
	nsController NamespaceController
	clientset    kubernetes.Interface
	queue        workqueue.RateLimitingInterface
	informer     cache.SharedIndexInformer
	startedOn    time.Time
	dispatchers  EventDispatchersContainer
	stopCh       chan struct{}
	maxRetries   int
	logBy        string
	pods         map[string]*pcn_types.Pod
	lock         sync.Mutex
	nsInterface  typed_core_v1.NamespaceInterface
}

// NewPodController will start a new pod controller
func NewPodController(clientset kubernetes.Interface, nsController NamespaceController) PodController {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": "Pod Controller", "method": "NewPodController()"})

	logBy := "PodController"
	maxRetries := 5

	//------------------------------------------------
	//	Set up the Pod Controller
	//------------------------------------------------

	informer := cache.NewSharedIndexInformer(&cache.ListWatch{
		ListFunc: func(options meta_v1.ListOptions) (runtime.Object, error) {
			return clientset.CoreV1().Pods(meta_v1.NamespaceAll).List(options)
		},
		WatchFunc: func(options meta_v1.ListOptions) (watch.Interface, error) {
			return clientset.CoreV1().Pods(meta_v1.NamespaceAll).Watch(options)
		},
	},
		&core_v1.Pod{},
		0, //Skip resync
		cache.Indexers{},
	)

	//------------------------------------------------
	//	Set up the queue
	//------------------------------------------------

	//	Start the queue
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	//------------------------------------------------
	//	Set up the event handlers
	//------------------------------------------------

	//	Whenever something happens to network policies, the event is routed by this event handler and routed to the queue. It'll know what to do.
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			event, err := buildEvent(obj, pcn_types.New)
			if err != nil {
				utilruntime.HandleError(err)
				return
			}
			queue.Add(event)
		},
		UpdateFunc: func(old, new interface{}) {
			event, err := buildEvent(new, pcn_types.Update)
			if err != nil {
				utilruntime.HandleError(err)
				return
			}

			queue.Add(event)
		},
		DeleteFunc: func(obj interface{}) {
			event, err := buildEvent(obj, pcn_types.Delete)
			if err != nil {
				utilruntime.HandleError(err)
				return
			}

			queue.Add(event)
		},
	})

	//------------------------------------------------
	//	Set up the dispatchers
	//------------------------------------------------

	dispatchers := EventDispatchersContainer{
		new:    NewEventDispatcher("new-pod-event-dispatcher"),
		update: NewEventDispatcher("update-pod-event-dispatcher"),
		delete: NewEventDispatcher("delete-pod-event-dispatcher"),
	}

	//	If namespace controller is nil, we're going to use it like this.
	var nsInterface typed_core_v1.NamespaceInterface
	if nsController == nil {
		l.Infoln("No namespace controller provided. Going to use a light implementation.")
		nsInterface = clientset.CoreV1().Namespaces()
	}

	//	Everything set up, return the controller
	return &PcnPodController{
		nsController: nsController,
		clientset:    clientset,
		queue:        queue,
		informer:     informer,
		dispatchers:  dispatchers,
		logBy:        logBy,
		maxRetries:   maxRetries,
		stopCh:       make(chan struct{}),
		pods:         map[string]*pcn_types.Pod{},
		nsInterface:  nsInterface,
	}
}

// Run starts the pod controller
func (p *PcnPodController) Run() {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": p.logBy, "method": "Run()"})

	//	Don't let panics crash the process
	defer utilruntime.HandleCrash()

	//	Record when we started, it is going to be used later
	p.startedOn = time.Now().UTC()

	//	Let's go!
	go p.informer.Run(p.stopCh)

	//	Make sure the cache is populated
	if !cache.WaitForCacheSync(p.stopCh, p.informer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}

	l.Infoln("Started...")

	//	Work *until* something bad happens. If that's the case, wait one second and then re-work again.
	//	Well, except when someone tells us to stop... in that case, just stop, man
	wait.Until(p.work, time.Second, p.stopCh)
}

// work gets the item from the queue and attempts to process it
func (p *PcnPodController) work() {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": p.logBy, "method": "work()"})
	stop := false

	for !stop {

		//	Get the item's key from the queue
		_event, quit := p.queue.Get()

		if quit {
			l.Infoln("Quit requested... worker going to exit.")
			return
		}

		event, ok := _event.(pcn_types.Event)
		if ok {
			err := p.process(event)

			//	No errors?
			if err == nil {
				//	Then reset the ratelimit counters
				p.queue.Forget(_event)
			} else if p.queue.NumRequeues(_event) < p.maxRetries {
				//	Tried less than the maximum retries?
				l.Warningf("Error processing item with key %s (will retry): %v", event.Key, err)
				p.queue.AddRateLimited(_event)
			} else {
				//	Too many retries?
				l.Errorf("Error processing %s (giving up): %v", event.Key, err)
				p.queue.Forget(_event)
				utilruntime.HandleError(err)
			}
		} else {
			//	Don't process something which is not valid.
			p.queue.Forget(_event)
			utilruntime.HandleError(fmt.Errorf("Error when trying to parse event %#v from the queue", _event))
		}

		stop = quit
	}
}

// process will process the event and dispatch the pod
func (p *PcnPodController) process(event pcn_types.Event) error {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": p.logBy, "method": "process()"})

	var pod *core_v1.Pod
	defer p.queue.Done(event)

	//	Get the pod by querying the key that kubernetes has assigned to this in its cache
	_pod, _, err := p.informer.GetIndexer().GetByKey(event.Key)

	//	Errors?
	if err != nil {
		l.Errorf("An error occurred: cannot find cache element with key %s from store %v", event.Key, err)
		return fmt.Errorf("An error occurred: cannot find cache element with key %s from ", event.Key)
	}

	//	Does not exist?
	/*if !exists {
		//l.Infof("Object with key %s does not exist. Going to trigger a onDelete function", event.Key)
		splitted := strings.Split(event.Key, "/")
		tempPod, ok := p.pods[splitted[1]]
		if ok {
			pod = tempPod.Pod
		}
	}*/

	//	Get the pod
	/*if _pod != nil {
		pod = _pod.(*core_v1.Pod)
	}*/

	//	Get the pod or try to recover it.
	pod, ok := _pod.(*core_v1.Pod)
	if !ok {
		tombstone, ok := _pod.(cache.DeletedFinalStateUnknown)
		if !ok {
			l.Errorln("error decoding object, invalid type")
			utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			return fmt.Errorf("error decoding object, invalid type")
		}
		pod, ok = tombstone.Obj.(*core_v1.Pod)
		if !ok {
			l.Errorln("error decoding object tombstone, invalid type")
			utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			return fmt.Errorf("error decoding object tombstone, invalid type")
		}
		l.Infof("Recovered deleted object '%s' from tombstone", pod.GetName())
	}

	//-------------------------------------
	//	Dispatch the event
	//-------------------------------------

	switch event.Type {

	case pcn_types.New:
		p.dispatchers.new.Dispatch(pod)
	case pcn_types.Update:
		p.dispatchers.update.Dispatch(pod)
	case pcn_types.Delete:
		p.dispatchers.delete.Dispatch(pod)
	}

	return nil
}

/*func (p *PcnPodController) addNewPod(pod *core_v1.Pod) {

	p.lock.Lock()
	defer p.lock.Unlock()

	podContainer := &pcn_types.Pod{
		Pod:  pod,
		Veth: "",
	}

	//	Add it in the main map
	p.pods[pod.Name] = podContainer
}*/

/*func (p *PcnPodController) removePod(pod *core_v1.Pod) {
	p.lock.Lock()
	defer p.lock.Unlock()

	_, exists := p.pods[pod.Name]
	if exists {
		delete(p.pods, pod.Name)
	}
}*/

// Stop will stop the pod controller
func (p *PcnPodController) Stop() {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": p.logBy, "method": "Stop()"})

	//	Make them know that exit has been requested
	close(p.stopCh)

	//	Shutdown the queue, making the worker unblock
	p.queue.ShutDown()

	//	Clean up the dispatchers
	p.dispatchers.new.CleanUp()
	p.dispatchers.update.CleanUp()
	p.dispatchers.delete.CleanUp()
}

// Subscribe executes the function consumer when the event event is triggered. It returns an error if the event type does not exist.
// It returns a function to call when you want to stop tracking that event.*/
func (p *PcnPodController) Subscribe(event pcn_types.EventType, podspec pcn_types.ObjectQuery, namespace pcn_types.ObjectQuery, phase core_v1.PodPhase, consumer func(*core_v1.Pod)) (func(), error) {

	//	Prepare the function to be executed
	consumerFunc := (func(item interface{}) {

		//	First, cast the item to a pod, so that the consumer will receive exactly what it wants...
		pod := item.(*core_v1.Pod)

		//	Does this pod satisfies the conditions?
		if !p.podMeetsCriteria(pod, podspec, namespace, phase) {
			return
		}

		//	Then, execute the consumer in a separate thread.
		//	NOTE: this step can also be done in the event dispatcher, but I want it to make them oblivious of the type they're handling.
		//	This way, the event dispatcher is as general as possible (also, it is not their concern to cast objects.)
		go consumer(pod)
	})

	//	What event are you subscribing to?
	switch event {

	//-------------------------------------
	//	New event
	//-------------------------------------

	case pcn_types.New:
		id := p.dispatchers.new.Add(consumerFunc)

		return func() {
			p.dispatchers.new.Remove(id)
		}, nil

	//-------------------------------------
	//	Update event
	//-------------------------------------

	case pcn_types.Update:
		id := p.dispatchers.update.Add(consumerFunc)

		return func() {
			p.dispatchers.update.Remove(id)
		}, nil

	//-------------------------------------
	//	Delete Event
	//-------------------------------------

	case pcn_types.Delete:
		id := p.dispatchers.delete.Add(consumerFunc)

		return func() {
			p.dispatchers.delete.Remove(id)
		}, nil

	//-------------------------------------
	//	Undefined event
	//-------------------------------------

	default:
		return nil, fmt.Errorf("Undefined event type")
	}
}

// podMeetsCriteria is called when before dispatching the event to verify if the pod should be dispatched or not
func (p *PcnPodController) podMeetsCriteria(pod *core_v1.Pod, podSpec pcn_types.ObjectQuery, nsSpec pcn_types.ObjectQuery, phase core_v1.PodPhase) bool {

	//	This is actually useless but who knows....
	if pod == nil {
		return false
	}

	//-------------------------------------
	//	The node
	//-------------------------------------
	if len(podSpec.Node) > 0 && pod.Spec.NodeName != podSpec.Node {
		return false
	}

	//-------------------------------------
	//	The phase
	//-------------------------------------
	if phase != pcn_types.PodAnyPhase {

		if phase != pcn_types.PodTerminating {
			//	I don't want terminating pods.

			if pod.ObjectMeta.DeletionTimestamp != nil {
				//	The pod is terminating.
				return false
			}

			if pod.Status.Phase != phase {
				//	The pod is not in the phase I want
				return false
			}
		} else {
			//	I want terminating pods

			if pod.ObjectMeta.DeletionTimestamp == nil {
				//	The pod is not terminating
				return false
			}
		}
	}

	//-------------------------------------
	//	The namespace
	//-------------------------------------
	if len(nsSpec.Name) > 0 {
		if nsSpec.Name != "*" && pod.Namespace != nsSpec.Name {
			return false
		}
	} else {
		//	Check the labels of the namespace
		if len(nsSpec.Labels) > 0 {
			// Get the list
			nsList, err := p.getNamespaces(pcn_types.ObjectQuery{
				By:     "labels",
				Labels: nsSpec.Labels,
			})
			if err != nil {
				return false
			}

			found := false
			for _, n := range nsList {
				if n.Name == pod.Namespace {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	//-------------------------------------
	//	The Pod Labels
	//-------------------------------------
	//	Check the labels: if this pod does not contain all the labels I am interested in, then stop right here.
	//	It should be very rare to see pods with more than 5 labels...
	if len(podSpec.Labels) > 0 {
		labelsFound := 0
		labelsToFind := len(podSpec.Labels)

		for neededKey, neededValue := range podSpec.Labels {
			if value, exists := pod.Labels[neededKey]; exists && value == neededValue {
				labelsFound++
				if labelsFound == labelsToFind {
					break
				}
			} else {
				//	I didn't find this key or the value wasn't the one I wanted: it's pointless to go on checking the other labels.
				break
			}
		}

		//	Did we find all labels we needed?
		if labelsFound != labelsToFind {
			return false
		}
	}

	return true
}

// GetPods gets pod according to a specific pod query and a namespace query
func (p *PcnPodController) GetPods(queryPod pcn_types.ObjectQuery, queryNs pcn_types.ObjectQuery) ([]core_v1.Pod, error) {
	//	The namespaces the pods must be found on
	//	If this remains empty it means that I don't care about the namespace they are in.
	ns := map[string]bool{}

	//------------------------------------------------
	//	Preliminary checks
	//------------------------------------------------
	//	The namespace
	if strings.ToLower(queryNs.By) == "name" && queryNs.Name != "*" {
		nsList, err := p.getNamespaces(queryNs)
		if err != nil {
			return []core_v1.Pod{}, err
		}
		if len(nsList) < 1 {
			//	If no namespace is found, it is useless to go on searching for pods
			return []core_v1.Pod{}, nil
		}
		for _, n := range nsList {
			ns[n.Name] = true
		}
	}

	//	Node specified?
	node := "*"
	if len(queryPod.Node) > 0 && queryPod.Node != "*" {
		node = queryPod.Node
	}

	//	Helper function
	getAndFilter := func(listOptions meta_v1.ListOptions) ([]core_v1.Pod, error) {
		list := []core_v1.Pod{}

		//	Do I care or not about the namespace?
		//	If not, I'll put the NamespaceAll inside the map as its only value
		if len(ns) < 1 {
			ns[meta_v1.NamespaceAll] = true
		}

		//	Loop through all interested namespaces
		for namespace := range ns {
			lister, err := p.clientset.CoreV1().Pods(namespace).List(listOptions)
			if err == nil {
				for _, currentPod := range lister.Items {
					if node == "*" || currentPod.Spec.NodeName == node {
						list = append(list, currentPod)
					}
				}
			} else {
				//return []core_v1.Pod, err
				//	Just skip this namespace.
			}
		}
		return list, nil
	}

	//-------------------------------------
	//	Find by name
	//-------------------------------------

	byName := func(name string) ([]core_v1.Pod, error) {
		if len(name) < 1 {
			return []core_v1.Pod{}, errors.New("Pod name not provided")
		}

		listOptions := meta_v1.ListOptions{}
		if name != "*" {
			listOptions.FieldSelector = "metadata.name=" + name
		}

		return getAndFilter(listOptions)
	}

	//-------------------------------------
	//	Find by labels
	//-------------------------------------

	byLabels := func(labels map[string]string) ([]core_v1.Pod, error) {
		if labels == nil {
			return []core_v1.Pod{}, errors.New("Pod labels is nil")
		}
		if len(labels) < 1 {
			//	If you need to get all pods, use get by name and name *
			return []core_v1.Pod{}, errors.New("No pod labels provided")
		}

		listOptions := meta_v1.ListOptions{
			LabelSelector: implodeLabels(labels),
		}

		return getAndFilter(listOptions)
	}

	switch strings.ToLower(queryPod.By) {
	case "name":
		return byName(queryPod.Name)
	case "labels":
		return byLabels(queryPod.Labels)
	default:
		return []core_v1.Pod{}, errors.New("Unrecognized pod query")
	}
}

// getNamespaces gets the namespaces based on the provided query
func (p *PcnPodController) getNamespaces(query pcn_types.ObjectQuery) ([]core_v1.Namespace, error) {

	// Use the external namespace controller, if available
	if p.nsController != nil {
		return p.nsController.GetNamespaces(query)
	}

	//-------------------------------------
	//	Find by name
	//-------------------------------------

	byName := func(name string) ([]core_v1.Namespace, error) {
		if len(name) < 1 {
			return []core_v1.Namespace{}, errors.New("Namespace name not provided")
		}

		listOptions := meta_v1.ListOptions{}
		if name != "*" {
			listOptions.FieldSelector = "metadata.name=" + name
		}

		lister, err := p.nsInterface.List(listOptions)
		return lister.Items, err
	}

	//-------------------------------------
	//	Find by labels
	//-------------------------------------

	byLabels := func(labels map[string]string) ([]core_v1.Namespace, error) {
		if labels == nil {
			return []core_v1.Namespace{}, errors.New("Namespace labels is nil")
		}

		lister, err := p.nsInterface.List(meta_v1.ListOptions{
			LabelSelector: implodeLabels(labels),
		})

		return lister.Items, err
	}

	//	Get the appropriate function
	switch strings.ToLower(query.By) {
	case "name":
		return byName(query.Name)
	case "labels":
		return byLabels(query.Labels)
	default:
		return []core_v1.Namespace{}, errors.New("Unrecognized namespace query")
	}
}
