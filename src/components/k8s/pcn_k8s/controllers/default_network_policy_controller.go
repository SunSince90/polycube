package controllers

import (
	"errors"
	"fmt"
	"strings"
	"time"

	//	TODO-ON-MERGE: change this to the polycube path
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"

	log "github.com/sirupsen/logrus"
	networking_v1 "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	workqueue "k8s.io/client-go/util/workqueue"
)

type DefaultNetworkPolicyController struct {
	nodeName                       string
	clientset                      *kubernetes.Clientset
	queue                          workqueue.RateLimitingInterface
	defaultNetworkPoliciesInformer cache.SharedIndexInformer
	startedOn                      time.Time
	dispatchers                    EventDispatchersContainer
	stopCh                         chan struct{}
	maxRetries                     int
	logBy                          string
}

func NewDefaultNetworkPolicyController(nodeName string, clientset *kubernetes.Clientset) *DefaultNetworkPolicyController {

	//	Init here
	//	TODO: make maxRetries settable on parameters?
	logBy := "DNPC"
	maxRetries := 5

	//	Let them know we're starting
	/*log.SetLevel(log.DebugLevel)
	var l = log.WithFields(log.Fields{
		"by":     logBy,
		"method": "NewNetworkPolicyController()",
	})*/

	//l.Infof("Network Policy Controller just called on node %s", nodeName)

	//------------------------------------------------
	//	Set up the default network policies informer
	//------------------------------------------------

	//	TODO: is there really a need for a *shared* informer?
	//	After all, this should be the only controller to do this.
	//	So, yeah... remember to check this up.
	npcInformer := cache.NewSharedIndexInformer(&cache.ListWatch{
		ListFunc: func(options meta_v1.ListOptions) (runtime.Object, error) {
			return clientset.NetworkingV1().NetworkPolicies(meta_v1.NamespaceAll).List(options)
		},
		WatchFunc: func(options meta_v1.ListOptions) (watch.Interface, error) {
			return clientset.NetworkingV1().NetworkPolicies(meta_v1.NamespaceAll).Watch(options)
		},
	},
		&networking_v1.NetworkPolicy{},
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
	npcInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			/*log.WithFields(log.Fields{
				"by":     logBy,
				"method": "AddFunc()",
			}).Infof("Something has been added! Workspaces is %s", key)*/

			//	Set up the event
			event := pcn_types.Event{
				Key:       key,
				Type:      pcn_types.New,
				Namespace: strings.Split(key, "/")[0],
			}

			//	Add this event to the queue
			if err == nil {
				queue.Add(event)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			/*log.WithFields(log.Fields{
				"by":     logBy,
				"method": "UpdateFunc()",
			}).Info("Something has been updated!")*/

			key, err := cache.MetaNamespaceKeyFunc(new)

			//	Set up the event
			event := pcn_types.Event{
				Key:       key,
				Type:      pcn_types.Update,
				Namespace: strings.Split(key, "/")[0],
			}
			//	Add this event to the queue
			if err == nil {
				queue.Add(event)
			}
		},
		DeleteFunc: func(obj interface{}) {
			/*log.WithFields(log.Fields{
				"by":     logBy,
				"method": "DeleteFunc()",
			}).Info("Something has been deleted!")*/

			key, err := cache.MetaNamespaceKeyFunc(obj)

			//	Set up the event
			event := pcn_types.Event{
				Key:       key,
				Type:      pcn_types.Delete,
				Namespace: strings.Split(key, "/")[0],
			}
			//	Add this event to the queue
			if err == nil {
				queue.Add(event)
			}
		},
	})

	//l.Info("Just set up the event handlers")

	//------------------------------------------------
	//	Set up the dispatchers
	//------------------------------------------------

	dispatchers := EventDispatchersContainer{
		new:    NewEventDispatcher("new-default-policy-event-dispatcher"),
		update: NewEventDispatcher("update-default-policy-event-dispatcher"),
		delete: NewEventDispatcher("delete-default-policy-event-dispatcher"),
	}

	//	Everything set up, return the controller
	return &DefaultNetworkPolicyController{
		nodeName:                       nodeName,
		clientset:                      clientset,
		queue:                          queue,
		defaultNetworkPoliciesInformer: npcInformer,
		dispatchers:                    dispatchers,
		logBy:                          logBy,
		maxRetries:                     maxRetries,
		stopCh:                         make(chan struct{}),
	}
}

func (npc *DefaultNetworkPolicyController) Run() {

	var l = log.WithFields(log.Fields{
		"by":     npc.logBy,
		"method": "Start()",
	})

	//	Channel will be closed by Stop().
	//defer close(npc.stopCh)

	//	Don't let panics crash the process
	defer utilruntime.HandleCrash()

	//	Make sure the work queue is shutdown which will trigger workers to end
	//	This is going to be shutdown by Stop()
	//defer npc.queue.ShutDown()

	//	Record when we started, it is going to be used later
	npc.startedOn = time.Now().UTC()

	//	Let's go!
	go npc.defaultNetworkPoliciesInformer.Run(npc.stopCh)

	//	Make sure the cache is populated
	if !cache.WaitForCacheSync(npc.stopCh, npc.defaultNetworkPoliciesInformer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}

	l.Info("Network Policy Controller started")

	//	Work *until* something bad happens. If that's the case, wait one second and then re-work again.
	//	Well, except when someone tells us to stop... in that case, just stop, man
	wait.Until(npc.work, time.Second, npc.stopCh)
}

func (npc *DefaultNetworkPolicyController) work() {

	var stop = false
	var l = log.WithFields(log.Fields{
		"by":     npc.logBy,
		"method": "work()",
	})

	for !stop {

		//	Get the item's key from the queue
		_event, quit := npc.queue.Get()

		if quit {
			l.Infoln("Quit requested... worker going to exit.")
			return
		}

		event := _event.(pcn_types.Event)

		//l.Infof("Just got the item: its key is %s on namespace %s", event.Key, event.Namespace)

		err := npc.processPolicy(event)

		//	No errors?
		if err == nil {
			//	Then reset the ratelimit counters
			npc.queue.Forget(_event)
			//l.Infof("Item with key %s has been forgotten from the queue", event.Key)
		} else if npc.queue.NumRequeues(_event) < npc.maxRetries {
			//	Tried less than the maximum retries?
			l.Warningf("Error processing item with key %s (will retry): %v", event.Key, err)
			npc.queue.AddRateLimited(_event)
		} else {
			//	Too many retries?
			l.Errorf("Error processing %s (giving up): %v", event.Key, err)
			npc.queue.Forget(_event)
			utilruntime.HandleError(err)
		}

		stop = quit
	}
}

func (npc *DefaultNetworkPolicyController) processPolicy(event pcn_types.Event) error {

	var l = log.WithFields(log.Fields{
		"by":     npc.logBy,
		"method": "processPolicy()",
	})
	var policy *networking_v1.NetworkPolicy

	defer npc.queue.Done(event)

	//l.Infof("Starting to process policy")

	//	Get the policy by querying the key that kubernetes has assigned to this in its cache
	_policy, exists, err := npc.defaultNetworkPoliciesInformer.GetIndexer().GetByKey(event.Key)

	//	Errors?
	if err != nil {
		l.Errorf("An error occurred: cannot find cache element with key %s from store %v", event.Key, err)

		//	TODO: check this
		return fmt.Errorf("An error occurred: cannot find cache element with key %s from ", event.Key)
	}

	//	Get the policy
	if _policy != nil {
		policy = _policy.(*networking_v1.NetworkPolicy)
	}

	//-------------------------------------
	//	Dispatch the event
	//-------------------------------------

	switch event.Type {

	case pcn_types.New:
		npc.dispatchers.new.Dispatch(policy)
	case pcn_types.Update:
		npc.dispatchers.update.Dispatch(policy)
	case pcn_types.Delete:
		//	TODO: check this, how to get dead policies now?
		/*_splitted := strings.Split(event.Key, "/")
		policy, ok := npc.deployedPolicies[_splitted[1]]
		if ok {
			npc.dispatchers.delete.Dispatch(policy)
		}*/
	}

	//	Does not exist?
	if !exists {
		//l.Infof("Object with key %s does not exist. Going to trigger a onDelete function", event.Key)
	}

	return nil
}

// GetPolicies returns a list of network policies that match the specified criteria.
// Return an empty list if no network policies have been found or an error occurred.
// In the latter case, it also returns the error occurred.
func (npc *DefaultNetworkPolicyController) GetPolicies(query pcn_types.ObjectQuery, namespace string) ([]networking_v1.NetworkPolicy, error) {

	//-------------------------------------
	//	Basic query checks
	//-------------------------------------

	if query.By != "name" {
		//	As of now, network policies can only be found by name.
		return []networking_v1.NetworkPolicy{}, errors.New("Query type not supported")
	}

	if len(query.Name) < 1 {
		return []networking_v1.NetworkPolicy{}, errors.New("No name provided")
	}

	if len(namespace) < 1 {
		return []networking_v1.NetworkPolicy{}, errors.New("No namespace provided")
	}

	//-------------------------------------
	//	Find by name
	//-------------------------------------

	if namespace == "*" {
		namespace = meta_v1.NamespaceAll
	}
	lister := npc.clientset.NetworkingV1().NetworkPolicies(namespace)

	//	All default policies?
	if query.Name == "*" {
		list, err := lister.List(meta_v1.ListOptions{})
		if err != nil {
			return []networking_v1.NetworkPolicy{}, err
		}
		return list.Items, nil
	}

	//	Specific name?
	list, err := lister.List(meta_v1.ListOptions{FieldSelector: "metadata.name == " + query.Name})
	if err != nil {
		return []networking_v1.NetworkPolicy{}, err
	}
	return list.Items, nil
}

func (npc *DefaultNetworkPolicyController) Stop() {

	l := log.WithFields(log.Fields{
		"by":     npc.logBy,
		"method": "Stop())",
	})

	//	Make them know that exit has been requested
	close(npc.stopCh)

	//	Shutdown the queue, making the worker unblock
	npc.queue.ShutDown()

	//	Clean up the dispatchers
	npc.dispatchers.new.CleanUp()
	npc.dispatchers.update.CleanUp()
	npc.dispatchers.delete.CleanUp()

	l.Info("Default network policy controller exited.")
}

/*Subscribe executes the function consumer when the event event is triggered. It returns an error if the event type does not exist.
It returns a function to call when you want to stop tracking that event.*/
func (npc *DefaultNetworkPolicyController) Subscribe(event pcn_types.EventType, consumer func(*networking_v1.NetworkPolicy)) (func(), error) {

	//	Prepare the function to be executed
	consumerFunc := (func(item interface{}) {

		//	First, cast the item to a network policy, so that the consumer will receive exactly what it wants...
		policy := item.(*networking_v1.NetworkPolicy)

		//	Then, execute the consumer in a separate thread.
		//	NOTE: this step can also be done in the event dispatcher, but I want it to make them oblivious of the type they're handling.
		//	This way, the event dispatcher is as general as possible (also, it is not their concern to cast objects.)
		go consumer(policy)
	})

	//	What event are you subscribing to?
	switch event {

	//-------------------------------------
	//	New event
	//-------------------------------------

	case pcn_types.New:
		id := npc.dispatchers.new.Add(consumerFunc)

		return func() {
			npc.dispatchers.new.Remove(id)
		}, nil

	//-------------------------------------
	//	Update event
	//-------------------------------------

	case pcn_types.Update:
		id := npc.dispatchers.update.Add(consumerFunc)

		return func() {
			npc.dispatchers.update.Remove(id)
		}, nil

	//-------------------------------------
	//	Delete Event
	//-------------------------------------

	case pcn_types.Delete:
		id := npc.dispatchers.delete.Add(consumerFunc)

		return func() {
			npc.dispatchers.delete.Remove(id)
		}, nil

	//-------------------------------------
	//	Undefined event
	//-------------------------------------

	default:
		return nil, fmt.Errorf("Undefined event type")
	}

}
