package controllers

import (
	"fmt"
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

// DefaultNetworkPolicyController is the implementation of the default network policy controller
type DefaultNetworkPolicyController struct {
	// clientset is the clientset of kubernetes
	clientset *kubernetes.Clientset
	// queue contains the events to be processed
	queue workqueue.RateLimitingInterface
	// defaultNetworkPoliciesInformer is the informer that gets the list of policies
	defaultNetworkPoliciesInformer cache.SharedIndexInformer
	// startedOn tells when the controller started working
	startedOn time.Time
	// dispatchers is the structure that dispatches the event to the intersted subscribers
	dispatchers EventDispatchersContainer
	// stopCh is the channel used to stop the controller
	stopCh chan struct{}
	// maxRetries tells how many times the controller should attempt decoding an object from the queue
	maxRetries int
	// logBy is the name used to identify log entries written by this controller
	logBy string
}

// NewDefaultNetworkPolicyController creates a new policy controller. Meant to be a singleton.
func NewDefaultNetworkPolicyController(clientset *kubernetes.Clientset) *DefaultNetworkPolicyController {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": "Default Policy Controller", "method": "NewDefaultNetworkPolicyController()"})

	logBy := "Default Network Policy Controller"
	maxRetries := 5

	//------------------------------------------------
	//	Set up the default network policies informer
	//------------------------------------------------

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
		new:    NewEventDispatcher("new-default-policy-event-dispatcher"),
		update: NewEventDispatcher("update-default-policy-event-dispatcher"),
		delete: NewEventDispatcher("delete-default-policy-event-dispatcher"),
	}

	//	Everything set up, return the controller
	return &DefaultNetworkPolicyController{
		clientset:                      clientset,
		queue:                          queue,
		defaultNetworkPoliciesInformer: npcInformer,
		dispatchers:                    dispatchers,
		logBy:                          logBy,
		maxRetries:                     maxRetries,
		stopCh:                         make(chan struct{}),
	}
}

// Run starts the network policy controller
func (npc *DefaultNetworkPolicyController) Run() {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": npc.logBy, "method": "Run()"})

	//	Don't let panics crash the process
	defer utilruntime.HandleCrash()

	//	Record when we started, it is going to be used later
	npc.startedOn = time.Now().UTC()

	//	Let's go!
	go npc.defaultNetworkPoliciesInformer.Run(npc.stopCh)

	//	Make sure the cache is populated
	if !cache.WaitForCacheSync(npc.stopCh, npc.defaultNetworkPoliciesInformer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}

	l.Infoln("Started...")

	//	Work *until* something bad happens. If that's the case, wait one second and then re-work again.
	//	Well, except when someone tells us to stop... in that case, just stop, man
	wait.Until(npc.work, time.Second, npc.stopCh)
}

// work gets the item from the queue and attempts to process it.
func (npc *DefaultNetworkPolicyController) work() {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": npc.logBy, "method": "work()"})
	stop := false

	for !stop {

		//	Get the item's key from the queue
		_event, quit := npc.queue.Get()

		if quit {
			l.Infoln("Quit requested... worker going to exit.")
			return
		}

		event, ok := _event.(pcn_types.Event)
		if ok {
			err := npc.processPolicy(event)

			//	No errors?
			if err == nil {
				//	Then reset the ratelimit counters
				npc.queue.Forget(_event)
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
		} else {
			//	Don't process something which is not valid.
			npc.queue.Forget(_event)
			utilruntime.HandleError(fmt.Errorf("Error when trying to parse event %#v from the queue", _event))
		}

		stop = quit
	}
}

// processPolicy will process the policy and dispatch it
func (npc *DefaultNetworkPolicyController) processPolicy(event pcn_types.Event) error {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": npc.logBy, "method": "processPolicy()"})

	var policy *networking_v1.NetworkPolicy
	defer npc.queue.Done(event)

	//	Get the policy by querying the key that kubernetes has assigned to this in its cache
	_policy, _, err := npc.defaultNetworkPoliciesInformer.GetIndexer().GetByKey(event.Key)

	//	Errors?
	if err != nil {
		l.Errorf("An error occurred: cannot find cache element with key %s from store %v", event.Key, err)
		return fmt.Errorf("An error occurred: cannot find cache element with key %s from ", event.Key)
	}

	//	Get the policy or try to recover it.
	policy, ok := _policy.(*networking_v1.NetworkPolicy)
	if !ok {
		policy, ok = event.Object.(*networking_v1.NetworkPolicy)
		if !ok {
			tombstone, ok := event.Object.(cache.DeletedFinalStateUnknown)
			if !ok {
				l.Errorln("error decoding object, invalid type")
				utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
				return fmt.Errorf("error decoding object, invalid type")
			}
			policy, ok = tombstone.Obj.(*networking_v1.NetworkPolicy)
			if !ok {
				l.Errorln("error decoding object tombstone, invalid type")
				utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
				return fmt.Errorf("error decoding object tombstone, invalid type")
			}
			l.Infof("Recovered deleted object '%s' from tombstone", policy.GetName())
		}
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
		npc.dispatchers.delete.Dispatch(policy)
	}

	return nil
}

// Stop stops the controller
func (npc *DefaultNetworkPolicyController) Stop() {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": npc.logBy, "method": "Stop()"})

	//	Make them know that exit has been requested
	close(npc.stopCh)

	//	Shutdown the queue, making the worker unblock
	npc.queue.ShutDown()

	//	Clean up the dispatchers
	npc.dispatchers.new.CleanUp()
	npc.dispatchers.update.CleanUp()
	npc.dispatchers.delete.CleanUp()

	l.Infoln("Default network policy controller exited.")
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
