package controllers

import (
	"sync"

	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
)

// EventDispatcher dispatches the event to all subscribers
type EventDispatcher struct {
	name        string
	n           pcn_types.SubscriberID
	subscribers map[pcn_types.SubscriberID]subscriber
	lock        sync.Mutex
}

// EventDispatchersContainer contains the three basic EventDispatcher-s: New, Update, Delete
type EventDispatchersContainer struct {
	new    *EventDispatcher
	update *EventDispatcher
	delete *EventDispatcher
}

type subscriber func(interface{})

// NewEventDispatcher starts a new event dispatcher
func NewEventDispatcher(name string) *EventDispatcher {
	return &EventDispatcher{
		name:        name,
		n:           0,
		subscribers: make(map[pcn_types.SubscriberID]subscriber),
	}
}

// Dispatch will dispatch the event to the list of subscribers
func (d *EventDispatcher) Dispatch(item interface{}) {
	d.lock.Lock()
	defer d.lock.Unlock()

	//	Are there any subscribers?
	if (len(d.subscribers)) < 1 {
		return
	}

	//	Loop through all of the subscribers
	for _, s := range d.subscribers {
		// The controller will make it go
		//	go s(item)
		s(item)
	}
}

// Add will add a new subscriber
func (d *EventDispatcher) Add(s subscriber) pcn_types.SubscriberID {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.subscribers[d.n+1] = s
	d.n++

	return d.n
}

// Remove will remove a subscriber
func (d *EventDispatcher) Remove(i pcn_types.SubscriberID) {
	d.lock.Lock()
	defer d.lock.Unlock()

	if _, exists := d.subscribers[i]; exists {
		delete(d.subscribers, i)
	}

}

// CleanUp will remove all subscribers at once
func (d *EventDispatcher) CleanUp() {
	d.lock.Lock()
	defer d.lock.Unlock()

	//	The suggested way to clean up a map, is to create a new empty one
	//	The garbage collector will take care of the rest
	d.subscribers = make(map[pcn_types.SubscriberID]subscriber)

}
