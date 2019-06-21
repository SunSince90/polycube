package types

// Event is the event from k8s cache
type Event struct {
	// Key is the key assigned to the object
	Key string
	// Type is the event type (DELETE, UPDATE, NEW)
	Type EventType
	// Namespace is the namespace of the object
	Namespace string
	// Object is the original object
	Object interface{}
}

// EventType is the type of the event
type EventType int

// SubscriberID is the ID assigned to a subscriber
type SubscriberID uint

const (
	// New represents the new event ID
	New = iota + 1
	// Update represents the update event ID
	Update
	// Delete represents the delete event ID
	Delete
)
