package types

type Event struct {
	Key       string
	Type      EventType
	Namespace string
}

type EventType int
type SubscriberID uint

const (
	New = iota + 1
	Update
	Delete
)
