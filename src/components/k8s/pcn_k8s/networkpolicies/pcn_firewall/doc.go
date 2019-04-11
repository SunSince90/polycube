package pcnfirewall

const (
	// FWM is the short name of a Firewall Manager
	FWM = "Firewall Manager"
	// FirstIngressID is the very first ingress ID
	FirstIngressID = int32(1)
	// FirstEgressID is the very first ingress ID
	FirstEgressID = int32(1)
	// CleanFirewall specifies the clean action
	CleanFirewall UnlinkOperation = "clean"
	// DestroyFirewall specifies the destroy action
	DestroyFirewall UnlinkOperation = "destroy"
	// DoNothing specifies that no action should be taken
	DoNothing UnlinkOperation = "nothing"
)

// UnlinkOperation is the operation that should be performed after unlinking a pod
type UnlinkOperation string
