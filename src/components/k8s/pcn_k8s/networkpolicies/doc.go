// Package networkpolicies contains logic for parsing policies.
// It parses policies from kubernetes and polycube and gets back rules in a format that the firewall can understand.
// Then, the network policy manager, will take care of managing firewall managers inside its node
package networkpolicies

const (
	// DPS is the short name of the Default Policy Parser
	DPS = "Default Policy Parser"
	// PM is the short name of the Network Policy Manager
	PM = "Policy Manager"
	// UnscheduleThreshold is the maximum number of hours a firewall manager should live with no pods monitored.
	//	For testing: 5 minutes
	UnscheduleThreshold = 5
	//UnscheduleThreshold = 24
)
