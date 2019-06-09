package types

type FirewallRule struct {
	// The id
	Id int32 `json:"id,omitempty"`

	// Source IP Address.
	Src string `json:"src,omitempty"`

	// Destination IP Address.
	Dst string `json:"dst,omitempty"`

	// Level 4 Protocol.
	L4proto string `json:"l4proto,omitempty"`

	// Source L4 Port
	Sport int32 `json:"sport,omitempty"`

	// Destination L4 Port
	Dport int32 `json:"dport,omitempty"`

	// TCP flags. Allowed values: SYN, FIN, ACK, RST, PSH, URG, CWR, ECE. ! means set to 0.
	Tcpflags string `json:"tcpflags,omitempty"`

	// Connection status (NEW, ESTABLISHED, RELATED, INVALID)
	Conntrack string `json:"conntrack,omitempty"`

	// Action if the rule matches. Default is DROP.
	Action string `json:"action,omitempty"`

	// Description of the rule.
	Description string `json:"description,omitempty"`
}
