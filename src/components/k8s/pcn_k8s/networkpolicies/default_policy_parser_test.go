package networkpolicies

import (
	"fmt"
	"testing"

	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"

	networking_v1 "k8s.io/api/networking/v1"

	pcn_controllers "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/controllers"
	"github.com/stretchr/testify/assert"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func Init(podController pcn_controllers.PodController) *DefaultPolicyParser {
	manager := newDefaultPolicyParser(podController)
	return manager
}

func TestNotNil(t *testing.T) {
	/*manager := Init(nil)
	assert.NotNil(t, manager)*/
}

func TestPolicyTypes(t *testing.T) {
	testObj := new(MockPodController)
	parser := Init(testObj)

	//	Case 1: spec is nil
	ingress, egress, ptype := parser.ParsePolicyTypes(nil)
	assert.Empty(t, ingress)
	assert.Empty(t, egress)
	assert.Equal(t, "ingress", ptype)

	//	Case 2: only ingress
	spec := &networking_v1.NetworkPolicySpec{
		PolicyTypes: []networking_v1.PolicyType{
			networking_v1.PolicyTypeIngress,
		},
	}
	ingress, egress, ptype = parser.ParsePolicyTypes(spec)
	assert.Empty(t, ingress)
	assert.Empty(t, egress)
	assert.Equal(t, "ingress", ptype)

	//	Case 2: only ingress
	spec = &networking_v1.NetworkPolicySpec{
		PolicyTypes: []networking_v1.PolicyType{
			networking_v1.PolicyTypeEgress,
		},
		Egress: []networking_v1.NetworkPolicyEgressRule{
			networking_v1.NetworkPolicyEgressRule{
				To: []networking_v1.NetworkPolicyPeer{},
			},
		},
	}
	ingress, egress, ptype = parser.ParsePolicyTypes(spec)
	assert.Empty(t, ingress)
	assert.NotEmpty(t, egress)
	assert.Equal(t, "egress", ptype)

	//	Case 3: both
	spec = &networking_v1.NetworkPolicySpec{
		PolicyTypes: []networking_v1.PolicyType{
			networking_v1.PolicyTypeEgress,
			networking_v1.PolicyTypeIngress,
		},
		Egress: []networking_v1.NetworkPolicyEgressRule{
			networking_v1.NetworkPolicyEgressRule{
				To: []networking_v1.NetworkPolicyPeer{},
			},
		},
		Ingress: []networking_v1.NetworkPolicyIngressRule{
			networking_v1.NetworkPolicyIngressRule{
				From: []networking_v1.NetworkPolicyPeer{},
			},
		},
	}
	ingress, egress, ptype = parser.ParsePolicyTypes(spec)
	assert.NotEmpty(t, ingress)
	assert.NotEmpty(t, egress)
	assert.Equal(t, "*", ptype)
}

func TestRulesIsNil(t *testing.T) {
	testObj := new(MockPodController)
	parser := Init(testObj)

	//	Case 1
	result := parser.ParseIngress(nil, "*")
	assert.Empty(t, result.Ingress)
	assert.Empty(t, result.Egress)

	//	Case 2
	result = parser.ParseEgress(nil, "*")
	assert.Empty(t, result.Ingress)
	assert.Empty(t, result.Egress)
}

func TestRulesLenZero(t *testing.T) {
	testObj := new(MockPodController)
	parser := Init(testObj)

	//	Case 1
	expectedIngress := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Action: pcn_types.ActionDrop,
		},
	}
	result := parser.ParseIngress([]networking_v1.NetworkPolicyIngressRule{}, "ns")
	assert.ElementsMatch(t, expectedIngress, result.Ingress)
	assert.Empty(t, result.Egress)

	//	Case 2
	expectedEgress := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Action: pcn_types.ActionDrop,
		},
	}
	result = parser.ParseEgress([]networking_v1.NetworkPolicyEgressRule{}, "ns")
	assert.ElementsMatch(t, expectedEgress, result.Egress)
	assert.Empty(t, result.Ingress)
}

func TestGetConnectionTemplate(t *testing.T) {

	testObj := new(MockPodController)
	parser := Init(testObj)

	src := "10.0.0.1"
	dst := "10.0.0.2"
	action := pcn_types.ActionForward
	direction := "ingress"
	ports := []pcn_types.ProtoPort{}

	//	Case 1
	expectedIngress := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Src:       src,
			Dst:       dst,
			Action:    action,
			Conntrack: pcn_types.ConnTrackNew,
		},
		k8sfirewall.ChainRule{
			Src:       src,
			Dst:       dst,
			Action:    action,
			Conntrack: pcn_types.ConnTrackEstablished,
		},
	}
	expectedEgress := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Src:       dst,
			Dst:       src,
			Action:    action,
			Conntrack: pcn_types.ConnTrackEstablished,
		},
	}

	result := parser.GetConnectionTemplate(direction, src, dst, action, ports)
	assert.ElementsMatch(t, expectedIngress, result.Ingress)
	assert.ElementsMatch(t, expectedEgress, result.Egress)

	for i := 0; i < len(result.Ingress); i++ {
		fmt.Printf("%+v\n", result.Ingress[i])
	}
	fmt.Println("---")
	//	Case 2
	direction = "egress"
	src = "10.0.0.3"
	dst = "10.0.0.4"
	action = pcn_types.ActionDrop

	expectedEgress = []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Src:       src,
			Dst:       dst,
			Action:    action,
			Conntrack: pcn_types.ConnTrackNew,
		},
		k8sfirewall.ChainRule{
			Src:       src,
			Dst:       dst,
			Action:    action,
			Conntrack: pcn_types.ConnTrackEstablished,
		},
	}
	expectedIngress = []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Src:       dst,
			Dst:       src,
			Action:    action,
			Conntrack: pcn_types.ConnTrackEstablished,
		},
	}

	result = parser.GetConnectionTemplate(direction, src, dst, action, ports)
	assert.ElementsMatch(t, expectedIngress, result.Ingress)
	assert.ElementsMatch(t, expectedEgress, result.Egress)

	for i := 0; i < len(result.Egress); i++ {
		fmt.Printf("%+v\n", result.Egress[i])
	}
}

func TestParseProtocolAndPort(t *testing.T) {
	stcp := core_v1.ProtocolSCTP
	udp := core_v1.ProtocolUDP
	tcp := core_v1.ProtocolTCP
	port := &intstr.IntOrString{
		IntVal: 6895,
	}
	ports := []networking_v1.NetworkPolicyPort{
		networking_v1.NetworkPolicyPort{
			Protocol: &udp,
			Port:     port,
		},
		networking_v1.NetworkPolicyPort{
			Protocol: &stcp,
			Port:     port,
		},
		networking_v1.NetworkPolicyPort{
			Protocol: &tcp,
			Port:     port,
		},
	}
	testObj := new(MockPodController)
	manager := Init(testObj)

	//	--- UDP
	supported, protocol, pport := manager.parseProtocolAndPort(ports[0])
	assert.Equal(t, "UDP", protocol)
	assert.Equal(t, int32(port.IntVal), pport)
	assert.True(t, supported)

	//	--- TCP
	supported, protocol, pport = manager.parseProtocolAndPort(ports[2])
	assert.Equal(t, "TCP", protocol)
	assert.Equal(t, int32(port.IntVal), pport)
	assert.True(t, supported)

	//	--- STCP
	supported, protocol, pport = manager.parseProtocolAndPort(ports[1])
	assert.Len(t, protocol, 0)
	assert.Zero(t, pport)
	assert.False(t, supported)
}

func TestParsePorts(t *testing.T) {
	testObj := new(MockPodController)
	parser := Init(testObj)

	// Case 1: protocol and port are nil
	///	Not very sure if protocol can be nil, but just in case ...
	expectedResult := []pcn_types.ProtoPort{
		pcn_types.ProtoPort{
			Port: 0,
		},
	}
	ports := []networking_v1.NetworkPolicyPort{
		networking_v1.NetworkPolicyPort{},
	}
	result := parser.ParsePorts(ports)
	assert.ElementsMatch(t, expectedResult, result)

	//	Case 2: port and protocol are not nil and there is an unsupported protocol
	udp := core_v1.ProtocolUDP
	ports[0] = networking_v1.NetworkPolicyPort{
		Port: &intstr.IntOrString{
			IntVal: 6895,
		},
		Protocol: &udp,
	}
	sctp := core_v1.ProtocolSCTP
	ports = append(ports, networking_v1.NetworkPolicyPort{
		Port: &intstr.IntOrString{
			IntVal: 6895,
		},
		Protocol: &sctp,
	})
	expectedResult = []pcn_types.ProtoPort{
		pcn_types.ProtoPort{
			Port:     ports[0].Port.IntVal,
			Protocol: "UDP",
		},
	}
	result = parser.ParsePorts(ports)
	assert.ElementsMatch(t, expectedResult, result)

	//	Case 3: only unsupported protocols
	ports = []networking_v1.NetworkPolicyPort{
		networking_v1.NetworkPolicyPort{
			Port: &intstr.IntOrString{
				IntVal: 6895,
			},
			Protocol: &sctp,
		},
	}
	result = parser.ParsePorts(ports)
	assert.Empty(t, result)

	//	case 3 ports is nil
	result = parser.ParsePorts(nil)
	assert.Empty(t, result)
}

func TestInsertPorts(t *testing.T) {
	testObj := new(MockPodController)
	parser := Init(testObj)

	src := "10.0.0.1"
	dst := "10.0.0.2"
	action := pcn_types.ActionForward

	//	This is tested above
	ingress := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Src:    src,
			Dst:    dst,
			Action: action,
		},
	}
	egress := []k8sfirewall.ChainRule{

		k8sfirewall.ChainRule{
			Src:    src,
			Dst:    dst,
			Action: action,
		},
	}

	//	This is tested above
	port1 := int32(1111)
	port2 := int32(2222)
	udp := core_v1.ProtocolUDP
	tcp := core_v1.ProtocolTCP
	ports := []networking_v1.NetworkPolicyPort{
		networking_v1.NetworkPolicyPort{
			Port: &intstr.IntOrString{
				IntVal: port1,
			},
			Protocol: &udp,
		},
		networking_v1.NetworkPolicyPort{
			Port: &intstr.IntOrString{
				IntVal: port2,
			},
			Protocol: &tcp,
		},
	}

	//	Case 1: nil ports
	fullRules := parser.insertPorts(ingress, egress, []pcn_types.ProtoPort{})
	assert.ElementsMatch(t, fullRules.Ingress, ingress)
	assert.ElementsMatch(t, fullRules.Egress, egress)

	//	Case 2: no ports
	fullRules = parser.insertPorts(ingress, egress, []pcn_types.ProtoPort{})
	assert.ElementsMatch(t, fullRules.Ingress, ingress)
	assert.ElementsMatch(t, fullRules.Egress, egress)

	//	Case 3, ports
	parsedPorts := parser.ParsePorts(ports)
	fullRules = parser.insertPorts(ingress, egress, parsedPorts)
	assert.Len(t, fullRules.Ingress, len(ingress)*len(ports))
	assert.Len(t, fullRules.Egress, len(egress)*len(ports))

	expectedIngress := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Src:     src,
			Dst:     dst,
			Action:  action,
			Dport:   port1,
			L4proto: "UDP",
		},
		k8sfirewall.ChainRule{
			Src:     src,
			Dst:     dst,
			Action:  action,
			Dport:   port2,
			L4proto: "TCP",
		},
	}
	expectedEgress := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Src:     src,
			Dst:     dst,
			Action:  action,
			Sport:   port1,
			L4proto: "UDP",
		},
		k8sfirewall.ChainRule{
			Src:     src,
			Dst:     dst,
			Action:  action,
			Sport:   port2,
			L4proto: "TCP",
		},
	}
	assert.ElementsMatch(t, fullRules.Ingress, expectedIngress)
	assert.ElementsMatch(t, fullRules.Egress, expectedEgress)

}

func TestParseIPBlock(t *testing.T) {
	testObj := new(MockPodController)
	parser := Init(testObj)

	//	case 1: block is nil
	result := parser.ParseIPBlock(nil, "ingress")
	assert.Empty(t, result.Ingress)
	assert.Empty(t, result.Egress)

	//	case 2: block is ""
	block := &networking_v1.IPBlock{
		CIDR: "",
	}
	result = parser.ParseIPBlock(block, "ingress")
	assert.Empty(t, result.Ingress)
	assert.Empty(t, result.Egress)

	//	case 3(ingress): block with exceptions
	block.CIDR = "10.0.0.0/24"
	block.Except = []string{"10.0.0.0/25"}
	expectedIngress := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Src:       block.CIDR,
			Action:    pcn_types.ActionForward,
			Conntrack: pcn_types.ConnTrackNew,
		},
		k8sfirewall.ChainRule{
			Src:       block.CIDR,
			Action:    pcn_types.ActionForward,
			Conntrack: pcn_types.ConnTrackEstablished,
		},
		k8sfirewall.ChainRule{
			Src:       block.Except[0],
			Action:    pcn_types.ActionDrop,
			Conntrack: pcn_types.ConnTrackNew,
		},
	}
	expectedEgress := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Dst:       block.CIDR,
			Action:    pcn_types.ActionForward,
			Conntrack: pcn_types.ConnTrackEstablished,
		},
	}
	result = parser.ParseIPBlock(block, "ingress")
	assert.ElementsMatch(t, expectedIngress, result.Ingress)
	assert.ElementsMatch(t, expectedEgress, result.Egress)

	//	case 3(egress): block with exceptions
	block.CIDR = "10.0.0.0/24"
	block.Except = []string{"10.0.0.0/25"}
	expectedEgress = []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Dst:       block.CIDR,
			Action:    pcn_types.ActionForward,
			Conntrack: pcn_types.ConnTrackNew,
		},
		k8sfirewall.ChainRule{
			Dst:       block.CIDR,
			Action:    pcn_types.ActionForward,
			Conntrack: pcn_types.ConnTrackEstablished,
		},
		k8sfirewall.ChainRule{
			Dst:       block.Except[0],
			Action:    pcn_types.ActionDrop,
			Conntrack: pcn_types.ConnTrackNew,
		},
	}
	expectedIngress = []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{
			Src:       block.CIDR,
			Action:    pcn_types.ActionForward,
			Conntrack: pcn_types.ConnTrackEstablished,
		},
	}
	result = parser.ParseIPBlock(block, "egress")
	assert.ElementsMatch(t, expectedIngress, result.Ingress)
	assert.ElementsMatch(t, expectedEgress, result.Egress)
}

func TestBuildPodQueries(t *testing.T) {
	testObj := new(MockPodController)
	parser := Init(testObj)
	ns := "namespace"
	//	case 1: matchexpressions
	podSelector := &meta_v1.LabelSelector{
		MatchExpressions: []meta_v1.LabelSelectorRequirement{},
	}
	_, _, err := parser.buildPodQueries(podSelector, nil, "")
	assert.Error(t, err)
	nsSelector := &meta_v1.LabelSelector{
		MatchExpressions: []meta_v1.LabelSelectorRequirement{},
	}
	_, _, err = parser.buildPodQueries(nil, nsSelector, "")
	assert.Error(t, err)

	//	case 2: select all pods and all namespaces
	//	a): both nil
	expectedP := pcn_types.ObjectQuery{
		By:   "name",
		Name: "*",
	}
	expectedN := pcn_types.ObjectQuery{
		By:   "name",
		Name: ns,
	}
	p, n, err := parser.buildPodQueries(nil, nil, ns)
	assert.NoError(t, err)
	assert.Equal(t, expectedP.By, p.By)
	assert.Equal(t, expectedP.Name, p.Name)
	assert.Equal(t, expectedN.By, n.By)
	assert.Equal(t, expectedN.Name, n.Name)

	//	b) empty labels
	podSelector = &meta_v1.LabelSelector{}
	nsSelector = &meta_v1.LabelSelector{}
	expectedN.Name = "*"
	podSelector.MatchLabels = map[string]string{}
	nsSelector.MatchLabels = map[string]string{}
	p, n, err = parser.buildPodQueries(podSelector, nsSelector, ns)
	assert.NoError(t, err)
	assert.Equal(t, expectedP.By, p.By)
	assert.Equal(t, expectedP.Name, p.Name)
	assert.Equal(t, expectedN.By, n.By)
	assert.Equal(t, expectedN.Name, n.Name)

	//	Case 3: specific labels for both
	podSelector.MatchLabels = map[string]string{"app": "pcn", "v": "2"}
	nsSelector.MatchLabels = map[string]string{"env": "production"}
	expectedN = pcn_types.ObjectQuery{
		By:     "labels",
		Labels: nsSelector.MatchLabels,
	}
	expectedP = pcn_types.ObjectQuery{
		By:     "labels",
		Labels: podSelector.MatchLabels,
	}
	p, n, err = parser.buildPodQueries(podSelector, nsSelector, ns)
	assert.NoError(t, err)
	assert.Equal(t, expectedP.By, p.By)
	assert.Equal(t, expectedP.Name, p.Name)
	assert.Equal(t, expectedP.Labels, p.Labels)
	assert.Equal(t, expectedN.By, n.By)
	assert.Equal(t, expectedN.Name, n.Name)
	assert.Equal(t, expectedN.Labels, n.Labels)
}

func TestParseSelectors(t *testing.T) {
	//	No need to do anything here: it just makes use of already tested functions.
}

func TestOnlyUnsupportedProtocol(t *testing.T) {
	//	if the policy only consists of unsupported protocol, then it is better
	//	not to generate rules at all, instead of creating wrong rules!
	stcp := core_v1.ProtocolSCTP
	port := &intstr.IntOrString{
		IntVal: 6895,
	}
	ports := []networking_v1.NetworkPolicyPort{
		networking_v1.NetworkPolicyPort{
			Protocol: &stcp,
			Port:     port,
		},
	}
	ipBlock := &networking_v1.IPBlock{
		CIDR: "192.168.0.0/16",
	}
	testObj := new(MockPodController)
	manager := Init(testObj)

	//---------------------------------
	//	Ingress
	//---------------------------------

	ingress := []networking_v1.NetworkPolicyIngressRule{
		networking_v1.NetworkPolicyIngressRule{
			From: []networking_v1.NetworkPolicyPeer{
				networking_v1.NetworkPolicyPeer{
					IPBlock: ipBlock,
				},
			},
			Ports: ports,
		},
	}

	result := manager.ParseIngress(ingress, "ns")
	assert.Empty(t, result.Ingress)
	assert.Empty(t, result.Egress)

	//---------------------------------
	//	Egress
	//---------------------------------

	egress := []networking_v1.NetworkPolicyEgressRule{
		networking_v1.NetworkPolicyEgressRule{
			To: []networking_v1.NetworkPolicyPeer{
				networking_v1.NetworkPolicyPeer{
					IPBlock: ipBlock,
				},
			},
			Ports: ports,
		},
	}

	result = manager.ParseEgress(egress, "ns")
	assert.Empty(t, result.Ingress)
	assert.Empty(t, result.Egress)
}

func TestBuildActions(t *testing.T) {
	tcp := core_v1.ProtocolTCP
	udp := core_v1.ProtocolUDP
	port1 := &intstr.IntOrString{
		IntVal: 6895,
	}
	port2 := &intstr.IntOrString{
		IntVal: 8080,
	}
	port3 := &intstr.IntOrString{
		IntVal: 80,
	}
	namespaceLabels := map[string]string{
		"environment": "production",
	}
	betaLabels := map[string]string{
		"app": "in-beta",
	}
	podLabels := map[string]string{
		"type":    "app",
		"version": "2.0",
	}

	policy := &networking_v1.NetworkPolicy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      TestDefaultPolicyName,
			Namespace: ProductionNamespace,
		},
		Spec: networking_v1.NetworkPolicySpec{
			PodSelector: meta_v1.LabelSelector{
				MatchLabels: LabelsPodsInProduction,
			},
			PolicyTypes: []networking_v1.PolicyType{
				networking_v1.PolicyTypeIngress,
				//networking_v1.PolicyTypeEgress,
			},
			Ingress: []networking_v1.NetworkPolicyIngressRule{

				//	First Rule: all pods inside my namespace
				networking_v1.NetworkPolicyIngressRule{
					From: []networking_v1.NetworkPolicyPeer{
						networking_v1.NetworkPolicyPeer{

							PodSelector: &meta_v1.LabelSelector{
								MatchLabels: map[string]string{},
							},
						},
					},
					Ports: []networking_v1.NetworkPolicyPort{
						networking_v1.NetworkPolicyPort{
							Protocol: &tcp,
							Port:     port1,
						},
						networking_v1.NetworkPolicyPort{
							Protocol: &udp,
							Port:     port1,
						},
					},
				},

				//	Second rule: pods with specific labels no ports, in my same namespace
				//	OR all pods in specific namespace
				networking_v1.NetworkPolicyIngressRule{
					From: []networking_v1.NetworkPolicyPeer{
						networking_v1.NetworkPolicyPeer{
							PodSelector: &meta_v1.LabelSelector{
								MatchLabels: podLabels,
							},
						},

						networking_v1.NetworkPolicyPeer{
							NamespaceSelector: &meta_v1.LabelSelector{
								MatchLabels: betaLabels,
							},
						},
					},
				},

				//	Fourth rule: pods with specific labels in namespace with specific labels
				networking_v1.NetworkPolicyIngressRule{
					From: []networking_v1.NetworkPolicyPeer{
						networking_v1.NetworkPolicyPeer{

							PodSelector: &meta_v1.LabelSelector{
								MatchLabels: podLabels,
							},
							NamespaceSelector: &meta_v1.LabelSelector{
								MatchLabels: namespaceLabels,
							},
						},
					},
				},

				//	Fifth rule: pods with specific labels in all namespaces
				networking_v1.NetworkPolicyIngressRule{
					From: []networking_v1.NetworkPolicyPeer{
						networking_v1.NetworkPolicyPeer{

							PodSelector: &meta_v1.LabelSelector{
								MatchLabels: podLabels,
							},
							NamespaceSelector: &meta_v1.LabelSelector{
								MatchLabels: map[string]string{},
							},
						},
					},
				},

				//	Sixth rule: same as the fourth but with ports
				networking_v1.NetworkPolicyIngressRule{
					From: []networking_v1.NetworkPolicyPeer{
						networking_v1.NetworkPolicyPeer{

							PodSelector: &meta_v1.LabelSelector{
								MatchLabels: podLabels,
							},
							NamespaceSelector: &meta_v1.LabelSelector{
								MatchLabels: namespaceLabels,
							},
						},
					},
					Ports: []networking_v1.NetworkPolicyPort{
						networking_v1.NetworkPolicyPort{
							Protocol: &tcp,
							Port:     port1,
						},
						networking_v1.NetworkPolicyPort{
							Protocol: &udp,
							Port:     port1,
						},
					},
				},
			},
		},
	}

	testObj := new(MockPodController)
	parser := Init(testObj)

	expectedActions := []pcn_types.FirewallAction{
		pcn_types.FirewallAction{
			PodLabels:     policy.Spec.Ingress[0].From[0].PodSelector.MatchLabels,
			NamespaceName: policy.Namespace,
			Templates:     parser.GetConnectionTemplate("ingress", "10.0.0.1", "", pcn_types.ActionForward, []pcn_types.ProtoPort{}),
		},
		pcn_types.FirewallAction{
			PodLabels:     policy.Spec.Ingress[1].From[0].PodSelector.MatchLabels,
			NamespaceName: policy.Namespace,
			Templates:     parser.GetConnectionTemplate("ingress", "10.0.0.1", "", pcn_types.ActionForward, []pcn_types.ProtoPort{}),
		},
		pcn_types.FirewallAction{
			NamespaceLabels: policy.Spec.Ingress[1].From[1].NamespaceSelector.MatchLabels,
			Templates:       parser.GetConnectionTemplate("ingress", "10.0.0.1", "", pcn_types.ActionForward, []pcn_types.ProtoPort{}),
		},
		pcn_types.FirewallAction{
			PodLabels:       policy.Spec.Ingress[2].From[0].PodSelector.MatchLabels,
			NamespaceLabels: policy.Spec.Ingress[2].From[0].NamespaceSelector.MatchLabels,
			Templates:       parser.GetConnectionTemplate("ingress", "10.0.0.1", "", pcn_types.ActionForward, []pcn_types.ProtoPort{}),
		},
		pcn_types.FirewallAction{
			PodLabels: policy.Spec.Ingress[2].From[0].PodSelector.MatchLabels,
			Templates: parser.GetConnectionTemplate("ingress", "10.0.0.1", "", pcn_types.ActionForward, []pcn_types.ProtoPort{}),
		},
		pcn_types.FirewallAction{
			PodLabels:       policy.Spec.Ingress[2].From[0].PodSelector.MatchLabels,
			NamespaceLabels: policy.Spec.Ingress[2].From[0].NamespaceSelector.MatchLabels,
			Templates:       parser.GetConnectionTemplate("ingress", "10.0.0.1", "", pcn_types.ActionForward, []pcn_types.ProtoPort{}),
		},
	}

	ingress, egress, _ := parser.ParsePolicyTypes(&policy.Spec)
	actions := parser.BuildActions(ingress, egress, policy.Namespace)

	//assert.ElementsMatch(t, expectedActions, actions)
	//	No need to test for the rules as they are tested in GetTemplate
	for i := 0; i < len(actions); i++ {
		assert.Equal(t, actions[i].NamespaceName, expectedActions[i].NamespaceName)
		assert.Len(t, actions[i].NamespaceLabels, len(expectedActions[i].NamespaceLabels))
		assert.Len(t, actions[i].PodLabels, len(expectedActions[i].PodLabels))
	}

	//	With egress as well

	policy.Spec.Egress = []networking_v1.NetworkPolicyEgressRule{

		networking_v1.NetworkPolicyEgressRule{
			To: []networking_v1.NetworkPolicyPeer{
				networking_v1.NetworkPolicyPeer{
					PodSelector: &meta_v1.LabelSelector{
						MatchLabels: podLabels,
					},
					NamespaceSelector: &meta_v1.LabelSelector{
						MatchLabels: namespaceLabels,
					},
				},
			},
			Ports: []networking_v1.NetworkPolicyPort{
				networking_v1.NetworkPolicyPort{
					Protocol: &tcp,
					Port:     port2,
				},
				networking_v1.NetworkPolicyPort{
					Protocol: &tcp,
					Port:     port3,
				},
			},
		},
		networking_v1.NetworkPolicyEgressRule{
			Ports: []networking_v1.NetworkPolicyPort{
				networking_v1.NetworkPolicyPort{
					Protocol: &tcp,
					Port:     port2,
				},
				networking_v1.NetworkPolicyPort{
					Protocol: &udp,
					Port:     port3,
				},
			},
		},
	}
	policy.Spec.PolicyTypes = append(policy.Spec.PolicyTypes, networking_v1.PolicyTypeEgress)

	expectedActions = append(expectedActions, pcn_types.FirewallAction{
		PodLabels:       policy.Spec.Egress[0].To[0].PodSelector.MatchLabels,
		NamespaceLabels: policy.Spec.Egress[0].To[0].NamespaceSelector.MatchLabels,
	})
	ingress, egress, _ = parser.ParsePolicyTypes(&policy.Spec)
	actions = parser.BuildActions(ingress, egress, policy.Namespace)

	for i := 0; i < len(actions); i++ {
		assert.Equal(t, actions[i].NamespaceName, expectedActions[i].NamespaceName)
		assert.Len(t, actions[i].NamespaceLabels, len(expectedActions[i].NamespaceLabels))
		assert.Len(t, actions[i].PodLabels, len(expectedActions[i].PodLabels))

		fmt.Printf("%+v\n", actions[i])
		fmt.Println("---")
	}
}

func TestBuildActionKey(t *testing.T) {
	testObj := new(MockPodController)
	parser := Init(testObj)

	namespace := "*"
	podLabels := map[string]string{}
	key := parser.buildActionKey(podLabels, nil, namespace)
	expectedKey := "nsName:*|podLabels:*"
	assert.Equal(t, expectedKey, key)

	podLabels = map[string]string{"app": "my-app", "stage": "beta", "beta-version": "1.2"}
	key = parser.buildActionKey(podLabels, nil, namespace)
	expectedKey = "nsName:*|podLabels:app=my-app,beta-version=1.2,stage=beta"
	assert.Equal(t, expectedKey, key)

	nsLabels := map[string]string{"env": "production", "app": "my-app"}
	key = parser.buildActionKey(podLabels, nsLabels, "")
	expectedKey = "nsLabels:app=my-app,env=production|podLabels:app=my-app,beta-version=1.2,stage=beta"
	assert.Equal(t, expectedKey, key)

	nsLabels = map[string]string{}
	key = parser.buildActionKey(podLabels, nsLabels, "")
	expectedKey = "nsName:*|podLabels:app=my-app,beta-version=1.2,stage=beta"
	assert.Equal(t, expectedKey, key)

	nsLabels = map[string]string{}
	podLabels = map[string]string{}
	key = parser.buildActionKey(podLabels, nsLabels, "")
	expectedKey = "nsName:*|podLabels:*"
	assert.Equal(t, expectedKey, key)
}

func TestDoesPolicyAffectPod(t *testing.T) {
	testObj := new(MockPodController)
	parser := Init(testObj)

	defaultNamespace := "default"
	policyToCheck := &networking_v1.NetworkPolicy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "policy-one",
			Namespace: defaultNamespace,
		},
		Spec: networking_v1.NetworkPolicySpec{
			PodSelector: meta_v1.LabelSelector{
				MatchExpressions: []meta_v1.LabelSelectorRequirement{
					meta_v1.LabelSelectorRequirement{
						Key: "key-one",
					},
				},
			},
		},
	}

	result := parser.DoesPolicyAffectPod(policyToCheck, nil)
	assert.False(t, result)

	pod := &core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: "not-default",
		},
	}

	policyToCheck.Spec.PodSelector = meta_v1.LabelSelector{
		MatchLabels: map[string]string{},
	}
	result = parser.DoesPolicyAffectPod(policyToCheck, pod)
	assert.False(t, result)

	pod.Namespace = defaultNamespace
	result = parser.DoesPolicyAffectPod(policyToCheck, pod)
	assert.True(t, result)

	labels := map[string]string{
		"app":     "nginx",
		"version": "3.3",
	}
	policyToCheck.Spec.PodSelector = meta_v1.LabelSelector{
		MatchLabels: labels,
	}
	result = parser.DoesPolicyAffectPod(policyToCheck, pod)
	assert.False(t, result)

	pod.Labels = map[string]string{
		"exists": "no",
	}
	result = parser.DoesPolicyAffectPod(policyToCheck, pod)
	assert.False(t, result)

	pod.Labels = map[string]string{
		"app": "nginx",
	}
	result = parser.DoesPolicyAffectPod(policyToCheck, pod)
	assert.False(t, result)

	pod.Labels = labels
	result = parser.DoesPolicyAffectPod(policyToCheck, pod)
	assert.True(t, result)

	pod.Labels["beta"] = "true"
	result = parser.DoesPolicyAffectPod(policyToCheck, pod)
	assert.True(t, result)
}
