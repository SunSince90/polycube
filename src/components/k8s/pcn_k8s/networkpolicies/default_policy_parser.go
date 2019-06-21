package networkpolicies

import (
	"errors"
	"fmt"
	"sync"

	pcn_controllers "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/controllers"
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"

	log "github.com/sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	networking_v1 "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PcnDefaultPolicyParser is the default policy (e.g.: kubernetes') parser
type PcnDefaultPolicyParser interface {
	ParsePolicyTypes(*networking_v1.NetworkPolicySpec) ([]networking_v1.NetworkPolicyIngressRule, []networking_v1.NetworkPolicyEgressRule, string)
	ParseIPBlock(*networking_v1.IPBlock, string) pcn_types.ParsedRules
	ParsePorts([]networking_v1.NetworkPolicyPort) []pcn_types.ProtoPort
	ParseSelectors(*meta_v1.LabelSelector, *meta_v1.LabelSelector, string, string) (pcn_types.ParsedRules, error)
	GetConnectionTemplate(string, string, string, string, []pcn_types.ProtoPort) pcn_types.ParsedRules
}

// DefaultPolicyParser is the implementation of the default parser
type DefaultPolicyParser struct {
	podController      pcn_controllers.PodController
	supportedProtocols string
	log                *log.Logger
}

// newDefaultPolicyParser starts a new parser
func newDefaultPolicyParser(podController pcn_controllers.PodController) *DefaultPolicyParser {
	return &DefaultPolicyParser{
		podController:      podController,
		supportedProtocols: "TCP,UDP",
		log:                log.New(),
	}
}

// insertPorts will complete the rules by adding the appropriate ports
func (d *DefaultPolicyParser) insertPorts(generatedIngressRules, generatedEgressRules []k8sfirewall.ChainRule, generatedPorts []pcn_types.ProtoPort) pcn_types.ParsedRules {

	//	Don't make me go through this if there are no ports
	if len(generatedPorts) < 1 {
		return pcn_types.ParsedRules{
			Ingress: generatedIngressRules,
			Egress:  generatedEgressRules,
		}
	}

	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}

	var waitForChains sync.WaitGroup
	waitForChains.Add(2)

	go func() {
		defer waitForChains.Done()
		//	Finally, for each parsed rule, apply the ports that have been found
		//	But only if you have at least one port
		for i := 0; i < len(generatedIngressRules); i++ {
			rule := generatedIngressRules[i]
			for _, generatedPort := range generatedPorts {
				edited := rule
				//edited.Dport = generatedPort.Port
				edited.Sport = generatedPort.Port
				edited.L4proto = generatedPort.Protocol
				parsed.Ingress = append(parsed.Ingress, edited)
			}
		}
	}()

	go func() {
		defer waitForChains.Done()
		for i := 0; i < len(generatedEgressRules); i++ {
			rule := generatedEgressRules[i]
			for _, generatedPort := range generatedPorts {
				edited := rule
				//edited.Sport = generatedPort.Port
				edited.Dport = generatedPort.Port
				edited.L4proto = generatedPort.Protocol
				parsed.Egress = append(parsed.Egress, edited)
			}
		}
	}()
	waitForChains.Wait()

	return parsed
}

// ParsePolicyTypes will parse the policy type of the policy and return the appropriate rules and the type of this policy
func (d *DefaultPolicyParser) ParsePolicyTypes(policySpec *networking_v1.NetworkPolicySpec) ([]networking_v1.NetworkPolicyIngressRule, []networking_v1.NetworkPolicyEgressRule, string) {

	var ingress []networking_v1.NetworkPolicyIngressRule
	var egress []networking_v1.NetworkPolicyEgressRule

	ingress = nil
	egress = nil
	policyType := "*"

	//	What if spec is not even there?
	if policySpec == nil {
		return nil, nil, "ingress"
	}

	//	Documentation is not very specific about the possibility of PolicyTypes being [], so I made this dumb piece of code just in case
	if policySpec.PolicyTypes == nil {
		ingress = policySpec.Ingress
		policyType = "ingress"
	} else {
		if len(policySpec.PolicyTypes) < 1 {
			ingress = policySpec.Ingress
			policyType = "ingress"
		} else {
			policyTypes := policySpec.PolicyTypes

			for _, val := range policyTypes {
				//	Can't use if-else because user may disable validation and insert
				//	trash values
				if val == networking_v1.PolicyTypeIngress {
					ingress = policySpec.Ingress
					policyType = "ingress"
				}
				if val == networking_v1.PolicyTypeEgress {
					egress = policySpec.Egress
					policyType = "egress"
				}
			}

			if ingress != nil && egress != nil {
				policyType = "*"
			}
		}
	}

	return ingress, egress, policyType
}

// ParseIPBlock will parse the IPBlock from the network policy and return the correct rules
func (d *DefaultPolicyParser) ParseIPBlock(block *networking_v1.IPBlock, k8sDirection string) pcn_types.ParsedRules {

	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}

	//	Actually, these two cannot happen with kubernetes
	if block == nil {
		return parsed
	}

	if len(block.CIDR) < 1 {
		return parsed
	}

	//	Add the default one
	cidrRules := pcn_types.ParsedRules{}
	if k8sDirection == "ingress" {
		cidrRules = d.GetConnectionTemplate(k8sDirection, block.CIDR, "", pcn_types.ActionForward, []pcn_types.ProtoPort{})
	} else {
		cidrRules = d.GetConnectionTemplate(k8sDirection, "", block.CIDR, pcn_types.ActionForward, []pcn_types.ProtoPort{})
	}

	parsed.Ingress = append(parsed.Ingress, cidrRules.Ingress...)
	parsed.Egress = append(parsed.Egress, cidrRules.Egress...)

	//	Loop through all exceptions
	for _, exception := range block.Except {
		exceptionRule := k8sfirewall.ChainRule{
			Action:    pcn_types.ActionDrop,
			Conntrack: pcn_types.ConnTrackNew,
		}

		if k8sDirection == "ingress" {
			//exceptionRule.Src = exception
			exceptionRule.Dst = exception
			parsed.Ingress = append(parsed.Ingress, exceptionRule)
		} else {
			exceptionRule.Src = exception
			//exceptionRule.Dst = exception
			parsed.Egress = append(parsed.Egress, exceptionRule)
		}
	}

	return parsed
}

// ParsePorts will parse the protocol and port and get the desired ports in a format that the firewall will understand
func (d *DefaultPolicyParser) ParsePorts(ports []networking_v1.NetworkPolicyPort) []pcn_types.ProtoPort {

	//	Init
	generatedPorts := []pcn_types.ProtoPort{}

	for _, port := range ports {

		//	If protocol is nil, then we have to get all protocols
		if port.Protocol == nil {

			//	If the port is not nil, default port is not 0
			var defaultPort int32
			if port.Port != nil {
				defaultPort = int32(port.Port.IntValue())
			}

			generatedPorts = append(generatedPorts, pcn_types.ProtoPort{
				Port: defaultPort,
			})

		} else {
			//	else parse the protocol
			supported, proto, port := d.parseProtocolAndPort(port)

			//	Our firewall does not support SCTP, so we check if protocol is supported
			if supported {
				generatedPorts = append(generatedPorts, pcn_types.ProtoPort{
					Protocol: proto,
					Port:     port,
				})
			}
		}
	}

	return generatedPorts
}

// parseProtocolAndPort parses the protocol in order to know if it is supported by the firewall manager
func (d *DefaultPolicyParser) parseProtocolAndPort(pp networking_v1.NetworkPolicyPort) (bool, string, int32) {

	//	Not sure if port can be nil, but it doesn't harm to do a simple reset
	var port int32
	if pp.Port != nil {
		port = int32(pp.Port.IntValue())
	}

	//	TCP?
	if *pp.Protocol == core_v1.ProtocolTCP {
		return true, "TCP", port
	}

	//	UDP?
	if *pp.Protocol == core_v1.ProtocolUDP {
		return true, "UDP", port
	}

	//	Not supported ¯\_(ツ)_/¯
	return false, "", 0
}

// ParseSelectors will parse the PodSelector or the NameSpaceSelector of a policy.
// It returns the appropriate rules for the specified pods
func (d *DefaultPolicyParser) ParseSelectors(podSelector, namespaceSelector *meta_v1.LabelSelector, namespace, direction string) (pcn_types.ParsedRules, error) {

	//	init
	rules := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}

	//	First build the query
	podQuery, nsQuery, err := d.buildPodQueries(podSelector, namespaceSelector, namespace)
	if err != nil {
		return rules, err
	}

	//	Now get the pods
	podsFound, err := d.podController.GetPods(podQuery, nsQuery)
	if err != nil {
		return rules, fmt.Errorf("Error while trying to get pods %s", err.Error())
	}

	//	Now build the pods
	for _, pod := range podsFound {
		parsed := pcn_types.ParsedRules{}
		if direction == "ingress" {
			parsed = d.GetConnectionTemplate(direction, pod.Status.PodIP, "", pcn_types.ActionForward, []pcn_types.ProtoPort{})
		} else {
			parsed = d.GetConnectionTemplate(direction, "", pod.Status.PodIP, pcn_types.ActionForward, []pcn_types.ProtoPort{})
		}

		rules.Ingress = append(rules.Ingress, parsed.Ingress...)
		rules.Egress = append(rules.Egress, parsed.Egress...)
	}

	return rules, nil
}

// buildPodQueries builds the queries to be directed to the pod controller, in order to get the desired pods.
func (d *DefaultPolicyParser) buildPodQueries(podSelector, namespaceSelector *meta_v1.LabelSelector, namespace string) (pcn_types.ObjectQuery, pcn_types.ObjectQuery, error) {

	//	Init
	queryPod := pcn_types.ObjectQuery{}
	queryNs := pcn_types.ObjectQuery{}

	//	If podSelector is nil: select everything and then block
	//	If podSelector is empty (len = 0): select everything and then forward
	//	NOTE: blocking everything is not the same as setting a default rule to block anything!
	//	Because that way we would also be preventing external connections from accessing our pods.
	//	Instead, we need to block all pods individually, so we can't solve it by just creating a default rule:
	//	we cannot know if user will deploy a policy to allow ipblocks in advance.

	//	Build the query
	if podSelector != nil {

		//	This is not supported yet...
		if podSelector.MatchExpressions != nil {
			return pcn_types.ObjectQuery{}, pcn_types.ObjectQuery{}, errors.New("MatchExpressions on pod selector is not supported yet")
		}

		//	Empty labels means "select everything"
		//	Nil labels means do not select anything. Which, for us, means deny access to those pods (see below)
		if len(podSelector.MatchLabels) < 1 {
			queryPod = pcn_types.ObjectQuery{
				By:   "name",
				Name: "*",
			}
		} else {
			queryPod = pcn_types.ObjectQuery{
				By:     "labels",
				Labels: podSelector.MatchLabels,
			}
		}
	} else {
		queryPod = pcn_types.ObjectQuery{
			By:   "name",
			Name: "*",
		}
	}

	//	Namespace selector
	if namespaceSelector != nil {

		//	Match expressions?
		if namespaceSelector.MatchExpressions != nil {
			//	This is not supported yet...
			return pcn_types.ObjectQuery{}, pcn_types.ObjectQuery{}, errors.New("MatchExpressions on namespace selector is not supported yet")
		}

		if len(namespaceSelector.MatchLabels) > 0 {
			//	Parse the match labels (like for the pod)
			queryNs = pcn_types.ObjectQuery{
				By:     "labels",
				Labels: namespaceSelector.MatchLabels,
			}
		} else {
			//	No labels: as per documentation, this means ALL namespaces
			queryNs = pcn_types.ObjectQuery{
				By:   "name",
				Name: "*",
			}
		}
	} else {
		//	If namespace selector is nil, we're going to use the one we found on the policy
		if len(namespace) < 0 {
			return pcn_types.ObjectQuery{}, pcn_types.ObjectQuery{}, errors.New("Namespace name not provided")
		}

		queryNs = pcn_types.ObjectQuery{
			By:   "name",
			Name: namespace,
		}
	}

	return queryPod, queryNs, nil
}

// GetConnectionTemplate builds a rule template based on connections
func (d *DefaultPolicyParser) GetConnectionTemplate(direction, src, dst, action string, ports []pcn_types.ProtoPort) pcn_types.ParsedRules {

	twoRules := make([]k8sfirewall.ChainRule, 2)
	oneRule := make([]k8sfirewall.ChainRule, 1)

	twoRules[0] = k8sfirewall.ChainRule{
		/*Src:       src,
		Dst:       dst,*/
		Src:       dst,
		Dst:       src,
		Action:    action,
		Conntrack: pcn_types.ConnTrackNew,
	}
	twoRules[1] = k8sfirewall.ChainRule{
		/*Src:       src,
		Dst:       dst,*/
		Src:       dst,
		Dst:       src,
		Action:    action,
		Conntrack: pcn_types.ConnTrackEstablished,
	}
	oneRule[0] = k8sfirewall.ChainRule{
		Src: src,
		Dst: dst,
		/*Src:       dst,
		Dst:       src,*/
		Action:    action,
		Conntrack: pcn_types.ConnTrackEstablished,
	}

	if direction == "ingress" {

		if len(ports) > 0 {
			withPorts := d.insertPorts(twoRules, oneRule, ports)
			twoRules, oneRule = withPorts.Ingress, withPorts.Egress
		}

		return pcn_types.ParsedRules{
			Ingress: twoRules,
			Egress:  oneRule,
		}
	}

	if len(ports) > 0 {
		withPorts := d.insertPorts(oneRule, twoRules, ports)
		oneRule, twoRules = withPorts.Ingress, withPorts.Egress
	}

	return pcn_types.ParsedRules{
		Ingress: oneRule,
		Egress:  twoRules,
	}

}
