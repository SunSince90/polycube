package pcnfirewall

import (
	"testing"

	k8s_types "k8s.io/apimachinery/pkg/types"

	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	log "github.com/sirupsen/logrus"

	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"
	"github.com/stretchr/testify/assert"
)

func TestBuildIDs(t *testing.T) {
	prevIngressID := int32(5)
	prevEgressID := int32(3)
	f := &DeployedFirewall{
		ingressID:    prevIngressID,
		egressID:     prevEgressID,
		ingressRules: map[string]map[int32]k8sfirewall.ChainRule{},
		egressRules:  map[string]map[int32]k8sfirewall.ChainRule{},
		ingressIPs:   map[string]map[int32]string{},
		egressIPs:    map[string]map[int32]string{},
	}

	ingressRules := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{},
		k8sfirewall.ChainRule{},
		k8sfirewall.ChainRule{},
	}
	egressRules := []k8sfirewall.ChainRule{
		k8sfirewall.ChainRule{},
	}
	policyName := "policy"
	targetAddress := "10.10.10.10"

	in, eg := f.buildIDs(policyName, targetAddress, ingressRules, egressRules)
	assert.Equal(t, prevIngressID+int32(len(ingressRules)), f.ingressID)
	assert.Equal(t, prevEgressID+int32(len(egressRules)), f.egressID)
	assert.Len(t, f.ingressRules[policyName], len(ingressRules))
	assert.Len(t, f.egressRules[policyName], len(egressRules))

	i := int32(0)
	for ; i < int32(len(in)); i++ {
		assert.Equal(t, prevIngressID+i, in[i].Id)
		assert.NotEmpty(t, f.ingressRules[policyName][in[i].Id])
		assert.Equal(t, f.ingressIPs[targetAddress][in[i].Id], policyName)
	}

	i = int32(0)
	for ; i < int32(len(eg)); i++ {
		assert.Equal(t, prevEgressID+i, eg[i].Id)
		assert.NotEmpty(t, f.egressRules[policyName][eg[i].Id])
		assert.Equal(t, f.egressIPs[targetAddress][eg[i].Id], policyName)
	}
}

func TestIncreaseCount(t *testing.T) {
	prevIngressCount := 0
	prevEgressCount := 0
	f := &DeployedFirewall{
		ingressPoliciesCount: prevIngressCount,
		egressPoliciesCount:  prevEgressCount,
		ingressDefaultAction: pcn_types.ActionForward,
		egressDefaultAction:  pcn_types.ActionForward,
	}

	//	Ingress
	result := f.increaseCount("ingress")
	assert.Equal(t, f.ingressPoliciesCount, 1)
	assert.Equal(t, f.ingressDefaultAction, pcn_types.ActionDrop)
	assert.Zero(t, f.egressPoliciesCount)
	assert.Equal(t, f.egressDefaultAction, pcn_types.ActionForward)
	assert.True(t, result)

	//	Egress
	result = f.increaseCount("egress")
	assert.Equal(t, f.ingressPoliciesCount, 1)
	assert.Equal(t, f.ingressDefaultAction, pcn_types.ActionDrop)
	assert.Equal(t, f.egressPoliciesCount, 1)
	assert.Equal(t, f.egressDefaultAction, pcn_types.ActionDrop)
	assert.True(t, result)

	//	Not changing ingress
	result = f.increaseCount("ingress")
	assert.Equal(t, f.ingressPoliciesCount, 2)
	assert.Equal(t, f.ingressDefaultAction, pcn_types.ActionDrop)
	assert.False(t, result)

	//	Not changing egress
	result = f.increaseCount("egress")
	assert.Equal(t, f.egressPoliciesCount, 2)
	assert.Equal(t, f.egressDefaultAction, pcn_types.ActionDrop)
	assert.False(t, result)
}

func TestDecreseCount(t *testing.T) {
	prevIngressCount := 2
	prevEgressCount := 2
	f := &DeployedFirewall{
		ingressPoliciesCount: prevIngressCount,
		egressPoliciesCount:  prevEgressCount,
		ingressDefaultAction: pcn_types.ActionDrop,
		egressDefaultAction:  pcn_types.ActionDrop,
	}

	//	Ingress
	result := f.decreaseCount("ingress")
	assert.Equal(t, f.ingressPoliciesCount, 1)
	assert.Equal(t, f.ingressDefaultAction, pcn_types.ActionDrop)
	assert.Equal(t, f.egressPoliciesCount, 2)
	assert.Equal(t, f.egressDefaultAction, pcn_types.ActionDrop)
	assert.False(t, result)

	//	Egress
	result = f.decreaseCount("egress")
	assert.Equal(t, f.ingressPoliciesCount, 1)
	assert.Equal(t, f.ingressDefaultAction, pcn_types.ActionDrop)
	assert.Equal(t, f.egressPoliciesCount, 1)
	assert.Equal(t, f.egressDefaultAction, pcn_types.ActionDrop)
	assert.False(t, result)

	//	Changing ingress
	result = f.decreaseCount("ingress")
	assert.Zero(t, f.ingressPoliciesCount)
	assert.Equal(t, f.ingressDefaultAction, pcn_types.ActionForward)
	assert.True(t, result)

	//	Not changing egress
	result = f.decreaseCount("egress")
	assert.Zero(t, f.egressPoliciesCount)
	assert.Equal(t, f.egressDefaultAction, pcn_types.ActionForward)
	assert.True(t, result)
}

func TestIsPolicyEnforced(t *testing.T) {
	f := &DeployedFirewall{
		ingressRules: map[string]map[int32]k8sfirewall.ChainRule{
			"policy":              map[int32]k8sfirewall.ChainRule{},
			"policy-only-ingress": map[int32]k8sfirewall.ChainRule{},
		},
		egressRules: map[string]map[int32]k8sfirewall.ChainRule{
			"policy":             map[int32]k8sfirewall.ChainRule{},
			"policy-only-egress": map[int32]k8sfirewall.ChainRule{},
		},
	}

	result := f.IsPolicyEnforced("policy")
	assert.True(t, result)

	result = f.IsPolicyEnforced("missing-policy")
	assert.False(t, result)

	result = f.IsPolicyEnforced("policy-only-ingress")
	assert.True(t, result)

	result = f.IsPolicyEnforced("policy-only-egress")
	assert.True(t, result)
}

func TestLink(t *testing.T) {
	f := &DeployedFirewall{
		fwAPI:      MockAPI,
		log:        log.New(),
		linkedPods: map[k8s_types.UID]string{},
		ingressRules: map[string]map[int32]k8sfirewall.ChainRule{
			"policy-one": map[int32]k8sfirewall.ChainRule{
				2: k8sfirewall.ChainRule{
					Id: 2,
					// ...
				},
				4: k8sfirewall.ChainRule{
					Id: 4,
					// ...
				},
			},
			"policy-two": map[int32]k8sfirewall.ChainRule{
				5: k8sfirewall.ChainRule{
					Id: 5,
					// ...
				},
				6: k8sfirewall.ChainRule{
					Id: 6,
					// ...
				},
				7: k8sfirewall.ChainRule{
					Id: 7,
					// ...
				},
			},
		},
		egressRules: map[string]map[int32]k8sfirewall.ChainRule{
			"policy-one": map[int32]k8sfirewall.ChainRule{
				3: k8sfirewall.ChainRule{
					Id: 3,
					// ...
				},
			},
			"policy-two": map[int32]k8sfirewall.ChainRule{
				1: k8sfirewall.ChainRule{
					Id: 1,
					// ...
				},
			},
		},
	}
	pod := &core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			UID: "POD-UID-1",
		},
		Status: core_v1.PodStatus{
			PodIP: "10.10.10.10",
		},
	}
	MockAPI.On("ReadFirewallUuidByID", nil, "fw-"+pod.Status.PodIP).Return("", nil, nil)

	result := f.Link(pod)
	assert.True(t, result)

	result = f.Link(pod)
	assert.False(t, result)

	//	Comment the second part to test the rest of this function.
	//	Did not test it because it just makes use of other function which I didn't want to mock. :P
}
