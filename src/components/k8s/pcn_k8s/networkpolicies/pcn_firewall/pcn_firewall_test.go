package pcnfirewall

import (
	"fmt"
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
	f := &FirewallManager{
		ingressID:    prevIngressID,
		egressID:     prevEgressID,
		ingressRules: map[string]map[int32]k8sfirewall.ChainRule{},
		egressRules:  map[string]map[int32]k8sfirewall.ChainRule{},
		ingressIPs:   map[string]map[int32]string{},
		egressIPs:    map[string]map[int32]string{},
		log:          log.New(),
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
	f := &FirewallManager{
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
	f := &FirewallManager{
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
	f := &FirewallManager{
		policyTypes: map[string]string{
			"policy":              "*",
			"policy-only-ingress": "ingress",
			"policy-only-egress":  "egress",
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

func TestReactToTerminated(t *testing.T) {
	policyOne := "policy-one"
	policyTwo := "policy-two"
	f := &FirewallManager{
		fwAPI:      MockAPI,
		log:        log.New(),
		linkedPods: map[k8s_types.UID]string{},
		ingressRules: map[string]map[int32]k8sfirewall.ChainRule{
			policyOne: map[int32]k8sfirewall.ChainRule{
				2: k8sfirewall.ChainRule{
					Id:  2,
					Src: "10.10.10.10",
				},
				4: k8sfirewall.ChainRule{
					Id:  4,
					Src: "10.10.10.10",
				},
				8: k8sfirewall.ChainRule{
					Id:  8,
					Src: "11.11.11.11",
				},
			},
			policyTwo: map[int32]k8sfirewall.ChainRule{
				5: k8sfirewall.ChainRule{
					Id:  5,
					Src: "10.10.10.10",
				},
				6: k8sfirewall.ChainRule{
					Id:  6,
					Src: "11.11.11.11",
				},
				7: k8sfirewall.ChainRule{
					Id:  7,
					Src: "12.12.12.12",
				},
			},
		},
		ingressIPs: map[string]map[int32]string{
			"10.10.10.10": map[int32]string{
				int32(2): policyOne,
				int32(4): policyOne,
				int32(5): policyTwo,
			},
			"11.11.11.11": map[int32]string{
				int32(8): policyOne,
				int32(6): policyTwo,
			},
			"12.12.12.12": map[int32]string{
				int32(7): policyTwo,
			},
		},
		egressRules: map[string]map[int32]k8sfirewall.ChainRule{
			policyOne: map[int32]k8sfirewall.ChainRule{
				3: k8sfirewall.ChainRule{
					Id:  3,
					Dst: "10.10.10.10",
				},
			},
			policyTwo: map[int32]k8sfirewall.ChainRule{
				1: k8sfirewall.ChainRule{
					Id:  1,
					Dst: "11.11.11.11",
				},
			},
		},
		egressIPs: map[string]map[int32]string{
			"10.10.10.10": map[int32]string{
				int32(3): policyOne,
			},
			"11.11.11.11": map[int32]string{
				int32(1): policyTwo,
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

	f.reactToPod(pcn_types.Delete, pod, "")

	assert.Empty(t, f.ingressIPs[pod.Status.PodIP])
	assert.Empty(t, f.egressIPs[pod.Status.PodIP])

	assert.Empty(t, f.ingressRules[policyOne][int32(2)])
	assert.Empty(t, f.ingressRules[policyOne][int32(4)])
	assert.Empty(t, f.ingressRules[policyTwo][int32(5)])
	assert.NotZero(t, len(f.ingressRules[policyOne]))
	assert.NotZero(t, len(f.ingressRules[policyTwo]))

	assert.Empty(t, f.egressRules[policyOne][int32(3)])
	assert.Zero(t, len(f.egressRules[policyOne]))
	assert.NotZero(t, len(f.egressRules[policyTwo]))

}

func TestDeleteAllPolicyRules(t *testing.T) {
	policyOne := "policy-one"
	policyTwo := "policy-two"
	f := &FirewallManager{
		fwAPI:      MockAPI,
		log:        log.New(),
		linkedPods: map[k8s_types.UID]string{},
		ingressRules: map[string]map[int32]k8sfirewall.ChainRule{
			policyOne: map[int32]k8sfirewall.ChainRule{
				2: k8sfirewall.ChainRule{
					Id:  2,
					Src: "10.10.10.10",
				},
				4: k8sfirewall.ChainRule{
					Id:  4,
					Src: "10.10.10.10",
				},
				8: k8sfirewall.ChainRule{
					Id:  8,
					Src: "11.11.11.11",
				},
			},
			policyTwo: map[int32]k8sfirewall.ChainRule{
				5: k8sfirewall.ChainRule{
					Id:  5,
					Src: "10.10.10.10",
				},
				6: k8sfirewall.ChainRule{
					Id:  6,
					Src: "11.11.11.11",
				},
				7: k8sfirewall.ChainRule{
					Id:  7,
					Src: "12.12.12.12",
				},
			},
		},
		ingressIPs: map[string]map[int32]string{
			"10.10.10.10": map[int32]string{
				int32(2): policyOne,
				int32(4): policyOne,
				int32(5): policyTwo,
			},
			"11.11.11.11": map[int32]string{
				int32(8): policyOne,
				int32(6): policyTwo,
			},
			"12.12.12.12": map[int32]string{
				int32(7): policyTwo,
			},
		},
		egressRules: map[string]map[int32]k8sfirewall.ChainRule{
			policyOne: map[int32]k8sfirewall.ChainRule{
				3: k8sfirewall.ChainRule{
					Id:  3,
					Dst: "10.10.10.10",
				},
			},
			policyTwo: map[int32]k8sfirewall.ChainRule{
				1: k8sfirewall.ChainRule{
					Id:  1,
					Dst: "11.11.11.11",
				},
			},
		},
		egressIPs: map[string]map[int32]string{
			"10.10.10.10": map[int32]string{
				int32(3): policyOne,
			},
			"11.11.11.11": map[int32]string{
				int32(1): policyTwo,
			},
		},
	}

	f.deleteAllPolicyRules(policyOne)
	assert.Empty(t, f.ingressRules[policyOne])
	assert.NotZero(t, len(f.ingressRules))
	assert.Empty(t, f.egressRules[policyOne])
	assert.NotZero(t, len(f.egressRules))

	assert.NotEmpty(t, f.ingressIPs["10.10.10.10"])
	assert.NotEmpty(t, f.ingressIPs["11.11.11.11"])
	assert.Empty(t, f.ingressIPs["10.10.10.10"][2])
	assert.Empty(t, f.ingressIPs["10.10.10.10"][4])
	assert.Empty(t, f.ingressIPs["11.11.11.11"][8])

	assert.Empty(t, f.egressIPs["10.10.10.10"])
	_, exists := f.egressIPs["10.10.10.10"]
	assert.False(t, exists)
}

func TestDeleteAllPolicyTemplates(t *testing.T) {
	policyOne := "policy-one"
	policyTwo := "policy-two"
	redis := "nsName:production|podLabels:app=redis,version=2.0"
	apache := "nsName:production|podLabels:app=apache,version=2.5"
	f := &FirewallManager{
		fwAPI:      MockAPI,
		log:        log.New(),
		linkedPods: map[k8s_types.UID]string{},
		policyActions: map[string]*subscriptions{
			redis: &subscriptions{
				actions: map[string]*pcn_types.ParsedRules{
					policyOne: &pcn_types.ParsedRules{},
				},
				unsubscriptors: []func(){
					func() {
						fmt.Println("redis update unsubscriptor")
					},
					func() {
						fmt.Println("redis delete unsubscriptor")
					},
				},
			},
			apache: &subscriptions{
				actions: map[string]*pcn_types.ParsedRules{
					policyOne: &pcn_types.ParsedRules{},
					policyTwo: &pcn_types.ParsedRules{},
				},
				unsubscriptors: []func(){
					func() {
						fmt.Println("apache update unsubscriptor")
					},
					func() {
						fmt.Println("apache update unsubscriptor")
					},
				},
			},
		},
	}

	f.deleteAllPolicyTemplates(policyOne)

	assert.NotEmpty(t, f.policyActions[apache])
	assert.NotZero(t, len(f.policyActions[apache].actions))
	_, exists := f.policyActions[apache].actions[policyOne]
	assert.False(t, exists)
	assert.Len(t, f.policyActions[apache].unsubscriptors, 2)

	_, exists = f.policyActions[redis]
	assert.False(t, exists)
}

func TestDestroy(t *testing.T) {
	policyOne := "policy-one"
	policyTwo := "policy-two"
	redis := "nsName:production|podLabels:app=redis,version=2.0"
	apache := "nsName:production|podLabels:app=apache,version=2.5"
	f := &FirewallManager{
		fwAPI:      MockAPI,
		log:        log.New(),
		linkedPods: map[k8s_types.UID]string{},
		policyActions: map[string]*subscriptions{
			redis: &subscriptions{
				actions: map[string]*pcn_types.ParsedRules{
					policyOne: &pcn_types.ParsedRules{},
				},
				unsubscriptors: []func(){
					func() {
						fmt.Println("redis update unsubscriptor")
					},
					func() {
						fmt.Println("redis delete unsubscriptor")
					},
				},
			},
			apache: &subscriptions{
				actions: map[string]*pcn_types.ParsedRules{
					policyOne: &pcn_types.ParsedRules{},
					policyTwo: &pcn_types.ParsedRules{},
				},
				unsubscriptors: []func(){
					func() {
						fmt.Println("apache update unsubscriptor")
					},
					func() {
						fmt.Println("apache update unsubscriptor")
					},
				},
			},
		},
	}

	f.Destroy()

	assert.Empty(t, f.policyActions)
}
