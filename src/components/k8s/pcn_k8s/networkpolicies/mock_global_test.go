package networkpolicies

import (
	pcn_firewall "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/networkpolicies/pcn_firewall"
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"
	"github.com/stretchr/testify/mock"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"
)

const (
	ProductionNamespace   = "Production"
	BetaNamespace         = "Beta"
	StagingNamespace      = "Staging"
	TestDefaultPolicyName = "Test Default Policy"
)

//--------------------------------------
//	Namespaces
//--------------------------------------

//	-- The Labels
var ProductionNsLabels = map[string]string{
	"app":  "myapp",
	"type": "production",
}
var BetaNsLabels = map[string]string{
	"app":  "myapp",
	"type": "beta",
}

//	-- The namespaces
var ProductionNs = core_v1.Namespace{
	ObjectMeta: meta_v1.ObjectMeta{
		Name:   ProductionNamespace,
		Labels: ProductionNsLabels,
	},
}
var BetaNs = core_v1.Namespace{
	ObjectMeta: meta_v1.ObjectMeta{
		Name:   BetaNamespace,
		Labels: BetaNsLabels,
	},
}

//--------------------------------------
//	Pods
//--------------------------------------

//	-- The labels
var LabelsPodsInProduction = map[string]string{
	"app":     "myapp",
	"version": "2.3",
}
var LabelsPodsInBeta = map[string]string{
	"app":     "myapp",
	"version": "3.0.0b",
}

//	-- Pods
var PodsInProduction = []core_v1.Pod{
	core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: ProductionNamespace,
			UID:       "PRODUCTION-POD-UID-1",
			Labels:    LabelsPodsInProduction,
		},
		Status: core_v1.PodStatus{
			PodIP: "172.10.10.10",
		},
	},
	core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: ProductionNamespace,
			UID:       "PRODUCTION-POD-UID-2",
			Labels:    LabelsPodsInProduction,
		},
		Status: core_v1.PodStatus{
			PodIP: "172.20.20.20",
		},
	},
}

var PodsInBeta = []core_v1.Pod{
	core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: ProductionNamespace,
			UID:       "BETA-POD-UID-1",
			Labels:    LabelsPodsInBeta,
		},
		Status: core_v1.PodStatus{
			PodIP: "172.90.90.90",
		},
	},
}

//--------------------------------------
//	Mocked Structures
//--------------------------------------

//	Mock the pod controller
type MockPodController struct {
	mock.Mock
}

func (m *MockPodController) Run()  {}
func (m *MockPodController) Stop() {}
func (m *MockPodController) Subscribe(pcn_types.EventType, pcn_types.ObjectQuery, pcn_types.ObjectQuery, core_v1.PodPhase, func(*core_v1.Pod)) (func(), error) {
	return func() {}, nil
}
func (m *MockPodController) GetPods(pod pcn_types.ObjectQuery, ns pcn_types.ObjectQuery) ([]core_v1.Pod, error) {
	args := m.Called(pod, ns)
	return args.Get(0).([]core_v1.Pod), args.Error(1)
}

//	Mock the firewall manager
//	TODO: redo this
type MockFirewallManager struct {
	mock.Mock
}

func (m *MockFirewallManager) Link(pod *core_v1.Pod) bool {
	args := m.Called(pod)
	return args.Get(0).(bool)
}
func (m *MockFirewallManager) Unlink(pod *core_v1.Pod, then pcn_firewall.UnlinkOperation) (bool, int) {
	args := m.Called(pod, then)
	return args.Get(0).(bool), args.Get(1).(int)
}
func (m *MockFirewallManager) LinkedPods() map[k8s_types.UID]string {
	args := m.Called()
	return args.Get(0).(map[k8s_types.UID]string)
}
func (m *MockFirewallManager) IsPolicyEnforced(p string) bool {
	args := m.Called(p)
	return args.Get(0).(bool)
}
func (m *MockFirewallManager) EnforcePolicy(p string, t string, i []k8sfirewall.ChainRule, e []k8sfirewall.ChainRule, a []pcn_types.FirewallAction) {
	m.Called(p, i, e, a)
}
func (m *MockFirewallManager) CeasePolicy(c string) {
	//args := m.Called(c)
	//return args.Get(0).(error), args.Get(1).(error)
}
func (m *MockFirewallManager) Name() string {
	args := m.Called()
	return args.Get(0).(string)
}
func (m *MockFirewallManager) ForPod() k8s_types.UID {
	args := m.Called()
	return args.Get(0).(k8s_types.UID)
}
func (m *MockFirewallManager) RemoveRules(p string, r []k8sfirewall.ChainRule) []k8sfirewall.ChainRule {
	args := m.Called(p, r)
	return args.Get(0).([]k8sfirewall.ChainRule)
}
func (m *MockFirewallManager) RemoveIPReferences(p string, t string) {
	//args := m.Called(p, t)
}
func (m *MockFirewallManager) Destroy() error {
	args := m.Called()
	return args.Get(0).(error)
}
