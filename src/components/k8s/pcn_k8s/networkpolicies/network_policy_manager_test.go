package networkpolicies

import (
	"fmt"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"

	pcn_firewall "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/networkpolicies/pcn_firewall"

	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"

	pcn_controllers "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/controllers"
)

func TestImplode(t *testing.T) {
	manager := &NetworkPolicyManager{}

	//	Case 1
	labels := map[string]string{"app": "redis", "z": "b", "b": "z"}
	ns := "production"
	result := manager.implode(labels, ns)
	expected := "production|app=redis,b=z,z=b"
	assert.Equal(t, expected, result)

	//	Case 2
	labels = map[string]string{}
	ns = "beta"
	result = manager.implode(labels, ns)
	expected = "beta|"
	assert.Equal(t, expected, result)
}

func TestGetOrCreateFirewall(t *testing.T) {
	oldFunc := startFirewall
	defer func() { startFirewall = oldFunc }()
	notLinkedPod := &core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			UID: "POD-NOTLINKED-UID-100",
			Labels: map[string]string{
				"linked": "no",
			},
			Namespace: "not-linked-namespace",
		},
		Status: core_v1.PodStatus{
			PodIP: "100.100.100.100",
		},
	}
	alreadyLinkedPod := &core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			UID: "POD-LINKED-UID-110",
			Labels: map[string]string{
				"linked": "yes",
			},
			Namespace: "linked-namespace",
		},
		Status: core_v1.PodStatus{
			PodIP: "110.110.110.110",
		},
	}
	updatedLinkedPod := &core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			UID: "POD-LINKED-UID-120",
			Labels: map[string]string{
				"linked":  "yes",
				"updated": "yes",
			},
			Namespace: "linked-namespace",
		},
		Status: core_v1.PodStatus{
			PodIP: "120.120.120.120",
		},
	}
	startFirewall = func(API k8sfirewall.FirewallAPI, podController pcn_controllers.PodController, name, namespace string, labels map[string]string) pcn_firewall.PcnFirewall {
		obj := new(MockFirewallManager)
		obj.On("Unlink", updatedLinkedPod, pcn_firewall.CleanFirewall).Return(true, 1)
		return obj
	}

	manager := &NetworkPolicyManager{
		localFirewalls: map[string]pcn_firewall.PcnFirewall{
			"linked-namespace|linked=yes": startFirewall(nil, nil, "linked-namespace|linked=yes", "linked-namespace", map[string]string{"linked": "yes"}),
		},
		flaggedForDeletion: map[string]*time.Timer{},
		linkedPods: map[k8s_types.UID]string{
			alreadyLinkedPod.UID: "linked-namespace|linked=yes",
			updatedLinkedPod.UID: "linked-namespace|linked=yes",
		},
	}

	//	Case 1: never seen pod
	_, r := manager.getOrCreateFirewallManager(notLinkedPod)
	assert.True(t, r)
	fwName := manager.implode(notLinkedPod.Labels, notLinkedPod.Namespace)
	assert.NotEmpty(t, manager.localFirewalls[fwName])

	//	Case 2: pod already seen
	_, r = manager.getOrCreateFirewallManager(alreadyLinkedPod)
	assert.False(t, r)
	fwName = manager.implode(alreadyLinkedPod.Labels, alreadyLinkedPod.Namespace)
	assert.NotEmpty(t, manager.localFirewalls[fwName])

	//	Case 3: pod has changed labels
	_, r = manager.getOrCreateFirewallManager(updatedLinkedPod)
	assert.True(t, r)
	updatedFwKey := manager.implode(updatedLinkedPod.Labels, updatedLinkedPod.Namespace)
	assert.Empty(t, manager.linkedPods[updatedLinkedPod.UID])
	assert.NotEmpty(t, manager.localFirewalls[fwName])
	assert.NotEmpty(t, manager.localFirewalls[updatedFwKey])
}

func TestToggleDeletionFlag(t *testing.T) {
	toBeDeleted := "to-be-deleted"
	manager := &NetworkPolicyManager{
		flaggedForDeletion: map[string]*time.Timer{},
		localFirewalls: map[string]pcn_firewall.PcnFirewall{
			toBeDeleted: new(MockFirewallManager),
		},
	}

	manager.flagForDeletion(toBeDeleted)
	assert.NotEmpty(t, manager.flaggedForDeletion[toBeDeleted])

	manager.unflagForDeletion(toBeDeleted)
	assert.Empty(t, manager.flaggedForDeletion[toBeDeleted])

	//	Test timer is executed correctly
	defer func() {
		fmt.Println("Sleeper: Going to sleep for 7 seconds")
		time.Sleep(time.Second * 7)
		fmt.Println("Sleeper: Woken Up! Let's check.")
		assert.Empty(t, manager.localFirewalls[toBeDeleted])
		assert.Empty(t, manager.flaggedForDeletion[toBeDeleted])
	}()
	manager.flaggedForDeletion[toBeDeleted] = time.AfterFunc(time.Second*3, func() {
		fmt.Println("Deleter: 3 seconds passed: time out! Going to delete the firewall manager")
		manager.deleteFirewallManager(toBeDeleted)
	})
}

func TestManageDeletedPod(t *testing.T) {
	fwNotExists := &core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			UID: "POD-NOFW-UID-100",
			Labels: map[string]string{
				"fw": "absent",
			},
			Namespace: "not-linked-namespace",
		},
		Status: core_v1.PodStatus{
			PodIP: "100.100.100.100",
		},
	}
	notLinked := &core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			UID: "POD-NOTLINKED-UID-110",
			Labels: map[string]string{
				"linked": "no",
			},
			Namespace: "not-linked-namespace",
		},
		Status: core_v1.PodStatus{
			PodIP: "110.110.110.110",
		},
	}
	alreadyLinkedPod := &core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			UID: "POD-LINKED-UID-120",
			Labels: map[string]string{
				"linked": "yes",
			},
			Namespace: "linked-namespace",
		},
		Status: core_v1.PodStatus{
			PodIP: "120.120.120.120",
		},
	}
	obj := new(MockFirewallManager)
	obj.On("Unlink", notLinked, pcn_firewall.DestroyFirewall).Return(false, 1)
	obj.On("Unlink", alreadyLinkedPod, pcn_firewall.DestroyFirewall).Return(true, 1)

	manager := &NetworkPolicyManager{
		localFirewalls: map[string]pcn_firewall.PcnFirewall{
			"not-linked-namespace|linked=no": obj,
			"linked-namespace|linked=yes":    obj,
		},
		flaggedForDeletion: map[string]*time.Timer{},
		linkedPods: map[k8s_types.UID]string{
			notLinked.UID:        "not-linked-namespace|linked=no",
			alreadyLinkedPod.UID: "linked-namespace|linked=yes",
		},
		log: log.New(),
	}

	manager.manageDeletedPod(fwNotExists)

	manager.manageDeletedPod(notLinked)
	assert.Empty(t, manager.linkedPods[notLinked.UID])

	manager.manageDeletedPod(alreadyLinkedPod)
	assert.Empty(t, manager.linkedPods[alreadyLinkedPod.UID])
}
