package controllers

import (
	"strings"

	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	"k8s.io/client-go/tools/cache"
)

// buildEvent builds the event
func buildEvent(obj interface{}, eventType pcn_types.EventType) (pcn_types.Event, error) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return pcn_types.Event{}, err
	}
	namespace, _, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return pcn_types.Event{}, err
	}

	event := pcn_types.Event{
		Key:       key,
		Type:      eventType,
		Namespace: namespace,
		Object:    obj,
	}

	return event, nil
}

// implodeLabels set labels in a key1=value1,key2=value2 format
func implodeLabels(labels map[string]string) string {
	implodedLabels := ""

	for k, v := range labels {
		implodedLabels += k + "=" + v + ","
	}

	return strings.Trim(implodedLabels, ",")
}
