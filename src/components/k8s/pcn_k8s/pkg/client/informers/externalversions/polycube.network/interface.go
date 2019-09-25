/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by informer-gen. DO NOT EDIT.

package polycube

import (
	internalinterfaces "github.com/polycube-network/polycube/src/components/k8s/pcn_k8s/pkg/client/informers/externalversions/internalinterfaces"
	v1beta "github.com/polycube-network/polycube/src/components/k8s/pcn_k8s/pkg/client/informers/externalversions/polycube.network/v1beta"
)

// Interface provides access to each of this group's versions.
type Interface interface {
	// V1beta provides access to shared informers for resources in V1beta.
	V1beta() v1beta.Interface
}

type group struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &group{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// V1beta returns a new v1beta.Interface.
func (g *group) V1beta() v1beta.Interface {
	return v1beta.New(g.factory, g.namespace, g.tweakListOptions)
}
