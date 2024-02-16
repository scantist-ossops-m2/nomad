// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package structs

import (
	"slices"
)

// ConsulConfigEntries represents Consul ConfigEntry definitions from a job for
// a single Consul namespace.
type ConsulConfigEntries struct {
	Cluster     string
	Ingress     map[string]*ConsulIngressConfigEntry
	Terminating map[string]*ConsulTerminatingConfigEntry
}

// ConfigEntries accumulates the Consul Configuration Entries defined in task groups
// of j, organized by Consul namespace.
func (j *Job) ConfigEntries() map[string]*ConsulConfigEntries {
	collection := make(map[string]*ConsulConfigEntries)

	for _, tg := range j.TaskGroups {

		// accumulate config entries by namespace
		ns := tg.Consul.GetNamespace()
		if _, exists := collection[ns]; !exists {
			collection[ns] = &ConsulConfigEntries{
				Ingress:     make(map[string]*ConsulIngressConfigEntry),
				Terminating: make(map[string]*ConsulTerminatingConfigEntry),
			}
		}

		for _, service := range tg.Services {
			if service.Connect.IsGateway() {
				gateway := service.Connect.Gateway
				if ig := gateway.Ingress; ig != nil {
					collection[ns].Ingress[service.Name] = ig
					collection[ns].Cluster = service.Cluster
				} else if term := gateway.Terminating; term != nil {
					collection[ns].Terminating[service.Name] = term
					collection[ns].Cluster = service.Cluster
				}
			}
		}
	}

	return collection
}

type PortNumber = uint16

// ConsulTransparentProxy is used to configure the Envoy sidecar for
// "transparent proxying", which creates IP tables rules inside the network
// namespace to ensure traffic flows thru the Envoy proxy
type ConsulTransparentProxy struct {
	UID                  string
	OutboundPort         PortNumber
	ExcludeInboundPorts  []string // can be Port.Label or Port.Value
	ExcludeOutboundPorts []PortNumber
	ExcludeOutboundCIDRs []string // TODO: netip.Prefix?
	ExcludeUIDs          []string
	NoDNS                bool
}

func (tp *ConsulTransparentProxy) Copy() *ConsulTransparentProxy {
	if tp == nil {
		return nil
	}
	ntp := new(ConsulTransparentProxy)
	*ntp = *tp

	ntp.ExcludeInboundPorts = slices.Clone(tp.ExcludeInboundPorts)
	ntp.ExcludeOutboundPorts = slices.Clone(tp.ExcludeOutboundPorts)
	ntp.ExcludeOutboundCIDRs = slices.Clone(tp.ExcludeOutboundCIDRs)
	ntp.ExcludeUIDs = slices.Clone(tp.ExcludeUIDs)

	return ntp
}

func (tp *ConsulTransparentProxy) Equal(o *ConsulTransparentProxy) bool {
	if tp == nil || o == nil {
		return tp == o
	}
	if tp.UID != o.UID {
		return false
	}
	if tp.OutboundPort != o.OutboundPort {
		return false
	}
	if !slices.Equal(tp.ExcludeInboundPorts, o.ExcludeInboundPorts) {
		return false
	}
	if !slices.Equal(tp.ExcludeOutboundPorts, o.ExcludeOutboundPorts) {
		return false
	}
	if !slices.Equal(tp.ExcludeOutboundCIDRs, o.ExcludeOutboundCIDRs) {
		return false
	}
	if !slices.Equal(tp.ExcludeUIDs, o.ExcludeUIDs) {
		return false
	}
	if tp.NoDNS != o.NoDNS {
		return false
	}

	return false
}
