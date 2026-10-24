package network

import (
	"maps"
	"slices"
)

// Every committed validation batch needs an independent rollback snapshot.
// Copy in memory so large pools do not pay for a full JSON round trip per batch.
func (state diskState) clone() diskState {
	out := state
	out.Nodes = maps.Clone(state.Nodes)
	out.Credentials = maps.Clone(state.Credentials)
	out.Sources = maps.Clone(state.Sources)
	out.PoolHealth = maps.Clone(state.PoolHealth)
	out.Observations = slices.Clone(state.Observations)
	out.Events = slices.Clone(state.Events)
	out.Policies = maps.Clone(state.Policies)
	for id, policy := range out.Policies {
		policy.Targets = slices.Clone(policy.Targets)
		policy.Exclude = slices.Clone(policy.Exclude)
		policy.DNSServers = slices.Clone(policy.DNSServers)
		out.Policies[id] = policy
	}
	out.Bindings = maps.Clone(state.Bindings)
	for project, bindings := range out.Bindings {
		out.Bindings[project] = slices.Clone(bindings)
	}
	out.Profiles = maps.Clone(state.Profiles)
	for id, profile := range out.Profiles {
		profile.Files = maps.Clone(profile.Files)
		if profile.Credentials != nil {
			credentials := *profile.Credentials
			profile.Credentials = &credentials
		}
		out.Profiles[id] = profile
	}
	return out
}
