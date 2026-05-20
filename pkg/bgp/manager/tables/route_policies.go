// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// BGPDesiredPolicy is a desired route policy statement rendered by a BGP reconciler.
// The route policy reconciler consumes this table, orders the statements, and
// renders the underlying BGP router policies.
type BGPDesiredPolicy struct {
	InstanceName string
	// Peer is the optional BGP peer name this desired policy statement applies
	// to. Empty means the statement is router-global.
	Peer     string
	Source   string
	Resource resource.Key

	// Priority controls policy rendering order. Lower values are evaluated
	// first by GoBGP.
	Priority int

	PolicyType    types.RoutePolicyType
	StatementName string
	Statement     *types.RoutePolicyStatement
}

func (rp *BGPDesiredPolicy) DeepCopy() *BGPDesiredPolicy {
	if rp == nil {
		return nil
	}
	return &BGPDesiredPolicy{
		InstanceName:  rp.InstanceName,
		Peer:          rp.Peer,
		Source:        rp.Source,
		Resource:      rp.Resource,
		Priority:      rp.Priority,
		PolicyType:    rp.PolicyType,
		StatementName: rp.StatementName,
		Statement:     CloneRoutePolicyStatement(rp.Statement),
	}
}

func (rp *BGPDesiredPolicy) DeepEqual(other *BGPDesiredPolicy) bool {
	if rp == nil || other == nil {
		return rp == other
	}
	if rp.InstanceName != other.InstanceName ||
		rp.Peer != other.Peer ||
		rp.Source != other.Source ||
		rp.Resource != other.Resource ||
		rp.Priority != other.Priority ||
		rp.PolicyType != other.PolicyType ||
		rp.StatementName != other.StatementName {
		return false
	}
	if rp.Statement == nil || other.Statement == nil {
		return rp.Statement == other.Statement
	}
	return rp.Statement.DeepEqual(other.Statement)
}

func (rp *BGPDesiredPolicy) String() string {
	return fmt.Sprintf(
		"BGPDesiredPolicy{InstanceName: %s, Peer: %s, Source: %s, Resource: %s, Priority: %d, PolicyType: %s, StatementName: %s}",
		rp.InstanceName,
		rp.Peer,
		rp.Source,
		rp.Resource,
		rp.Priority,
		rp.PolicyType,
		rp.StatementName,
	)
}

func (rp *BGPDesiredPolicy) TableHeader() []string {
	return []string{
		"InstanceName",
		"Peer",
		"Source",
		"Resource",
		"Priority",
		"PolicyType",
		"StatementName",
	}
}

func (rp *BGPDesiredPolicy) TableRow() []string {
	return []string{
		rp.InstanceName,
		rp.Peer,
		rp.Source,
		rp.Resource.String(),
		fmt.Sprintf("%d", rp.Priority),
		rp.PolicyType.String(),
		rp.StatementName,
	}
}

type BGPDesiredPolicyKey struct {
	InstanceName      string
	Peer              string
	Source            string
	ResourceNamespace string
	ResourceName      string
	PolicyType        types.RoutePolicyType
	StatementName     string
}

func (k BGPDesiredPolicyKey) Key() index.Key {
	return index.String(strings.Join([]string{
		k.InstanceName,
		k.Peer,
		k.Source,
		k.ResourceNamespace,
		k.ResourceName,
		k.PolicyType.String(),
		k.StatementName,
	}, "\x00"))
}

type BGPDesiredPolicyOwner struct {
	InstanceName      string
	Source            string
	ResourceNamespace string
	ResourceName      string
}

func (o BGPDesiredPolicyOwner) Key() index.Key {
	return index.String(strings.Join([]string{
		o.InstanceName,
		o.Source,
		o.ResourceNamespace,
		o.ResourceName,
	}, "\x00"))
}

func NewBGPDesiredPolicyOwner(instanceName, source string, res resource.Key) BGPDesiredPolicyOwner {
	return BGPDesiredPolicyOwner{
		InstanceName:      instanceName,
		Source:            source,
		ResourceNamespace: res.Namespace,
		ResourceName:      res.Name,
	}
}

var (
	BGPDesiredPolicyIndex = statedb.Index[*BGPDesiredPolicy, BGPDesiredPolicyKey]{
		Name: "key",
		FromObject: func(obj *BGPDesiredPolicy) index.KeySet {
			return index.NewKeySet(
				BGPDesiredPolicyKey{
					InstanceName:      obj.InstanceName,
					Peer:              obj.Peer,
					Source:            obj.Source,
					ResourceNamespace: obj.Resource.Namespace,
					ResourceName:      obj.Resource.Name,
					PolicyType:        obj.PolicyType,
					StatementName:     obj.StatementName,
				}.Key(),
			)
		},
		FromKey: BGPDesiredPolicyKey.Key,
		Unique:  true,
	}
	BGPDesiredPolicyInstanceIndex = statedb.Index[*BGPDesiredPolicy, string]{
		Name: "InstanceName",
		FromObject: func(obj *BGPDesiredPolicy) index.KeySet {
			return index.NewKeySet(index.String(obj.InstanceName))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}
	BGPDesiredPolicyOwnerIndex = statedb.Index[*BGPDesiredPolicy, BGPDesiredPolicyOwner]{
		Name: "Owner",
		FromObject: func(obj *BGPDesiredPolicy) index.KeySet {
			return index.NewKeySet(NewBGPDesiredPolicyOwner(obj.InstanceName, obj.Source, obj.Resource).Key())
		},
		FromKey: BGPDesiredPolicyOwner.Key,
		Unique:  false,
	}
)

func NewBGPDesiredPolicyTable(db *statedb.DB) (statedb.RWTable[*BGPDesiredPolicy], error) {
	return statedb.NewTable(
		db,
		"bgp-desired-policies",
		BGPDesiredPolicyIndex,
		BGPDesiredPolicyInstanceIndex,
		BGPDesiredPolicyOwnerIndex,
	)
}

func CloneRoutePolicy(in *types.RoutePolicy) *types.RoutePolicy {
	if in == nil {
		return nil
	}
	out := &types.RoutePolicy{
		Name: in.Name,
		Type: in.Type,
	}
	if len(in.Statements) > 0 {
		out.Statements = make([]*types.RoutePolicyStatement, len(in.Statements))
		for i, stmt := range in.Statements {
			out.Statements[i] = CloneRoutePolicyStatement(stmt)
		}
	}
	return out
}

func CloneRoutePolicyStatement(in *types.RoutePolicyStatement) *types.RoutePolicyStatement {
	if in == nil {
		return nil
	}
	return &types.RoutePolicyStatement{
		Name:       in.Name,
		Conditions: cloneRoutePolicyConditions(in.Conditions),
		Actions:    cloneRoutePolicyActions(in.Actions),
	}
}

func cloneRoutePolicyConditions(in types.RoutePolicyConditions) types.RoutePolicyConditions {
	out := types.RoutePolicyConditions{}
	if in.MatchNeighbors != nil {
		out.MatchNeighbors = &types.RoutePolicyNeighborMatch{
			Type:      in.MatchNeighbors.Type,
			Neighbors: append([]netip.Addr(nil), in.MatchNeighbors.Neighbors...),
		}
	}
	if in.MatchPrefixes != nil {
		out.MatchPrefixes = &types.RoutePolicyPrefixMatch{
			Type:     in.MatchPrefixes.Type,
			Prefixes: append([]types.RoutePolicyPrefix(nil), in.MatchPrefixes.Prefixes...),
		}
	}
	out.MatchFamilies = append([]types.Family(nil), in.MatchFamilies...)
	return out
}

func cloneRoutePolicyActions(in types.RoutePolicyActions) types.RoutePolicyActions {
	out := types.RoutePolicyActions{
		RouteAction:         in.RouteAction,
		AddCommunities:      append([]string(nil), in.AddCommunities...),
		AddLargeCommunities: append([]string(nil), in.AddLargeCommunities...),
	}
	if in.SetLocalPreference != nil {
		localPref := *in.SetLocalPreference
		out.SetLocalPreference = &localPref
	}
	if in.NextHop != nil {
		nextHop := *in.NextHop
		out.NextHop = &nextHop
	}
	return out
}
