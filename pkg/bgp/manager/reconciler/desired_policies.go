// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"

	"github.com/cilium/statedb"

	bgptables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

const (
	routePolicyPriorityService   = 10
	routePolicyPriorityPodCIDR   = 20
	routePolicyPriorityPodIPPool = 30
	routePolicyPriorityInterface = 40
)

func reconcileDesiredRoutePolicyStatements(
	db *statedb.DB,
	table statedb.RWTable[*bgptables.BGPDesiredPolicy],
	instance string,
	source string,
	priority int,
	res resource.Key,
	policyType types.RoutePolicyType,
	desired RoutePolicyStatementMap,
) error {
	return reconcileDesiredRoutePolicyStatementsByPeer(
		db,
		table,
		instance,
		source,
		priority,
		res,
		policyType,
		PeerRoutePolicyStatementMap{"": desired},
	)
}

func reconcileDesiredRoutePolicyStatementsByPeer(
	db *statedb.DB,
	table statedb.RWTable[*bgptables.BGPDesiredPolicy],
	instance string,
	source string,
	priority int,
	res resource.Key,
	policyType types.RoutePolicyType,
	desired PeerRoutePolicyStatementMap,
) error {
	if db == nil || table == nil {
		return fmt.Errorf("BGP desired policy statement table is not initialized")
	}

	txn := db.WriteTxn(table)
	defer txn.Abort()

	type peerStatementKey struct {
		peer string
		name string
	}

	owner := bgptables.NewBGPDesiredPolicyOwner(instance, source, res)
	existing := statedb.Collect(table.List(txn, bgptables.BGPDesiredPolicyOwnerIndex.Query(owner)))
	existingByKey := make(map[peerStatementKey]*bgptables.BGPDesiredPolicy, len(existing))
	for _, statement := range existing {
		if statement.PolicyType != policyType {
			continue
		}
		existingByKey[peerStatementKey{peer: statement.Peer, name: statement.StatementName}] = statement
	}

	desiredKeys := make(map[peerStatementKey]struct{})
	for peer, statements := range desired {
		for name, statement := range statements {
			if statement == nil {
				continue
			}
			key := peerStatementKey{peer: peer, name: name}
			desiredKeys[key] = struct{}{}
			desiredRow := &bgptables.BGPDesiredPolicy{
				InstanceName:  instance,
				Peer:          peer,
				Source:        source,
				Resource:      res,
				Priority:      priority,
				PolicyType:    policyType,
				StatementName: name,
				Statement:     bgptables.CloneRoutePolicyStatement(statement),
			}
			if existingPolicy, found := existingByKey[key]; found && existingPolicy.DeepEqual(desiredRow) {
				continue
			}
			if _, _, err := table.Insert(txn, desiredRow); err != nil {
				return fmt.Errorf("failed inserting desired route policy statement %q for peer %q: %w", name, peer, err)
			}
		}
	}

	for _, statement := range existing {
		if statement.PolicyType != policyType {
			continue
		}
		key := peerStatementKey{peer: statement.Peer, name: statement.StatementName}
		if _, found := desiredKeys[key]; found {
			continue
		}
		if _, _, err := table.Delete(txn, statement); err != nil {
			return fmt.Errorf("failed deleting desired route policy statement %q for peer %q: %w", statement.StatementName, statement.Peer, err)
		}
	}

	txn.Commit()
	return nil
}

func deleteDesiredRoutePoliciesByInstance(
	db *statedb.DB,
	table statedb.RWTable[*bgptables.BGPDesiredPolicy],
	instance string,
) error {
	return deleteDesiredRoutePolicies(db, table, instance, "")
}

func deleteDesiredRoutePoliciesBySource(
	db *statedb.DB,
	table statedb.RWTable[*bgptables.BGPDesiredPolicy],
	instance string,
	source string,
) error {
	return deleteDesiredRoutePolicies(db, table, instance, source)
}

func deleteDesiredRoutePolicies(
	db *statedb.DB,
	table statedb.RWTable[*bgptables.BGPDesiredPolicy],
	instance string,
	source string,
) error {
	if db == nil || table == nil {
		return nil
	}

	txn := db.WriteTxn(table)
	defer txn.Abort()

	for _, policy := range statedb.Collect(table.List(txn, bgptables.BGPDesiredPolicyInstanceIndex.Query(instance))) {
		if source != "" && policy.Source != source {
			continue
		}
		if _, _, err := table.Delete(txn, policy); err != nil {
			return fmt.Errorf("failed deleting desired route policy statement %q: %w", policy.StatementName, err)
		}
	}

	txn.Commit()
	return nil
}

func deleteStaleDesiredRoutePolicyResources(
	db *statedb.DB,
	table statedb.RWTable[*bgptables.BGPDesiredPolicy],
	instance string,
	source string,
	keep map[resource.Key]struct{},
) error {
	if db == nil || table == nil {
		return fmt.Errorf("BGP desired policy statement table is not initialized")
	}

	txn := db.WriteTxn(table)
	defer txn.Abort()

	for _, policy := range statedb.Collect(table.List(txn, bgptables.BGPDesiredPolicyInstanceIndex.Query(instance))) {
		if policy.Source != source {
			continue
		}
		if _, found := keep[policy.Resource]; found {
			continue
		}
		if _, _, err := table.Delete(txn, policy); err != nil {
			return fmt.Errorf("failed deleting desired route policy statement %q: %w", policy.StatementName, err)
		}
	}

	txn.Commit()
	return nil
}
