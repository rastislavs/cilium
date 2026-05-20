// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/fake"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	bgptables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// routePolicyFixtureMap is a test-only adapter for legacy RoutePolicy fixtures.
// Production reconcilers now write RoutePolicyStatementMap values into StateDB.
type routePolicyFixtureMap map[resource.Key]RoutePolicyMap

func Test_RoutePolicyReconcilerDesiredRoutePolicyStatementOrder(t *testing.T) {
	req := require.New(t)

	db := statedb.New()
	routePolicyTable, err := bgptables.NewBGPDesiredPolicyTable(db)
	req.NoError(err)

	txn := db.WriteTxn(routePolicyTable)
	_, _, err = routePolicyTable.Insert(txn, desiredRoutePolicyRow("instance-0", PodCIDRReconcilerName, routePolicyPriorityPodCIDR, "pod-cidr-policy"))
	req.NoError(err)
	_, _, err = routePolicyTable.Insert(txn, desiredRoutePolicyRow("instance-0", ServiceReconcilerName, routePolicyPriorityService, "service-policy"))
	req.NoError(err)
	txn.Commit()

	reconciler := &RoutePolicyReconciler{
		logger:           hivetest.Logger(t),
		db:               db,
		routePolicyTable: routePolicyTable,
	}

	desiredPolicies, err := reconciler.desiredRoutePolicies("instance-0")
	req.NoError(err)
	req.Len(desiredPolicies, 1)
	req.Equal([]string{"service-policy", "pod-cidr-policy"}, routePolicyStatementNames(desiredPolicies[routePolicyNameForType(types.RoutePolicyTypeExport)]))
}

func Test_RoutePolicyReconcilerDesiredRoutePolicyStatementOrderTieBreaksByName(t *testing.T) {
	req := require.New(t)

	db := statedb.New()
	routePolicyTable, err := bgptables.NewBGPDesiredPolicyTable(db)
	req.NoError(err)

	txn := db.WriteTxn(routePolicyTable)
	row := desiredRoutePolicyRow("instance-0", ServiceReconcilerName, routePolicyPriorityService, "z-statement")
	row.Resource = resource.Key{Name: "a-resource"}
	_, _, err = routePolicyTable.Insert(txn, row)
	req.NoError(err)

	row = desiredRoutePolicyRow("instance-0", PodCIDRReconcilerName, routePolicyPriorityService, "a-statement")
	row.Resource = resource.Key{Name: "z-resource"}
	_, _, err = routePolicyTable.Insert(txn, row)
	req.NoError(err)
	txn.Commit()

	reconciler := &RoutePolicyReconciler{
		logger:           hivetest.Logger(t),
		db:               db,
		routePolicyTable: routePolicyTable,
	}

	desiredPolicies, err := reconciler.desiredRoutePolicies("instance-0")
	req.NoError(err)
	req.Equal([]string{"a-statement", "z-statement"}, routePolicyStatementNames(desiredPolicies[routePolicyNameForType(types.RoutePolicyTypeExport)]))
}

func Test_RoutePolicyReconcilerDesiredRoutePolicyGroupsByPeer(t *testing.T) {
	req := require.New(t)

	db := statedb.New()
	routePolicyTable, err := bgptables.NewBGPDesiredPolicyTable(db)
	req.NoError(err)

	txn := db.WriteTxn(routePolicyTable)
	peerA := desiredRoutePolicyRow("instance-0", ServiceReconcilerName, routePolicyPriorityService, "shared-statement")
	peerA.Peer = "peer-a"
	_, _, err = routePolicyTable.Insert(txn, peerA)
	req.NoError(err)

	peerB := desiredRoutePolicyRow("instance-0", ServiceReconcilerName, routePolicyPriorityService, "shared-statement")
	peerB.Peer = "peer-b"
	_, _, err = routePolicyTable.Insert(txn, peerB)
	req.NoError(err)

	global := desiredRoutePolicyRow("instance-0", ServiceReconcilerName, routePolicyPriorityService, "global-statement")
	_, _, err = routePolicyTable.Insert(txn, global)
	req.NoError(err)
	txn.Commit()

	reconciler := &RoutePolicyReconciler{
		logger:           hivetest.Logger(t),
		db:               db,
		routePolicyTable: routePolicyTable,
	}

	desiredPolicies, err := reconciler.desiredRoutePolicies("instance-0")
	req.NoError(err)
	req.Len(desiredPolicies, 3)
	req.Equal([]string{"shared-statement"}, routePolicyStatementNames(desiredPolicies[routePolicyName("peer-a", types.RoutePolicyTypeExport)]))
	req.Equal([]string{"shared-statement"}, routePolicyStatementNames(desiredPolicies[routePolicyName("peer-b", types.RoutePolicyTypeExport)]))
	req.Equal([]string{"global-statement"}, routePolicyStatementNames(desiredPolicies[routePolicyNameForType(types.RoutePolicyTypeExport)]))
}

func Test_RoutePolicyReconcilerSkipsGoBGPWhenRenderedPoliciesUnchanged(t *testing.T) {
	req := require.New(t)

	db := statedb.New()
	routePolicyTable, err := bgptables.NewBGPDesiredPolicyTable(db)
	req.NoError(err)

	res := resource.Key{Name: "resource-0"}
	statement := desiredRoutePolicyRow("instance-0", ServiceReconcilerName, routePolicyPriorityService, "service-policy").Statement
	err = reconcileDesiredRoutePolicyStatements(
		db,
		routePolicyTable,
		"instance-0",
		ServiceReconcilerName,
		routePolicyPriorityService,
		res,
		types.RoutePolicyTypeExport,
		RoutePolicyStatementMap{statement.Name: statement},
	)
	req.NoError(err)

	router := &countingRoutePolicyRouter{FakeRouter: fake.NewFakeRouter()}
	bgpInstance := instance.NewFakeBGPInstanceWithName("instance-0")
	bgpInstance.Router = router

	reconciler := &RoutePolicyReconciler{
		logger:           hivetest.Logger(t),
		db:               db,
		routePolicyTable: routePolicyTable,
		metadata:         make(map[string]RoutePolicyReconcilerMetadata),
	}
	req.NoError(reconciler.Init(bgpInstance))

	params := ReconcileParams{
		BGPInstance:   bgpInstance,
		DesiredConfig: &v2.CiliumBGPNodeInstance{Name: "instance-0"},
		CiliumNode:    &v2.CiliumNode{},
	}
	req.NoError(reconciler.Reconcile(context.Background(), params))
	req.Equal(1, router.addPolicyCalls)
	req.Equal(0, router.removePolicyCalls)
	resetCalls := router.resetNeighborCalls + router.resetAllNeighborsCalls

	req.NoError(reconciler.Reconcile(context.Background(), params))
	req.Equal(1, router.addPolicyCalls)
	req.Equal(0, router.removePolicyCalls)
	req.Equal(resetCalls, router.resetNeighborCalls+router.resetAllNeighborsCalls)
}

func Test_ReconcileDesiredRoutePolicyStatementsSkipsUnchangedRows(t *testing.T) {
	req := require.New(t)

	db := statedb.New()
	routePolicyTable, err := bgptables.NewBGPDesiredPolicyTable(db)
	req.NoError(err)

	res := resource.Key{Name: "resource-0"}
	statement := desiredRoutePolicyRow("instance-0", ServiceReconcilerName, routePolicyPriorityService, "service-policy").Statement
	desired := RoutePolicyStatementMap{statement.Name: statement}

	err = reconcileDesiredRoutePolicyStatements(db, routePolicyTable, "instance-0", ServiceReconcilerName, routePolicyPriorityService, res, types.RoutePolicyTypeExport, desired)
	req.NoError(err)
	rev := routePolicyRevision(req, db, routePolicyTable, "instance-0", ServiceReconcilerName, res, types.RoutePolicyTypeExport, statement.Name)

	err = reconcileDesiredRoutePolicyStatements(db, routePolicyTable, "instance-0", ServiceReconcilerName, routePolicyPriorityService, res, types.RoutePolicyTypeExport, desired)
	req.NoError(err)
	req.Equal(rev, routePolicyRevision(req, db, routePolicyTable, "instance-0", ServiceReconcilerName, res, types.RoutePolicyTypeExport, statement.Name))

	err = reconcileDesiredRoutePolicyStatements(db, routePolicyTable, "instance-0", ServiceReconcilerName, routePolicyPriorityService+1, res, types.RoutePolicyTypeExport, desired)
	req.NoError(err)
	req.Greater(routePolicyRevision(req, db, routePolicyTable, "instance-0", ServiceReconcilerName, res, types.RoutePolicyTypeExport, statement.Name), rev)
}

func Test_ReconcileDesiredRoutePolicyStatementsByPeerWritesPeerAndDeletesStale(t *testing.T) {
	req := require.New(t)

	db := statedb.New()
	routePolicyTable, err := bgptables.NewBGPDesiredPolicyTable(db)
	req.NoError(err)

	res := resource.Key{Name: "resource-0"}
	statement := desiredRoutePolicyRow("instance-0", ServiceReconcilerName, routePolicyPriorityService, "service-policy").Statement

	err = reconcileDesiredRoutePolicyStatementsByPeer(
		db,
		routePolicyTable,
		"instance-0",
		ServiceReconcilerName,
		routePolicyPriorityService,
		res,
		types.RoutePolicyTypeExport,
		PeerRoutePolicyStatementMap{"peer-a": {statement.Name: statement}},
	)
	req.NoError(err)
	rows := statedb.Collect(routePolicyTable.List(db.ReadTxn(), bgptables.BGPDesiredPolicyInstanceIndex.Query("instance-0")))
	req.Len(rows, 1)
	req.Equal("peer-a", rows[0].Peer)

	err = reconcileDesiredRoutePolicyStatementsByPeer(
		db,
		routePolicyTable,
		"instance-0",
		ServiceReconcilerName,
		routePolicyPriorityService,
		res,
		types.RoutePolicyTypeExport,
		PeerRoutePolicyStatementMap{"peer-b": {statement.Name: statement}},
	)
	req.NoError(err)
	rows = statedb.Collect(routePolicyTable.List(db.ReadTxn(), bgptables.BGPDesiredPolicyInstanceIndex.Query("instance-0")))
	req.Len(rows, 1)
	req.Equal("peer-b", rows[0].Peer)
}

func routePolicyRevision(
	req *require.Assertions,
	db *statedb.DB,
	table statedb.RWTable[*bgptables.BGPDesiredPolicy],
	instance string,
	source string,
	res resource.Key,
	policyType types.RoutePolicyType,
	statementName string,
) statedb.Revision {
	policyKey := bgptables.BGPDesiredPolicyKey{
		InstanceName:      instance,
		Source:            source,
		ResourceNamespace: res.Namespace,
		ResourceName:      res.Name,
		PolicyType:        policyType,
		StatementName:     statementName,
	}
	_, rev, found := table.Get(db.ReadTxn(), bgptables.BGPDesiredPolicyIndex.Query(policyKey))
	req.True(found)
	return rev
}

func routePolicyMapFromTable(
	db *statedb.DB,
	table statedb.RWTable[*bgptables.BGPDesiredPolicy],
	instance string,
	source string,
	res resource.Key,
) RoutePolicyMap {
	policies := routePolicyFixtureMapFromTable(db, table, instance, source)[res]
	if policies == nil {
		return RoutePolicyMap{}
	}
	return policies
}

func routePolicyFixtureMapFromTable(
	db *statedb.DB,
	table statedb.RWTable[*bgptables.BGPDesiredPolicy],
	instance string,
	source string,
) routePolicyFixtureMap {
	rows := statedb.Collect(table.List(db.ReadTxn(), bgptables.BGPDesiredPolicyInstanceIndex.Query(instance)))
	policies := make(routePolicyFixtureMap)
	for _, row := range rows {
		if row.Source != source || row.Statement == nil {
			continue
		}
		if _, found := policies[row.Resource]; !found {
			policies[row.Resource] = make(RoutePolicyMap)
		}
		statement := bgptables.CloneRoutePolicyStatement(row.Statement)
		statement.Name = ""
		policies[row.Resource][row.StatementName] = &types.RoutePolicy{
			Name:       row.StatementName,
			Type:       row.PolicyType,
			Statements: []*types.RoutePolicyStatement{statement},
		}
	}
	if len(policies) == 0 {
		return nil
	}
	return policies
}

func seedDesiredRoutePolicyFixtures(
	req *require.Assertions,
	db *statedb.DB,
	table statedb.RWTable[*bgptables.BGPDesiredPolicy],
	instance string,
	source string,
	priority int,
	desired routePolicyFixtureMap,
) {
	for res, policies := range desired {
		err := reconcileDesiredRoutePolicyStatements(db, table, instance, source, priority, res, types.RoutePolicyTypeExport, routePolicyStatementsFromPolicies(policies))
		req.NoError(err)
	}
}

func desiredRoutePolicyRow(instance, source string, priority int, policyName string) *bgptables.BGPDesiredPolicy {
	return &bgptables.BGPDesiredPolicy{
		InstanceName:  instance,
		Source:        source,
		Resource:      resource.Key{Name: policyName},
		Priority:      priority,
		PolicyType:    types.RoutePolicyTypeExport,
		StatementName: policyName,
		Statement: &types.RoutePolicyStatement{
			Name: policyName,
			Actions: types.RoutePolicyActions{
				RouteAction: types.RoutePolicyActionAccept,
			},
		},
	}
}

func routePolicyStatementNames(policy *types.RoutePolicy) []string {
	if policy == nil {
		return nil
	}
	names := make([]string, 0, len(policy.Statements))
	for _, statement := range policy.Statements {
		names = append(names, statement.Name)
	}
	return names
}

func routePolicyStatementsFromPolicies(policies RoutePolicyMap) RoutePolicyStatementMap {
	statements := make(RoutePolicyStatementMap)
	for policyName, policy := range policies {
		if policy == nil {
			continue
		}
		for i, statement := range policy.Statements {
			name := statement.Name
			if name == "" {
				name = policyName
				if len(policy.Statements) > 1 {
					name = policyStatementName(policyName, i)
				}
			}
			clone := bgptables.CloneRoutePolicyStatement(statement)
			clone.Name = name
			statements[name] = clone
		}
	}
	return statements
}

type countingRoutePolicyRouter struct {
	*fake.FakeRouter

	addPolicyCalls         int
	removePolicyCalls      int
	resetNeighborCalls     int
	resetAllNeighborsCalls int
}

func (r *countingRoutePolicyRouter) AddRoutePolicy(ctx context.Context, p types.RoutePolicyRequest) error {
	r.addPolicyCalls++
	return r.FakeRouter.AddRoutePolicy(ctx, p)
}

func (r *countingRoutePolicyRouter) RemoveRoutePolicy(ctx context.Context, p types.RoutePolicyRequest) error {
	r.removePolicyCalls++
	return r.FakeRouter.RemoveRoutePolicy(ctx, p)
}

func (r *countingRoutePolicyRouter) ResetNeighbor(ctx context.Context, p types.ResetNeighborRequest) error {
	r.resetNeighborCalls++
	return r.FakeRouter.ResetNeighbor(ctx, p)
}

func (r *countingRoutePolicyRouter) ResetAllNeighbors(ctx context.Context, p types.ResetAllNeighborsRequest) error {
	r.resetAllNeighborsCalls++
	return r.FakeRouter.ResetAllNeighbors(ctx, p)
}
