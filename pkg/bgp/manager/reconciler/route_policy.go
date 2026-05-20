// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	bgptables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
)

type RoutePolicyReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type RoutePolicyReconcilerIn struct {
	cell.In

	Logger           *slog.Logger
	DB               *statedb.DB
	RoutePolicyTable statedb.RWTable[*bgptables.BGPDesiredPolicy]
}

type RoutePolicyReconciler struct {
	logger           *slog.Logger
	db               *statedb.DB
	routePolicyTable statedb.RWTable[*bgptables.BGPDesiredPolicy]
	metadata         map[string]RoutePolicyReconcilerMetadata
}

type RoutePolicyReconcilerMetadata struct {
	RoutePolicies RoutePolicyMap
}

func NewRoutePolicyReconciler(in RoutePolicyReconcilerIn) RoutePolicyReconcilerOut {
	return RoutePolicyReconcilerOut{
		Reconciler: &RoutePolicyReconciler{
			logger:           in.Logger.With(types.ReconcilerLogField, RoutePolicyReconcilerName),
			db:               in.DB,
			routePolicyTable: in.RoutePolicyTable,
			metadata:         make(map[string]RoutePolicyReconcilerMetadata),
		},
	}
}

func (r *RoutePolicyReconciler) Name() string {
	return RoutePolicyReconcilerName
}

func (r *RoutePolicyReconciler) Priority() int {
	return RoutePolicyReconcilerPriority
}

func (r *RoutePolicyReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = RoutePolicyReconcilerMetadata{
		RoutePolicies: make(RoutePolicyMap),
	}
	return nil
}

func (r *RoutePolicyReconciler) Cleanup(i *instance.BGPInstance) {
	if i == nil {
		return
	}
	delete(r.metadata, i.Name)
	if err := deleteDesiredRoutePoliciesByInstance(r.db, r.routePolicyTable, i.Name); err != nil {
		r.logger.Warn("Failed deleting desired route policies", types.InstanceLogField, i.Name, "error", err)
	}
}

func (r *RoutePolicyReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	desiredPolicies, err := r.desiredRoutePolicies(p.BGPInstance.Name)
	if err != nil {
		return err
	}

	metadata := r.getMetadata(p.BGPInstance)
	if routePolicyMapsDeepEqual(metadata.RoutePolicies, desiredPolicies) {
		return nil
	}

	updatedPolicies, err := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
		Logger:          r.logger.With(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:             ctx,
		Router:          p.BGPInstance.Router,
		DesiredPolicies: desiredPolicies,
		CurrentPolicies: metadata.RoutePolicies,
	})

	metadata.RoutePolicies = updatedPolicies
	r.setMetadata(p.BGPInstance, metadata)
	return err
}

func (r *RoutePolicyReconciler) desiredRoutePolicies(instance string) (RoutePolicyMap, error) {
	rx := r.db.ReadTxn()
	rows := statedb.Collect(r.routePolicyTable.List(rx, bgptables.BGPDesiredPolicyInstanceIndex.Query(instance)))
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Priority != rows[j].Priority {
			return rows[i].Priority < rows[j].Priority
		}
		if rows[i].Peer != rows[j].Peer {
			return rows[i].Peer < rows[j].Peer
		}
		if rows[i].StatementName != rows[j].StatementName {
			return rows[i].StatementName < rows[j].StatementName
		}
		if rows[i].PolicyType != rows[j].PolicyType {
			return rows[i].PolicyType < rows[j].PolicyType
		}
		if cmp := strings.Compare(rows[i].Source, rows[j].Source); cmp != 0 {
			return cmp < 0
		}
		if cmp := strings.Compare(rows[i].Resource.Namespace, rows[j].Resource.Namespace); cmp != 0 {
			return cmp < 0
		}
		if cmp := strings.Compare(rows[i].Resource.Name, rows[j].Resource.Name); cmp != 0 {
			return cmp < 0
		}
		return false
	})

	desired := make(RoutePolicyMap)
	seenStatements := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if row.Statement == nil {
			continue
		}
		policyName := routePolicyName(row.Peer, row.PolicyType)
		statementKey := policyName + "\x00" + row.StatementName
		if _, found := seenStatements[statementKey]; found {
			return nil, fmt.Errorf("duplicate desired route policy statement %q for %s policy", row.StatementName, row.PolicyType)
		}
		seenStatements[statementKey] = struct{}{}

		policy := desired[policyName]
		if policy == nil {
			policy = &types.RoutePolicy{
				Name: policyName,
				Type: row.PolicyType,
			}
			desired[policyName] = policy
		}
		statement := bgptables.CloneRoutePolicyStatement(row.Statement)
		if statement.Name == "" {
			statement.Name = row.StatementName
		}
		policy.Statements = append(policy.Statements, statement)
	}
	return desired, nil
}

func routePolicyName(peer string, policyType types.RoutePolicyType) string {
	if peer == "" {
		return routePolicyNameForType(policyType)
	}
	return fmt.Sprintf("cilium-%s-%s", peer, policyType.String())
}

func routePolicyNameForType(policyType types.RoutePolicyType) string {
	return "cilium-" + policyType.String()
}

func routePolicyMapsDeepEqual(a, b RoutePolicyMap) bool {
	if len(a) != len(b) {
		return false
	}
	for name, policyA := range a {
		policyB, found := b[name]
		if !found {
			return false
		}
		if policyA == nil || policyB == nil {
			if policyA != policyB {
				return false
			}
			continue
		}
		if !policyA.DeepEqual(policyB) {
			return false
		}
	}
	return true
}

func (r *RoutePolicyReconciler) getMetadata(i *instance.BGPInstance) RoutePolicyReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *RoutePolicyReconciler) setMetadata(i *instance.BGPInstance, metadata RoutePolicyReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}
