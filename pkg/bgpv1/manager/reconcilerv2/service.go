// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

type ServiceReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type ServiceReconcilerIn struct {
	cell.In
	DB         *statedb.DB
	Frontends  statedb.Table[*loadbalancer.Frontend]
	Logger     *slog.Logger
	PeerAdvert *CiliumPeerAdvertisement
}

type ServiceReconciler struct {
	logger     *slog.Logger
	db         *statedb.DB
	frontends  statedb.Table[*loadbalancer.Frontend]
	peerAdvert *CiliumPeerAdvertisement
	metadata   map[string]ServiceReconcilerMetadata
}

func NewServiceReconciler(in ServiceReconcilerIn) ServiceReconcilerOut {
	return ServiceReconcilerOut{
		Reconciler: &ServiceReconciler{
			logger:     in.Logger,
			db:         in.DB,
			frontends:  in.Frontends,
			peerAdvert: in.PeerAdvert,
			metadata:   make(map[string]ServiceReconcilerMetadata),
		},
	}
	// TODO:
	// - subscribe to loadbalancer.Frontend events and trigger reconcile upon changes
	// - use something like rate.NewLimiter(1*time.Second, 1) to rate-limit reconciliation triggers
	// - double-check if backend changes trigger frontend events - if not, subscribe for backend changes as well
}

// ServiceReconcilerMetadata holds per-instance reconciler state.
type ServiceReconcilerMetadata struct {
	ServicePaths          ResourceAFPathsMap
	ServiceAdvertisements PeerAdvertisements
	ServiceRoutePolicies  ResourceRoutePolicyMap

	FrontendChanges statedb.ChangeIterator[*loadbalancer.Frontend]
	ReconcileCount  uint32
}

func (r *ServiceReconciler) getMetadata(i *instance.BGPInstance) ServiceReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *ServiceReconciler) setMetadata(i *instance.BGPInstance, metadata ServiceReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}

func (r *ServiceReconciler) Name() string {
	return ServiceReconcilerName
}

func (r *ServiceReconciler) Priority() int {
	return ServiceReconcilerPriority
}

func (r *ServiceReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: service reconciler initialization with nil BGPInstance")
	}

	r.metadata[i.Name] = ServiceReconcilerMetadata{
		ServicePaths:          make(ResourceAFPathsMap),
		ServiceAdvertisements: make(PeerAdvertisements),
		ServiceRoutePolicies:  make(ResourceRoutePolicyMap),
	}
	return nil
}

func (r *ServiceReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *ServiceReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2.BGPServiceAdvert)
	if err != nil {
		return err
	}

	reqFullReconcile := r.modifiedServiceAdvertisements(p, desiredPeerAdverts)

	serviceMetadata := r.getMetadata(p.BGPInstance)
	if serviceMetadata.ReconcileCount == 0 {
		reqFullReconcile = true // first reconciliation for the instance must be always full
	}
	serviceMetadata.ReconcileCount++
	r.setMetadata(p.BGPInstance, serviceMetadata)

	err = r.reconcileServices(ctx, p, desiredPeerAdverts, reqFullReconcile)

	if err == nil && reqFullReconcile {
		// update svc advertisements in metadata only if the reconciliation was successful
		r.updateServiceAdvertisementsMetadata(p, desiredPeerAdverts)
	}
	return err
}

func (r *ServiceReconciler) reconcileServices(ctx context.Context, p ReconcileParams, desiredPeerAdverts PeerAdvertisements, fullReconcile bool) error {
	var (
		toReconcile []*loadbalancer.Frontend
		toWithdraw  []resource.Key

		desiredSvcRoutePolicies ResourceRoutePolicyMap
		desiredSvcPaths         ResourceAFPathsMap

		err error
	)

	if fullReconcile {
		r.logger.Debug("performing all services reconciliation")

		// get all services to reconcile and to withdraw.
		toReconcile, toWithdraw, err = r.fullReconciliationServiceList(p)
		if err != nil {
			return err
		}
	} else {
		r.logger.Debug("performing modified services reconciliation")

		// get modified services to reconcile and to withdraw.
		// Note: we should call svc diff only once in a reconcile loop.
		toReconcile, toWithdraw, err = r.diffReconciliationServiceList(p)
		if err != nil {
			return err
		}
	}

	// get desired service route policies
	desiredSvcRoutePolicies, err = r.getDesiredRoutePolicies(p, desiredPeerAdverts, toReconcile, toWithdraw)
	if err != nil {
		return err
	}

	// reconcile service route policies
	err = r.reconcileSvcRoutePolicies(ctx, p, desiredSvcRoutePolicies)
	if err != nil {
		return fmt.Errorf("failed to reconcile service route policies: %w", err)
	}

	// get desired service paths
	desiredSvcPaths, err = r.getDesiredPaths(p, desiredPeerAdverts, toReconcile, toWithdraw)
	if err != nil {
		return err
	}

	// reconcile service paths
	err = r.reconcilePaths(ctx, p, desiredSvcPaths)
	if err != nil {
		return fmt.Errorf("failed to reconcile service paths: %w", err)
	}

	return nil
}

func (r *ServiceReconciler) reconcileSvcRoutePolicies(ctx context.Context, p ReconcileParams, desiredSvcRoutePolicies ResourceRoutePolicyMap) error {
	var err error
	metadata := r.getMetadata(p.BGPInstance)
	for svcKey, desiredSvcRoutePolicies := range desiredSvcRoutePolicies {
		currentSvcRoutePolicies, exists := metadata.ServiceRoutePolicies[svcKey]
		if !exists && len(desiredSvcRoutePolicies) == 0 {
			continue
		}

		updatedSvcRoutePolicies, rErr := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
			Logger:          r.logger.With(types.InstanceLogField, p.DesiredConfig.Name),
			Ctx:             ctx,
			Router:          p.BGPInstance.Router,
			DesiredPolicies: desiredSvcRoutePolicies,
			CurrentPolicies: currentSvcRoutePolicies,
		})

		if rErr == nil && len(desiredSvcRoutePolicies) == 0 {
			delete(metadata.ServiceRoutePolicies, svcKey)
		} else {
			metadata.ServiceRoutePolicies[svcKey] = updatedSvcRoutePolicies
		}
		err = errors.Join(err, rErr)
	}
	r.setMetadata(p.BGPInstance, metadata)

	return err
}

func (r *ServiceReconciler) getDesiredRoutePolicies(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, toUpdate []*loadbalancer.Frontend, toRemove []resource.Key) (ResourceRoutePolicyMap, error) {
	desiredSvcRoutePolicies := make(ResourceRoutePolicyMap)

	for _, frontend := range toUpdate {
		svcKey := resource.Key{
			Name:      frontend.ServiceName.Name(),
			Namespace: frontend.ServiceName.Namespace(),
		}

		// get desired route policies for the service
		svcRoutePolicies, err := r.getDesiredSvcRoutePolicies(p, desiredPeerAdverts, frontend)
		if err != nil {
			return nil, err
		}

		desiredSvcRoutePolicies[svcKey] = svcRoutePolicies
	}

	for _, svcKey := range toRemove {
		// for withdrawn services, we need to set route policies to nil.
		desiredSvcRoutePolicies[svcKey] = nil
	}

	return desiredSvcRoutePolicies, nil
}

func (r *ServiceReconciler) getDesiredSvcRoutePolicies(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, frontend *loadbalancer.Frontend) (RoutePolicyMap, error) {
	desiredSvcRoutePolicies := make(RoutePolicyMap)

	for peer, afAdverts := range desiredPeerAdverts {
		for fam, adverts := range afAdverts {
			agentFamily := types.ToAgentFamily(fam)

			for _, advert := range adverts {
				labelSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
				if err != nil {
					return nil, fmt.Errorf("failed constructing LabelSelector: %w", err)
				}
				if !labelSelector.Matches(serviceLabelSet(frontend.Service)) {
					continue
				}

				for _, advertType := range []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr, v2.BGPExternalIPAddr, v2.BGPClusterIPAddr} {
					policy, err := r.getServiceRoutePolicy(p, peer, agentFamily, frontend, advert, advertType)
					if err != nil {
						return nil, fmt.Errorf("failed to get desired %s route policy: %w", advertType, err)
					}
					if policy != nil {
						existingPolicy := desiredSvcRoutePolicies[policy.Name]
						if existingPolicy != nil {
							policy, err = MergeRoutePolicies(existingPolicy, policy)
							if err != nil {
								return nil, fmt.Errorf("failed to merge %s route policies: %w", advertType, err)
							}
						}
						desiredSvcRoutePolicies[policy.Name] = policy
					}
				}
			}
		}
	}

	return desiredSvcRoutePolicies, nil
}

func (r *ServiceReconciler) reconcilePaths(ctx context.Context, p ReconcileParams, desiredSvcPaths ResourceAFPathsMap) error {
	var err error
	metadata := r.getMetadata(p.BGPInstance)

	metadata.ServicePaths, err = ReconcileResourceAFPaths(ReconcileResourceAFPathsParams{
		Logger:                 r.logger.With(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:                    ctx,
		Router:                 p.BGPInstance.Router,
		DesiredResourceAFPaths: desiredSvcPaths,
		CurrentResourceAFPaths: metadata.ServicePaths,
	})

	r.setMetadata(p.BGPInstance, metadata)
	return err
}

// modifiedServiceAdvertisements compares local advertisement state with desiredPeerAdverts, if they differ,
// returns true signaling that full reconciliation is required.
func (r *ServiceReconciler) modifiedServiceAdvertisements(p ReconcileParams, desiredPeerAdverts PeerAdvertisements) bool {
	// current metadata
	serviceMetadata := r.getMetadata(p.BGPInstance)

	// check if BGP advertisement configuration modified
	modified := !PeerAdvertisementsEqual(serviceMetadata.ServiceAdvertisements, desiredPeerAdverts)

	return modified
}

// updateServiceAdvertisementsMetadata updates the provided ServiceAdvertisements in the reconciler metadata.
func (r *ServiceReconciler) updateServiceAdvertisementsMetadata(p ReconcileParams, peerAdverts PeerAdvertisements) {
	// current metadata
	serviceMetadata := r.getMetadata(p.BGPInstance)

	// update ServiceAdvertisements in the metadata
	r.setMetadata(p.BGPInstance, ServiceReconcilerMetadata{
		ServicePaths:          serviceMetadata.ServicePaths,
		ServiceRoutePolicies:  serviceMetadata.ServiceRoutePolicies,
		ServiceAdvertisements: peerAdverts,
	})
}

func hasLocalBackends(p ReconcileParams, fe *loadbalancer.Frontend) bool {
	for backend := range fe.Backends {
		if backend.NodeName == p.CiliumNode.Name && backend.State == loadbalancer.BackendStateActive {
			return true
		}
	}
	return false
}

func (r *ServiceReconciler) fullReconciliationServiceList(p ReconcileParams) (toReconcile []*loadbalancer.Frontend, toWithdraw []resource.Key, err error) {
	metadata := r.getMetadata(p.BGPInstance)

	// re-init changes interator, so that it contains changes since the last full reconciliation
	tx := r.db.WriteTxn(r.frontends)
	metadata.FrontendChanges, err = r.frontends.Changes(tx)
	if err != nil {
		tx.Abort()
		return nil, nil, fmt.Errorf("error subscribing to frontends changes: %w", err)
	}
	tx.Commit()
	r.setMetadata(p.BGPInstance, metadata)

	rx := r.db.ReadTxn()
	events, _ := metadata.FrontendChanges.Next(rx)

	svcSet := sets.New[resource.Key]()
	for frontentEvent := range events {
		frontend := frontentEvent.Object
		if frontentEvent.Deleted {
			continue // skip frontends deleted between acquiring write and read tx
		}
		toReconcile = append(toReconcile, frontend)
		svcSet.Insert(resource.Key{Name: frontend.ServiceName.Name(), Namespace: frontend.ServiceName.Namespace()})
	}

	// check for services which are no longer present
	serviceAFPaths := metadata.ServicePaths
	for svcKey := range serviceAFPaths {
		// if the service no longer exists, withdraw it
		if !svcSet.Has(svcKey) {
			toWithdraw = append(toWithdraw, svcKey)
		}
	}
	return
}

// diffReconciliationServiceList returns a list of services to reconcile and to withdraw when
// performing partial (diff) service reconciliation.
func (r *ServiceReconciler) diffReconciliationServiceList(p ReconcileParams) (toReconcile []*loadbalancer.Frontend, toWithdraw []resource.Key, err error) {
	metadata := r.getMetadata(p.BGPInstance)
	rx := r.db.ReadTxn()

	// TODO: maybe ensure that FrontendChanges is initialized
	events, _ := metadata.FrontendChanges.Next(rx)

	for frontentEvent := range events {
		frontend := frontentEvent.Object
		if frontentEvent.Deleted {
			toWithdraw = append(toWithdraw, resource.Key{Name: frontend.ServiceName.Name(), Namespace: frontend.ServiceName.Namespace()})
		} else {
			toReconcile = append(toReconcile, frontend)
		}
	}
	return
}

func (r *ServiceReconciler) getDesiredPaths(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, toReconcile []*loadbalancer.Frontend, toWithdraw []resource.Key) (ResourceAFPathsMap, error) {

	// TODO: desiredServiceAFPaths this is per-service map, but should be per-frontend map
	// Let's try making ResourceAFPathsMap more generic - allowing string as a key
	// Then, we may use frontend.ID or frontend.Address.String() as the key

	desiredServiceAFPaths := make(ResourceAFPathsMap)
	for _, frontend := range toReconcile {
		svcKey := resource.Key{
			Name:      frontend.ServiceName.Name(),
			Namespace: frontend.ServiceName.Namespace(),
		}

		afPaths, err := r.getServiceAFPaths(p, desiredPeerAdverts, frontend)
		if err != nil {
			return nil, err
		}

		desiredServiceAFPaths[svcKey] = afPaths
	}

	for _, svcKey := range toWithdraw {
		// for withdrawn services, we need to set paths to nil.
		desiredServiceAFPaths[svcKey] = nil
	}

	return desiredServiceAFPaths, nil
}

func (r *ServiceReconciler) getServiceAFPaths(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, fe *loadbalancer.Frontend) (AFPathsMap, error) {
	desiredFamilyAdverts := make(AFPathsMap) // TODO: probably does not have to be a map, just single AFPath

	for _, peerFamilyAdverts := range desiredPeerAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)

			for _, advert := range familyAdverts {
				// get prefixes for the service
				desiredPrefixes, err := r.getServicePrefixes(p, fe, advert)
				if err != nil {
					return nil, err
				}

				for _, prefix := range desiredPrefixes {
					// we only add path corresponding to the family of the prefix.
					if agentFamily.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
						path := types.NewPathForPrefix(prefix)
						path.Family = agentFamily
						addPathToAFPathsMap(desiredFamilyAdverts, agentFamily, path)
					}
					if agentFamily.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
						path := types.NewPathForPrefix(prefix)
						path.Family = agentFamily
						addPathToAFPathsMap(desiredFamilyAdverts, agentFamily, path)
					}
				}
			}
		}
	}
	return desiredFamilyAdverts, nil
}

func (r *ServiceReconciler) getServicePrefixes(p ReconcileParams, fe *loadbalancer.Frontend, advert v2.BGPAdvertisement) ([]netip.Prefix, error) {
	if advert.AdvertisementType != v2.BGPServiceAdvert {
		return nil, fmt.Errorf("unexpected advertisement type: %s", advert.AdvertisementType)
	}

	if advert.Selector == nil || advert.Service == nil {
		// advertisement has no selector or no service options, default behavior is not to match any service.
		return nil, nil
	}

	// The vRouter has a service selector, so determine the desired routes.
	svcSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
	if err != nil {
		return nil, fmt.Errorf("labelSelectorAsSelector: %w", err)
	}

	// Ignore non-matching services.
	if !svcSelector.Matches(serviceLabelSet(fe.Service)) {
		return nil, nil
	}

	var desiredRoutes []netip.Prefix // TODO: this always returns single prefix, does not need to be a slice
	// Loop over the service upsertAdverts and determine the desired routes.
	for _, svcAdv := range advert.Service.Addresses {
		switch svcAdv {
		case v2.BGPLoadBalancerIPAddr:
			desiredRoutes = append(desiredRoutes, r.getLBSvcPaths(p, fe, advert)...)
		case v2.BGPClusterIPAddr:
			desiredRoutes = append(desiredRoutes, r.getClusterIPPaths(p, fe, advert)...)
		case v2.BGPExternalIPAddr:
			desiredRoutes = append(desiredRoutes, r.getExternalIPPaths(p, fe, advert)...)
		}
	}

	return desiredRoutes, nil
}

// TODO: the following 3 probably can be consolidated into a single method now
func (r *ServiceReconciler) getExternalIPPaths(p ReconcileParams, fe *loadbalancer.Frontend, advert v2.BGPAdvertisement) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	if fe.Type != loadbalancer.SVCTypeExternalIPs {
		return desiredRoutes
	}
	// Ignore externalTrafficPolicy == Local && no local EPs.
	if fe.Service.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal && !hasLocalBackends(p, fe) {
		return desiredRoutes
	}

	addr := fe.Address.AddrCluster.Addr()
	prefix, err := addr.Prefix(getServicePrefixLength(fe, addr, advert, v2.BGPExternalIPAddr))
	if err != nil {
		return desiredRoutes
	}
	desiredRoutes = append(desiredRoutes, prefix)

	return desiredRoutes
}

func (r *ServiceReconciler) getClusterIPPaths(p ReconcileParams, fe *loadbalancer.Frontend, advert v2.BGPAdvertisement) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	if fe.Type != loadbalancer.SVCTypeClusterIP {
		return desiredRoutes
	}
	// Ignore internalTrafficPolicy == Local && no local EPs.
	if fe.Service.IntTrafficPolicy != loadbalancer.SVCTrafficPolicyLocal && !hasLocalBackends(p, fe) {
		return desiredRoutes
	}

	addr := fe.Address.AddrCluster.Addr()
	prefix, err := addr.Prefix(getServicePrefixLength(fe, addr, advert, v2.BGPClusterIPAddr))
	if err != nil {
		return desiredRoutes
	}
	desiredRoutes = append(desiredRoutes, prefix)

	return desiredRoutes
}

func (r *ServiceReconciler) getLBSvcPaths(p ReconcileParams, fe *loadbalancer.Frontend, advert v2.BGPAdvertisement) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	if fe.Type != loadbalancer.SVCTypeLoadBalancer {
		return desiredRoutes
	}
	// Ignore externalTrafficPolicy == Local && no local EPs.
	if fe.Service.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal && !hasLocalBackends(p, fe) {
		return desiredRoutes
	}
	// Ignore service managed by an unsupported LB class.
	if fe.Service.LoadBalancerClass != nil && *fe.Service.LoadBalancerClass != v2.BGPLoadBalancerClass {
		// The service is managed by a different LB class.
		return desiredRoutes
	}

	addr := fe.Address.AddrCluster.Addr()
	prefix, err := addr.Prefix(getServicePrefixLength(fe, addr, advert, v2.BGPLoadBalancerIPAddr))
	if err != nil {
		return desiredRoutes
	}

	desiredRoutes = append(desiredRoutes, prefix)
	return desiredRoutes
}

func (r *ServiceReconciler) getServiceRoutePolicy(p ReconcileParams, peer PeerID, family types.Family, fe *loadbalancer.Frontend, advert v2.BGPAdvertisement, advertType v2.BGPServiceAddressType) (*types.RoutePolicy, error) {
	if peer.Address == "" {
		return nil, nil
	}
	peerAddr, err := netip.ParseAddr(peer.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer address: %w", err)
	}

	valid, err := checkServiceAdvertisement(advert, advertType)
	if err != nil {
		return nil, fmt.Errorf("failed to check %s advertisement: %w", advertType, err)
	}
	if !valid {
		return nil, nil
	}

	var svcPrefixes []netip.Prefix
	switch advertType {
	case v2.BGPLoadBalancerIPAddr:
		svcPrefixes = r.getLBSvcPaths(p, fe, advert)
	case v2.BGPExternalIPAddr:
		svcPrefixes = r.getExternalIPPaths(p, fe, advert)
	case v2.BGPClusterIPAddr:
		svcPrefixes = r.getClusterIPPaths(p, fe, advert)
	}

	var v4Prefixes, v6Prefixes types.PolicyPrefixMatchList
	for _, prefix := range svcPrefixes {
		if family.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
			v4Prefixes = append(v4Prefixes, &types.RoutePolicyPrefixMatch{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()})
		}
		if family.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
			v6Prefixes = append(v6Prefixes, &types.RoutePolicyPrefixMatch{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()})
		}
	}
	if len(v4Prefixes) == 0 && len(v6Prefixes) == 0 {
		return nil, nil
	}

	// TODO: with aggregation enabled, we are rendering too many policies
	policyName := PolicyName(peer.Name, family.Afi.String(), advert.AdvertisementType, fmt.Sprintf("%s-%s-%s", fe.ServiceName.Name(), fe.ServiceName.Namespace(), advertType))
	policy, err := CreatePolicy(policyName, peerAddr, v4Prefixes, v6Prefixes, advert)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s IP route policy: %w", advertType, err)
	}

	return policy, nil
}

// checkServiceAdvertisement checks if the service advertisement is enabled in the advertisement.
func checkServiceAdvertisement(advert v2.BGPAdvertisement, advertServiceType v2.BGPServiceAddressType) (bool, error) {
	if advert.Service == nil {
		return false, fmt.Errorf("advertisement has no service options")
	}

	// If selector is nil, we do not use this advertisement.
	if advert.Selector == nil {
		return false, nil
	}

	// check service type is enabled in advertisement
	svcTypeEnabled := slices.Contains(advert.Service.Addresses, advertServiceType)
	if !svcTypeEnabled {
		return false, nil
	}

	return true, nil
}

func serviceLabelSet(svc *loadbalancer.Service) labels.Labels {
	svcLabels := maps.Clone(svc.Labels.StringMap())
	if svcLabels == nil {
		svcLabels = make(map[string]string)
	}
	svcLabels["io.kubernetes.service.name"] = svc.Name.Name()
	svcLabels["io.kubernetes.service.namespace"] = svc.Name.Namespace()
	return labels.Set(svcLabels)
}

func getServicePrefixLength(fe *loadbalancer.Frontend, addr netip.Addr, advert v2.BGPAdvertisement, addrType v2.BGPServiceAddressType) int {
	length := addr.BitLen()

	if addrType == v2.BGPClusterIPAddr {
		// for iTP=Local, we always use the full prefix length
		if fe.Service.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
			return length
		}
	} else {
		// for eTP=Local, we always use the full prefix length
		if fe.Service.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
			return length
		}
	}

	if addr.Is4() && advert.Service.AggregationLengthIPv4 != nil {
		length = int(*advert.Service.AggregationLengthIPv4)
	}

	if addr.Is6() && advert.Service.AggregationLengthIPv6 != nil {
		length = int(*advert.Service.AggregationLengthIPv6)
	}
	return length
}
