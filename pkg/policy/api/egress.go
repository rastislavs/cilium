// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/slices"
)

// EgressCommonRule is a rule that shares some of its fields across the
// EgressRule and EgressDenyRule. It's publicly exported so the code generators
// can generate code for this structure.
//
// +deepequal-gen:private-method=true
type EgressCommonRule struct {
	// ToEndpoints is a list of endpoints identified by an EndpointSelector to
	// which the endpoints subject to the rule are allowed to communicate.
	//
	// Example:
	// Any endpoint with the label "role=frontend" can communicate with any
	// endpoint carrying the label "role=backend".
	//
	// +kubebuilder:validation:Optional
	ToEndpoints []EndpointSelector `json:"toEndpoints,omitempty"`

	// ToRequires is a list of additional constraints which must be met
	// in order for the selected endpoints to be able to connect to other
	// endpoints. These additional constraints do no by itself grant access
	// privileges and must always be accompanied with at least one matching
	// ToEndpoints.
	//
	// Example:
	// Any Endpoint with the label "team=A" requires any endpoint to which it
	// communicates to also carry the label "team=A".
	//
	// +kubebuilder:validation:Optional
	ToRequires []EndpointSelector `json:"toRequires,omitempty"`

	// ToCIDR is a list of IP blocks which the endpoint subject to the rule
	// is allowed to initiate connections. Only connections destined for
	// outside of the cluster and not targeting the host will be subject
	// to CIDR rules.  This will match on the destination IP address of
	// outgoing connections. Adding a prefix into ToCIDR or into ToCIDRSet
	// with no ExcludeCIDRs is equivalent. Overlaps are allowed between
	// ToCIDR and ToCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=database-proxy" is allowed to
	// initiate connections to 10.2.3.0/24
	//
	// +kubebuilder:validation:Optional
	ToCIDR CIDRSlice `json:"toCIDR,omitempty"`

	// ToCIDRSet is a list of IP blocks which the endpoint subject to the rule
	// is allowed to initiate connections to in addition to connections
	// which are allowed via ToEndpoints, along with a list of subnets contained
	// within their corresponding IP block to which traffic should not be
	// allowed. This will match on the destination IP address of outgoing
	// connections. Adding a prefix into ToCIDR or into ToCIDRSet with no
	// ExcludeCIDRs is equivalent. Overlaps are allowed between ToCIDR and
	// ToCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=database-proxy" is allowed to
	// initiate connections to 10.2.3.0/24 except from IPs in subnet 10.2.3.0/28.
	//
	// +kubebuilder:validation:Optional
	ToCIDRSet CIDRRuleSlice `json:"toCIDRSet,omitempty"`

	// ToEntities is a list of special entities to which the endpoint subject
	// to the rule is allowed to initiate connections. Supported entities are
	// `world`, `cluster`, `host`, `remote-node`, `kube-apiserver`, `ingress`, `init`,
	// `health`, `unmanaged`, `none` and `all`.
	//
	// +kubebuilder:validation:Optional
	ToEntities EntitySlice `json:"toEntities,omitempty"`

	// ToServices is a list of services to which the endpoint subject
	// to the rule is allowed to initiate connections.
	// Currently Cilium only supports toServices for K8s services.
	//
	// +kubebuilder:validation:Optional
	ToServices []Service `json:"toServices,omitempty"`

	// ToGroups is a directive that allows the integration with multiple outside
	// providers. Currently, only AWS is supported, and the rule can select by
	// multiple sub directives:
	//
	// Example:
	// toGroups:
	// - aws:
	//     securityGroupsIds:
	//     - 'sg-XXXXXXXXXXXXX'
	//
	// +kubebuilder:validation:Optional
	ToGroups []Groups `json:"toGroups,omitempty"`

	// ToNodes is a list of nodes identified by an
	// EndpointSelector to which endpoints subject to the rule is allowed to communicate.
	//
	// +kubebuilder:validation:Optional
	ToNodes []EndpointSelector `json:"toNodes,omitempty"`

	// TODO: Move this to the policy package
	// (https://github.com/cilium/cilium/issues/8353)
	aggregatedSelectors EndpointSelectorSlice `json:"-"`
}

// DeepEqual returns true if both EgressCommonRule are deep equal.
// The semantic of a nil slice in one of its fields is different from the semantic
// of an empty non-nil slice, thus it explicitly checks for that case before calling
// the autogenerated method.
func (in *EgressCommonRule) DeepEqual(other *EgressCommonRule) bool {
	if slices.XorNil(in.ToEndpoints, other.ToEndpoints) {
		return false
	}
	if slices.XorNil(in.ToCIDR, other.ToCIDR) {
		return false
	}
	if slices.XorNil(in.ToCIDRSet, other.ToCIDRSet) {
		return false
	}
	if slices.XorNil(in.ToEntities, other.ToEntities) {
		return false
	}

	return in.deepEqual(other)
}

// EgressRule contains all rule types which can be applied at egress, i.e.
// network traffic that originates inside the endpoint and exits the endpoint
// selected by the endpointSelector.
//
//   - All members of this structure are optional. If omitted or empty, the
//     member will have no effect on the rule.
//
//   - If multiple members of the structure are specified, then all members
//     must match in order for the rule to take effect. The exception to this
//     rule is the ToRequires member; the effects of any Requires field in any
//     rule will apply to all other rules as well.
//
//   - ToEndpoints, ToCIDR, ToCIDRSet, ToEntities, ToServices and ToGroups are
//     mutually exclusive. Only one of these members may be present within an
//     individual rule.
type EgressRule struct {
	EgressCommonRule `json:",inline"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// connect to.
	//
	// Example:
	// Any endpoint with the label "role=frontend" is allowed to initiate
	// connections to destination port 8080/tcp
	//
	// +kubebuilder:validation:Optional
	ToPorts PortRules `json:"toPorts,omitempty"`

	// ToFQDN allows whitelisting DNS names in place of IPs. The IPs that result
	// from DNS resolution of `ToFQDN.MatchName`s are added to the same
	// EgressRule object as ToCIDRSet entries, and behave accordingly. Any L4 and
	// L7 rules within this EgressRule will also apply to these IPs.
	// The DNS -> IP mapping is re-resolved periodically from within the
	// cilium-agent, and the IPs in the DNS response are effected in the policy
	// for selected pods as-is (i.e. the list of IPs is not modified in any way).
	// Note: An explicit rule to allow for DNS traffic is needed for the pods, as
	// ToFQDN counts as an egress rule and will enforce egress policy when
	// PolicyEnforcment=default.
	// Note: If the resolved IPs are IPs within the kubernetes cluster, the
	// ToFQDN rule will not apply to that IP.
	// Note: ToFQDN cannot occur in the same policy as other To* rules.
	//
	// +kubebuilder:validation:Optional
	ToFQDNs FQDNSelectorSlice `json:"toFQDNs,omitempty"`

	// ICMPs is a list of ICMP rule identified by type number
	// which the endpoint subject to the rule is allowed to connect to.
	//
	// Example:
	// Any endpoint with the label "app=httpd" is allowed to initiate
	// type 8 ICMP connections.
	//
	// +kubebuilder:validation:Optional
	ICMPs ICMPRules `json:"icmps,omitempty"`

	// Authentication is the required authentication type for the allowed traffic, if any.
	//
	// +kubebuilder:validation:Optional
	Authentication *Authentication `json:"authentication,omitempty"`
}

// EgressDenyRule contains all rule types which can be applied at egress, i.e.
// network traffic that originates inside the endpoint and exits the endpoint
// selected by the endpointSelector.
//
//   - All members of this structure are optional. If omitted or empty, the
//     member will have no effect on the rule.
//
//   - If multiple members of the structure are specified, then all members
//     must match in order for the rule to take effect. The exception to this
//     rule is the ToRequires member; the effects of any Requires field in any
//     rule will apply to all other rules as well.
//
//   - ToEndpoints, ToCIDR, ToCIDRSet, ToEntities, ToServices and ToGroups are
//     mutually exclusive. Only one of these members may be present within an
//     individual rule.
type EgressDenyRule struct {
	EgressCommonRule `json:",inline"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is not allowed to connect
	// to.
	//
	// Example:
	// Any endpoint with the label "role=frontend" is not allowed to initiate
	// connections to destination port 8080/tcp
	//
	// +kubebuilder:validation:Optional
	ToPorts PortDenyRules `json:"toPorts,omitempty"`

	// ICMPs is a list of ICMP rule identified by type number
	// which the endpoint subject to the rule is not allowed to connect to.
	//
	// Example:
	// Any endpoint with the label "app=httpd" is not allowed to initiate
	// type 8 ICMP connections.
	//
	// +kubebuilder:validation:Optional
	ICMPs ICMPRules `json:"icmps,omitempty"`
}

// SetAggregatedSelectors creates a single slice containing all of the following
// fields within the EgressCommonRule, converted to EndpointSelector, to be
// stored by the caller of the EgressCommonRule for easy lookup while performing
// policy evaluation for the rule:
// * ToEntities
// * ToCIDR
// * ToCIDRSet
// * ToFQDNs
//
// ToEndpoints is not aggregated due to requirement folding in
// GetDestinationEndpointSelectorsWithRequirements()
func (e *EgressCommonRule) getAggregatedSelectors() EndpointSelectorSlice {
	// explicitly check for empty non-nil slices, it should not result in any identity being selected.
	if (e.ToEntities != nil && len(e.ToEntities) == 0) ||
		(e.ToCIDR != nil && len(e.ToCIDR) == 0) ||
		(e.ToCIDRSet != nil && len(e.ToCIDRSet) == 0) {
		return nil
	}

	res := make(EndpointSelectorSlice, 0, len(e.ToEntities)+len(e.ToCIDR)+len(e.ToCIDRSet))
	res = append(res, e.ToEntities.GetAsEndpointSelectors()...)
	res = append(res, e.ToCIDR.GetAsEndpointSelectors()...)
	res = append(res, e.ToCIDRSet.GetAsEndpointSelectors()...)
	return res
}

// SetAggregatedSelectors creates a single slice containing all of the following
// fields within the EgressRule, converted to EndpointSelector, to be stored
// within the EgressRule for easy lookup while performing policy evaluation
// for the rule:
// * ToEntities
// * ToCIDR
// * ToCIDRSet
// * ToFQDNs
//
// ToEndpoints is not aggregated due to requirement folding in
// GetDestinationEndpointSelectorsWithRequirements()
func (e *EgressRule) SetAggregatedSelectors() {
	ess := e.getAggregatedSelectors()
	ess = append(ess, e.ToFQDNs.GetAsEndpointSelectors()...)
	e.aggregatedSelectors = ess
}

// SetAggregatedSelectors creates a single slice containing all of the following
// fields within the EgressRule, converted to EndpointSelector, to be stored
// within the EgressRule for easy lookup while performing policy evaluation
// for the rule:
// * ToEntities
// * ToCIDR
// * ToCIDRSet
// * ToFQDNs
//
// ToEndpoints is not aggregated due to requirement folding in
// GetDestinationEndpointSelectorsWithRequirements()
func (e *EgressCommonRule) SetAggregatedSelectors() {
	e.aggregatedSelectors = e.getAggregatedSelectors()
}

// GetDestinationEndpointSelectorsWithRequirements returns a slice of endpoints selectors covering
// all L3 dst selectors of the egress rule
func (e *EgressRule) GetDestinationEndpointSelectorsWithRequirements(requirements []slim_metav1.LabelSelectorRequirement) EndpointSelectorSlice {
	if e.aggregatedSelectors == nil {
		e.SetAggregatedSelectors()
	}
	return e.EgressCommonRule.getDestinationEndpointSelectorsWithRequirements(requirements)
}

// GetDestinationEndpointSelectorsWithRequirements returns a slice of endpoints selectors covering
// all L3 source selectors of the ingress rule
func (e *EgressDenyRule) GetDestinationEndpointSelectorsWithRequirements(requirements []slim_metav1.LabelSelectorRequirement) EndpointSelectorSlice {
	if e.aggregatedSelectors == nil {
		e.SetAggregatedSelectors()
	}
	return e.EgressCommonRule.getDestinationEndpointSelectorsWithRequirements(requirements)
}

// GetDestinationEndpointSelectorsWithRequirements returns a slice of endpoints selectors covering
// all L3 source selectors of the ingress rule
func (e *EgressCommonRule) getDestinationEndpointSelectorsWithRequirements(
	requirements []slim_metav1.LabelSelectorRequirement,
) EndpointSelectorSlice {

	// explicitly check for empty non-nil slices, it should not result in any identity being selected.
	if e.aggregatedSelectors == nil || (e.ToEndpoints != nil && len(e.ToEndpoints) == 0) ||
		(e.ToNodes != nil && len(e.ToNodes) == 0) {
		return nil
	}

	res := make(EndpointSelectorSlice, 0, len(e.ToEndpoints)+len(e.aggregatedSelectors)+len(e.ToNodes))

	if len(requirements) > 0 && len(e.ToEndpoints) > 0 {
		for idx := range e.ToEndpoints {
			sel := *e.ToEndpoints[idx].DeepCopy()
			sel.MatchExpressions = append(sel.MatchExpressions, requirements...)
			sel.SyncRequirementsWithLabelSelector()
			// Even though this string is deep copied, we need to override it
			// because we are updating the contents of the MatchExpressions.
			sel.cachedLabelSelectorString = sel.LabelSelector.String()
			res = append(res, sel)
		}
	} else {
		res = append(res, e.ToEndpoints...)
		res = append(res, e.ToNodes...)
	}
	return append(res, e.aggregatedSelectors...)
}

// AllowsWildcarding returns true if wildcarding should be performed upon
// policy evaluation for the given rule.
func (e *EgressRule) AllowsWildcarding() bool {
	return e.EgressCommonRule.AllowsWildcarding() && len(e.ToFQDNs) == 0
}

// AllowsWildcarding returns true if wildcarding should be performed upon
// policy evaluation for the given rule.
func (e *EgressCommonRule) AllowsWildcarding() bool {
	return len(e.ToRequires)+len(e.ToServices) == 0
}

// RequiresDerivative returns true when the EgressCommonRule contains sections
// that need a derivative policy created in order to be enforced
// (e.g. ToGroups).
func (e *EgressCommonRule) RequiresDerivative() bool {
	return len(e.ToGroups) > 0
}

func (e *EgressCommonRule) IsL3() bool {
	if e == nil {
		return false
	}
	return len(e.ToEndpoints) > 0 ||
		len(e.ToRequires) > 0 ||
		len(e.ToCIDR) > 0 ||
		len(e.ToCIDRSet) > 0 ||
		len(e.ToEntities) > 0 ||
		len(e.ToGroups) > 0 ||
		len(e.ToNodes) > 0
}

// CreateDerivative will return a new rule based on the data gathered by the
// rules that creates a new derivative policy.
// In the case of ToGroups will call outside using the groups callback and this
// function can take a bit of time.
func (e *EgressRule) CreateDerivative(ctx context.Context) (*EgressRule, error) {
	newRule := e.DeepCopy()
	if !e.RequiresDerivative() {
		return newRule, nil
	}
	newRule.ToCIDRSet = make(CIDRRuleSlice, 0, len(e.ToGroups))
	cidrSet, err := ExtractCidrSet(ctx, e.ToGroups)
	if err != nil {
		return &EgressRule{}, err
	}
	newRule.ToCIDRSet = append(e.ToCIDRSet, cidrSet...)
	newRule.ToGroups = nil
	e.SetAggregatedSelectors()
	return newRule, nil
}

// CreateDerivative will return a new rule based on the data gathered by the
// rules that creates a new derivative policy.
// In the case of ToGroups will call outside using the groups callback and this
// function can take a bit of time.
func (e *EgressDenyRule) CreateDerivative(ctx context.Context) (*EgressDenyRule, error) {
	newRule := e.DeepCopy()
	if !e.RequiresDerivative() {
		return newRule, nil
	}
	newRule.ToCIDRSet = make(CIDRRuleSlice, 0, len(e.ToGroups))
	cidrSet, err := ExtractCidrSet(ctx, e.ToGroups)
	if err != nil {
		return &EgressDenyRule{}, err
	}
	newRule.ToCIDRSet = append(e.ToCIDRSet, cidrSet...)
	newRule.ToGroups = nil
	e.SetAggregatedSelectors()
	return newRule, nil
}
