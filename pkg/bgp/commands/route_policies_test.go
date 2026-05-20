// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/types"
)

func TestPrintBGPRoutePoliciesTableIncludesInstanceAndStatementNames(t *testing.T) {
	var out strings.Builder
	tw := getCmdTabWriter(&out)

	PrintBGPRoutePoliciesTable(tw, []agent.InstanceRoutePolicies{
		{
			Name: "blue-instance",
			RoutePolicies: []*types.RoutePolicy{
				{
					Name: "cilium-export",
					Type: types.RoutePolicyTypeExport,
					Statements: []*types.RoutePolicyStatement{
						{
							Name: "z-statement",
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
						{
							Name: "a-statement",
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionReject,
							},
						},
					},
				},
			},
		},
	})
	require.NoError(t, tw.Flush())

	req := require.New(t)
	req.Contains(out.String(), "Instance")
	req.Contains(out.String(), "Policy")
	req.Contains(out.String(), "Type")
	req.Contains(out.String(), "Statement")
	req.Less(strings.Index(out.String(), "Policy"), strings.Index(out.String(), "Type"))
	req.Less(strings.Index(out.String(), "Type"), strings.Index(out.String(), "Statement"))
	req.Contains(out.String(), "blue-instance")
	req.Contains(out.String(), "z-statement")
	req.Contains(out.String(), "a-statement")
	req.Less(strings.Index(out.String(), "z-statement"), strings.Index(out.String(), "a-statement"))
	req.NotContains(out.String(), "65001")

	zLine := lineContaining(out.String(), "z-statement")
	req.Contains(zLine, "blue-instance")
	req.Contains(zLine, "cilium-export")
	req.Contains(zLine, "export")
	req.Less(strings.Index(zLine, "export"), strings.Index(zLine, "z-statement"))

	aLine := lineContaining(out.String(), "a-statement")
	req.NotContains(aLine, "blue-instance")
	req.NotContains(aLine, "cilium-export")
	req.NotContains(aLine, "export")
}

func lineContaining(output, needle string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}
