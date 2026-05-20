// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/types"
)

func TestWriteTableJSON(t *testing.T) {
	var out bytes.Buffer

	err := writeTableJSON(
		&out,
		[]string{"Instance", "Peer", "Family"},
		[][]string{
			{"65001", "65000", "ipv4-unicast"},
			{"65001", "65000", "ipv6-unicast"},
		},
	)
	require.NoError(t, err)

	var table tableJSON
	err = json.Unmarshal(out.Bytes(), &table)
	require.NoError(t, err)
	require.Equal(t, []string{"Instance", "Peer", "Family"}, table.Columns)
	require.Equal(t, []map[string]string{
		{
			"Instance": "65001",
			"Peer":     "65000",
			"Family":   "ipv4-unicast",
		},
		{
			"Instance": "65001",
			"Peer":     "65000",
			"Family":   "ipv6-unicast",
		},
	}, table.Rows)
}

func TestPeerStateTableRowsDeduplicate(t *testing.T) {
	instances := []agent.InstancePeerStates{
		{
			Name: "65001",
			Peers: []types.PeerState{
				{
					Name:         "65000",
					SessionState: types.SessionEstablished,
					Uptime:       2*time.Minute + 45*time.Second,
					Families: []types.PeerFamilyState{
						{
							Family:           types.Family{Afi: types.AfiIPv4, Safi: types.SafiUnicast},
							ReceivedRoutes:   6,
							AcceptedRoutes:   0,
							AdvertisedRoutes: 6,
						},
						{
							Family:           types.Family{Afi: types.AfiIPv6, Safi: types.SafiUnicast},
							ReceivedRoutes:   5,
							AcceptedRoutes:   0,
							AdvertisedRoutes: 5,
						},
					},
				},
			},
		},
	}

	fullRows := peerStateTableFieldRows(instances, false, false)
	require.Equal(t, [][]string{
		{"65001", "65000", "established", "2m45s", "ipv4-unicast", "6", "0", "6"},
		{"65001", "65000", "established", "2m45s", "ipv6-unicast", "5", "0", "5"},
	}, fullRows)

	rows := peerStateTableFieldRows(instances, false, true)
	require.Equal(t, [][]string{
		{"65001", "65000", "established", "2m45s", "ipv4-unicast", "6", "0", "6"},
		{"", "", "", "", "ipv6-unicast", "5", "0", "5"},
	}, rows)
}
