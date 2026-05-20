// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTableJSONRowsToStrings(t *testing.T) {
	rows, err := tableJSONRowsToStrings(
		[]byte(`{
  "columns": [
    "Instance",
    "Peer",
    "Family",
    "Accepted"
  ],
  "rows": [
    {
      "Instance": "65001",
      "Peer": "65000",
      "Family": "ipv4-unicast",
      "Accepted": "0"
    },
    {
      "Instance": "65001",
      "Peer": "65000",
      "Family": "ipv6-unicast",
      "Accepted": "0"
    }
  ]
}`),
	)
	require.NoError(t, err)
	require.Equal(t, []string{
		"Instance\tPeer\tFamily\tAccepted",
		"65001\t65000\tipv4-unicast\t0",
		"\t\tipv6-unicast\t0",
	}, rows)
}
