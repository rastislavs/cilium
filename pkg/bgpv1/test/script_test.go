// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/bgpv1/test/gobgp"
	"github.com/cilium/cilium/pkg/defaults"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestScript(t *testing.T) {
	testutils.PrivilegedTest(t)

	logrus.SetLevel(logrus.DebugLevel)
	hivetest.LogLevel(slog.LevelDebug)
	slog.SetLogLoggerLevel(slog.LevelDebug)

	setup := func(t testing.TB, args []string) *script.Engine {
		var err error

		h := ciliumhive.New(
			client.FakeClientCell,
			daemonk8s.ResourcesCell,
			metrics.Cell,
			bgpv1.Cell,

			cell.Provide(func() *option.DaemonConfig {
				// BGP Manager uses the global variable option.Config so we need to set it there as well
				option.Config = &option.DaemonConfig{
					EnableBGPControlPlane:     true,
					BGPSecretsNamespace:       "bgp-secrets",
					BGPRouterIDAllocationMode: defaults.BGPRouterIDAllocationMode,
					IPAM:                      ipamOption.IPAMKubernetes,
				}
				return option.Config
			}),

			cell.Invoke(func() {
				types.SetName("test-node")
			}),
		)

		hiveLog := hivetest.Logger(t)
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(hiveLog, context.TODO()))
		})

		// Parse the shebang arguments in the script.
		flags := pflag.NewFlagSet("test-flags", pflag.ContinueOnError)
		peeringIPs := flags.StringSlice("peering-ips", nil, "List of IPs used for peering in the test")
		//h.RegisterFlags(flags)
		require.NoError(t, flags.Parse(args), "Error parsing test flags")

		// Setup test link & IPs
		err = netlink.LinkAdd(&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{Name: "bgp-test"},
		})
		require.NoError(t, err, "error by adding test link")
		l, err := netlink.LinkByName("bgp-test")
		require.NoError(t, err)
		for _, ip := range *peeringIPs {
			ipAddr, err := netip.ParseAddr(ip)
			bits := 32
			if ipAddr.Is6() {
				bits = 128
			}
			prefix := netip.PrefixFrom(ipAddr, bits)
			err = netlink.AddrAdd(l, toNetlinkAddr(prefix))
			require.NoError(t, err)
		}
		t.Cleanup(func() {
			netlink.LinkDel(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{Name: "bgp-test"},
			})
		})

		// set up GoBGP command
		gobgpCmdCtx := gobgp.NewCmdContext()
		t.Cleanup(gobgpCmdCtx.Cleanup)

		cmds, err := h.ScriptCommands(hiveLog)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))
		maps.Insert(cmds, maps.All(gobgp.ScriptCmds(gobgpCmdCtx)))

		return &script.Engine{
			Cmds: cmds,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		[]string{"PATH=" + os.Getenv("PATH")},
		"testdata/*.txtar")
}
