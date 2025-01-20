// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"log/slog"
	"maps"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
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

		// Run the test in a new network namespace.
		origNS := netns.None()
		newNS := netns.None()
		runtime.LockOSThread()

		t.Cleanup(func() {
			if origNS.IsOpen() {
				netns.Set(origNS)
				origNS.Close()
			}
			if newNS.IsOpen() {
				newNS.Close()
			}
			runtime.UnlockOSThread()
		})
		origNS, err = netns.Get()
		assert.NoError(t, err)
		newNS, err = netns.New()
		assert.NoError(t, err)

		h := ciliumhive.New(
			client.FakeClientCell,
			daemonk8s.ResourcesCell,
			metrics.Cell,
			bgpv1.Cell,

			cell.Provide(func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableBGPControlPlane:     true,
					BGPSecretsNamespace:       "bgp-secrets",
					BGPRouterIDAllocationMode: defaults.BGPRouterIDAllocationMode,
					IPAM:                      ipamOption.IPAMKubernetes,
				}
			}),

			cell.Invoke(func() {
				types.SetName("test-node")
			}),
		)

		hiveLog := hivetest.Logger(t)
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(hiveLog, context.TODO()))
		})

		gobgpServer := server.NewBgpServer(server.LoggerOption(gobgp.NewServerLogger(log, gobgp.LogParams{
			AS:        65000,
			Component: "test",
			SubSys:    "gobgp",
		})))
		go gobgpServer.Serve()
		t.Cleanup(gobgpServer.Stop)

		err = gobgpServer.StartBgp(context.Background(), &gobgpapi.StartBgpRequest{Global: &gobgpapi.Global{
			Asn:        65000,
			RouterId:   "10.0.1.100",
			ListenPort: 179,
		}})
		require.NoError(t, err)

		// Parse the shebang arguments in the script.
		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)
		require.NoError(t, flags.Parse(args), "flags.Parse")

		cmds, err := h.ScriptCommands(hiveLog)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))
		cmds["gobgp"] = gobgpScriptCmd(gobgpServer)

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
