// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/cilium/hive/script"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	bgppacket "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
)

const (
	padding     = 3
	minWidth    = 5
	paddingChar = ' '

	defaultTimeout = 10 * time.Second
)

var (
	// log is the logger passed to gobgp instances
	log = &logrus.Logger{
		Out:   os.Stdout,
		Hooks: make(logrus.LevelHooks),
		Formatter: &logrus.TextFormatter{
			DisableTimestamp: false,
			DisableColors:    false,
		},
		Level: logrus.DebugLevel,
	}
)

type cmdContext struct {
	servers map[uint32]*server.BgpServer
}

func NewCmdContext() *cmdContext {
	return &cmdContext{
		servers: make(map[uint32]*server.BgpServer),
	}
}

func (ctx *cmdContext) Cleanup() {
	for _, s := range ctx.servers {
		s.Stop()
	}
}

func ScriptCmds(ctx *cmdContext) map[string]script.Cmd {
	return map[string]script.Cmd{
		"gobgp/add-server": addServerCmd(ctx),
		"gobgp/add-peer":   addPeerCmd(ctx),
		"gobgp/wait-state": waitStateCmd(ctx),
		"gobgp":            goBGPCmd(ctx),
	}
}

func addServerCmd(cmdCtx *cmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Add a new GoBGP server instance with the specified parameters",
			Args:    "asn router-id port",
			Detail: []string{
				"Add GoBGP server instance with the specified ASN and router-id listening on the specified port.",
				"'ASN' is the autonomous system number of this instance.",
				"'router-id' is the IP address used as the server's router-id.",
				"'port' is the port number on which the server listens for incoming connections.",
				"'port' with the value -1 means that the server will not listen for incoming connections.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 3 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/add-server asn router-id port'")
			}
			asn, err := strconv.Atoi(args[0])
			if err != nil {
				return nil, fmt.Errorf("could not parse asn: %v", err)
			}
			port, err := strconv.Atoi(args[2])
			if err != nil {
				return nil, fmt.Errorf("could not parse port: %v", err)
			}

			// start new GoBGP server
			gobgpServer := server.NewBgpServer(server.LoggerOption(gobgp.NewServerLogger(log, gobgp.LogParams{
				AS:        uint32(asn),
				Component: "test",
				SubSys:    "gobgp",
			})))
			go gobgpServer.Serve()
			err = gobgpServer.StartBgp(context.Background(), &gobgpapi.StartBgpRequest{Global: &gobgpapi.Global{
				Asn:        uint32(asn),
				RouterId:   args[1],
				ListenPort: int32(port),
			}})
			if err != nil {
				gobgpServer.Stop()
				return nil, err
			}
			cmdCtx.servers[uint32(asn)] = gobgpServer

			s.Logf("Started GoBGP Server ASN: %d, router-id: %s, port: %d\n", asn, args[1], port)
			return nil, nil
		},
	)
}

func addPeerCmd(cmdCtx *cmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Adds a new peer with the given IP and remote ASN to the GoBGP server instance",
			Args:    "ip remote-asn",
			Flags: func(fs *pflag.FlagSet) {
				fs.Uint32("server-asn", 0, "ASN number of the GoBGP server instance. Can be omitted if only one instance is active.")
			},
			Detail: []string{
				"Adds a new peer with the given IP and remote ASN to the GoBGP server instance.",
				"'ip' is IP address of the peer.",
				"'remote-asn' is the remote ASN number of the peer.",
				"If there are multiple server instances configured, the server-asn flag needs to be specified.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/ass-peer ip remote-asn'")
			}
			gobgpServer, err := getGoBGPServer(s, cmdCtx)
			if err != nil {
				return nil, err
			}

			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()
			peer := &gobgpapi.Peer{
				Conf: &gobgpapi.PeerConf{
					NeighborAddress: args[0],
				},
				Transport: &gobgpapi.Transport{
					LocalAddress: "10.0.1.100", // TODO pass via a context
					PassiveMode:  true,
				},
			}
			_, err = fmt.Sscanf(args[1], "%d", &peer.Conf.PeerAsn)
			if err != nil {
				return nil, fmt.Errorf("could not parse remote-asn: %v", err)
			}
			err = gobgpServer.AddPeer(ctx, &gobgpapi.AddPeerRequest{Peer: peer})
			if err != nil {
				return nil, fmt.Errorf("error by adding peer to server: %v", err)
			}
			return nil, nil
		},
	)
}

func waitStateCmd(cmdCtx *cmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Wait until the specified peer is in the specified state",
			Args:    "peer state",
			Flags: func(fs *pflag.FlagSet) {
				fs.Duration("timeout", 10*time.Second, "Maximum amount of time to wait for the peering state")
				fs.Uint32("server-asn", 0, "ASN number of the GoBGP server instance. Can be omitted if only one instance is active.")
			},
			Detail: []string{
				"Wait until the specified peer is in the specified state.",
				"'peer' is IP address of a previously configured peer.",
				"'state' is one of: 'UNKNOWN', 'IDLE', 'CONNECT', 'ACTIVE', 'OPENSENT', 'OPENCONFIRM', 'ESTABLISHED'.",
				"If there are multiple server instances configured, the server-asn flag needs to be specified.",
				"The default wait timeout is 10 seconds.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("invalid command format, should be: 'gobgp/wait-state peer state'")
			}
			timeout, err := s.Flags.GetDuration("timeout")
			if err != nil {
				return nil, fmt.Errorf("could not parse timeout: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			gobgpServer, err := getGoBGPServer(s, cmdCtx)
			if err != nil {
				return nil, err
			}

			doneCh := make(chan struct{})
			watchRequest := &gobgpapi.WatchEventRequest{
				Peer: &gobgpapi.WatchEventRequest_Peer{},
			}
			err = gobgpServer.WatchEvent(ctx, watchRequest, func(r *gobgpapi.WatchEventResponse) {
				if p := r.GetPeer(); p != nil && p.Type == gobgpapi.WatchEventResponse_PeerEvent_STATE {
					s.Logf("peer %s %s\n", p.Peer.Conf.NeighborAddress, p.Peer.State.SessionState)
					if p.Peer.State.SessionState == gobgpapi.PeerState_SessionState(gobgpapi.PeerState_SessionState_value[args[1]]) {
						if p.Peer.Conf.NeighborAddress == args[0] {
							doneCh <- struct{}{}
						}
					}
				}
			})
			if err != nil {
				return nil, err
			}
			select {
			case <-s.Context().Done():
				return nil, s.Context().Err()
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-doneCh:
			}
			return nil, nil
		},
	)
}

func goBGPCmd(ctx *cmdContext) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "gobgp CLI",
			Args:    "cmd args...",
		},
		func(s *script.State, args ...string) (waitFunc script.WaitFunc, err error) {
			if len(ctx.servers) == 0 {
				return nil, fmt.Errorf("no GoBGP servers configured")
			}
			var server *server.BgpServer
			for _, s := range ctx.servers {
				server = s // TODO
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			buf := bytes.Buffer{}
			writer := bufio.NewWriter(&buf)
			w := tabwriter.NewWriter(writer, minWidth, 0, padding, paddingChar, 0)

			outFile := ""

			if len(args) < 1 {
				return nil, fmt.Errorf("gobgp cmd args...\n'cmd' is one of: peer, routes")
			}
			switch args[0] {
			case "peers":
				printPeerHeader(w)
				err = server.ListPeer(ctx, &gobgpapi.ListPeerRequest{EnableAdvertised: true}, func(p *gobgpapi.Peer) {
					printPeer(w, p)
				})
				if len(args) > 1 {
					outFile = args[1]
				}

			case "routes":
				req := &gobgpapi.ListPathRequest{
					TableType: gobgpapi.TableType_GLOBAL,
					Family: &gobgpapi.Family{
						Afi:  gobgpapi.Family_AFI_IP,
						Safi: gobgpapi.Family_SAFI_UNICAST,
					},
				}
				printPathHeader(w)
				err = server.ListPath(ctx, req, func(dst *gobgpapi.Destination) {
					printPath(w, dst)
				})
				if len(args) > 1 {
					outFile = args[1]
				}

			default:
				return nil, fmt.Errorf("unknown gobgp command %q, expected one of: peer, routes", args[0])
			}

			w.Flush()
			writer.Flush()
			if outFile != "" {
				os.WriteFile(filepath.Join(s.Getwd()+"/"+outFile), buf.Bytes(), 0666) // filepath.join does not work here
			} else {
				os.Stdout.Write(buf.Bytes())
			}
			return nil, err
		},
	)
}

func getGoBGPServer(s *script.State, ctx *cmdContext) (*server.BgpServer, error) {
	if len(ctx.servers) == 0 {
		return nil, fmt.Errorf("no GoBGP servers configured")
	}
	asn, err := s.Flags.GetUint32("server-asn")
	if err != nil {
		return nil, fmt.Errorf("could not parse server-asn: %v", err)
	}
	if asn == 0 {
		// asn not specified
		if len(ctx.servers) > 1 {
			return nil, fmt.Errorf("multiple GoBGP servers are active, server-asn flag is required")
		} else {
			// only one server configured, return it
			for _, serv := range ctx.servers {
				return serv, nil
			}
		}
	}
	return ctx.servers[asn], nil
}

func printPeerHeader(w *tabwriter.Writer) {
	fmt.Fprintln(w, "PeerAddress\tPeerASN\tSessionState")
}

func printPeer(w *tabwriter.Writer, peer *gobgpapi.Peer) {
	fmt.Fprintf(w, "%s\t%d\t%s\n", peer.Conf.NeighborAddress, peer.State.PeerAsn, peer.State.SessionState)
}

func printPathHeader(w *tabwriter.Writer) {
	fmt.Fprintln(w, "Prefix\tNextHop\tAttrs")
}

func printPath(w *tabwriter.Writer, dst *gobgpapi.Destination) {
	aPaths, _ := gobgp.ToAgentPaths(dst.Paths)
	for _, path := range aPaths {
		fmt.Fprintf(w, "%s\t%s\t%s\n", dst.Prefix, nextHopFromPathAttributes(path.PathAttributes), path.PathAttributes)
	}
}

func nextHopFromPathAttributes(pathAttributes []bgppacket.PathAttributeInterface) string {
	for _, a := range pathAttributes {
		switch attr := a.(type) {
		case *bgppacket.PathAttributeNextHop:
			return attr.Value.String()
		case *bgppacket.PathAttributeMpReachNLRI:
			return attr.Nexthop.String()
		}
	}
	return "0.0.0.0"
}
