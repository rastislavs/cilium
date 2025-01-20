// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/cilium/hive/script"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	bgppacket "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
)

const (
	padding     = 3
	minWidth    = 5
	paddingChar = ' '
)

func gobgpScriptCmd(server *server.BgpServer) script.Cmd {
	const defaultTimeout = time.Minute
	return script.Command(
		script.CmdUsage{
			Summary: "gobgp CLI",
			Args:    "cmd args...",
		},
		func(s *script.State, args ...string) (waitFunc script.WaitFunc, err error) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			defer cancel()

			buf := bytes.Buffer{}
			writer := bufio.NewWriter(&buf)
			w := tabwriter.NewWriter(writer, minWidth, 0, padding, paddingChar, 0)

			outFile := ""

			if len(args) < 1 {
				return nil, fmt.Errorf("gobgp cmd args...\n'cmd' is one of: peer, routes")
			}
			switch args[0] {
			case "peer":
				if len(args) > 1 && args[1] == "add" {
					peer := &gobgpapi.Peer{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: args[2],
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.0.1.100", // TODO pass via a context
							PassiveMode:  true,
						},
					}
					fmt.Sscanf(args[3], "%d", peer.Conf.PeerAsn)
					return nil, server.AddPeer(ctx, &gobgpapi.AddPeerRequest{Peer: peer})
				} else {
					return nil, fmt.Errorf("invalid gobgp args: %v", args)
				}

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
