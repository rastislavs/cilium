// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package route

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type Route struct {
	Prefix   net.IPNet
	Nexthop  *net.IP
	Local    net.IP
	Device   string
	MTU      int
	Priority int
	Proto    int
	Scope    netlink.Scope
	Table    int
	Type     int
}

// LogAttrs returns the route attributes as slog attributes.
// The return type is []any to match with signature of With().
func (r *Route) LogAttrs() []any {
	nexthop := "<nil>"
	if r.Nexthop != nil {
		nexthop = r.Nexthop.String()
	}

	return []any{
		slog.String("prefix", r.Prefix.String()),
		slog.String("nexthop", nexthop),
		slog.String("local", r.Local.String()),
		slog.String(logfields.Interface, r.Device),
	}
}

// ByMask is used to sort an array of routes by mask, narrow first.
type ByMask []Route

func (a ByMask) Len() int {
	return len(a)
}

func (a ByMask) Less(i, j int) bool {
	lenA, _ := a[i].Prefix.Mask.Size()
	lenB, _ := a[j].Prefix.Mask.Size()
	return lenA > lenB
}

func (a ByMask) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// ToIPCommand converts the route into a full "ip route ..." command
func (r *Route) ToIPCommand(dev string) []string {
	res := []string{"ip"}
	if r.Prefix.IP.To4() == nil {
		res = append(res, "-6")
	}
	res = append(res, "route", "add", r.Prefix.String())
	if r.Priority != 0 {
		res = append(res, "metric", fmt.Sprintf("%d", r.Priority))
	}
	if r.Nexthop != nil {
		res = append(res, "via", r.Nexthop.String())
	}
	if r.MTU != 0 {
		res = append(res, "mtu", fmt.Sprintf("%d", r.MTU))
	}
	res = append(res, "dev", dev)
	return res
}
