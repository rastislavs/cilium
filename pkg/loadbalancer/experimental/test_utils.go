// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/lbmap"
)

var (
	// special addresses that are replaced by the test runner.
	autoAddr = loadbalancer.L3n4Addr{
		AddrCluster: types.MustParseAddrCluster("0.0.0.1"),
		L4Addr:      loadbalancer.L4Addr{},
		Scope:       0,
	}
	zeroAddr = loadbalancer.L3n4Addr{
		AddrCluster: types.MustParseAddrCluster("0.0.0.3"),
		L4Addr:      loadbalancer.L4Addr{},
		Scope:       0,
	}

	extraFrontend = loadbalancer.L3n4Addr{
		AddrCluster: types.MustParseAddrCluster("10.0.0.2"),
		L4Addr: loadbalancer.L4Addr{
			Protocol: loadbalancer.TCP,
			Port:     80,
		},
		Scope: 0,
	}

	// backend addresses
	backend1 = loadbalancer.L3n4Addr{
		AddrCluster: types.MustParseAddrCluster("10.1.0.1"),
		L4Addr: loadbalancer.L4Addr{
			Protocol: loadbalancer.TCP,
			Port:     80,
		},
		Scope: 0,
	}
	backend2 = loadbalancer.L3n4Addr{
		AddrCluster: types.MustParseAddrCluster("10.1.0.2"),
		L4Addr: loadbalancer.L4Addr{
			Protocol: loadbalancer.TCP,
			Port:     80,
		},
		Scope: 0,
	}

	// frontendAddrs are assigned to the <auto>/autoAddr. Each test set is run with
	// each of these.
	frontendAddrs = []loadbalancer.L3n4Addr{
		parseAddrPort("10.0.0.1:80"),
		parseAddrPort("[2001::1]:80"),
	}

	nodePortAddrs = []netip.Addr{
		netip.MustParseAddr("10.0.0.3"),
		netip.MustParseAddr("2002::1"),
	}
)

type numeric interface {
	~int | ~uint32 | ~uint16
}

// TODO: Figure out what to do about the IDs. If we want to do fault inject the
// operations will be retried and the ID allocations are non-deterministic.
func sanitizeID[Num numeric](n Num, sanitize bool) string {
	if !sanitize {
		return strconv.FormatInt(int64(n), 10)
	}
	if n == 0 {
		return "<zero>"
	}
	return "<non-zero>"
}

func parseAddrPort(s string) loadbalancer.L3n4Addr {
	addrS, portS, found := strings.Cut(s, "]:")
	if found {
		// IPv6
		addrS = addrS[1:] // drop [
	} else {
		// IPv4
		addrS, portS, found = strings.Cut(s, ":")
		if !found {
			panic("bad <ip:port>")
		}
	}
	addr := types.MustParseAddrCluster(addrS)
	port, _ := strconv.ParseInt(portS, 10, 16)
	return *loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		addr, uint16(port), loadbalancer.ScopeExternal,
	)

}

// MapDump is a dump of a BPF map. These are generated by the dump() method, which
// solely defines the format.
type MapDump = string

func dumpLBMapsWithReplace(lbmaps LBMaps, feAddr loadbalancer.L3n4Addr, sanitizeIDs bool) (out []MapDump) {
	replaceAddr := func(addr net.IP, port uint16) (s string) {
		s = addr.String()
		if addr.To4() == nil {
			s = "[" + s + "]"
		}
		s = fmt.Sprintf("%s:%d", s, port)
		if addr.IsUnspecified() {
			s = "<zero>"
			return
		}
		switch addr.String() {
		case feAddr.AddrCluster.String():
			s = "<auto>"
		case nodePortAddrs[0].String():
			s = "<nodePort>"
		case nodePortAddrs[1].String():
			s = "<nodePort>"
		}
		return
	}
	return DumpLBMaps(lbmaps, sanitizeIDs, replaceAddr)
}

// DumpLBMaps the load-balancing maps into a concise format for assertions in tests.
func DumpLBMaps(lbmaps LBMaps, sanitizeIDs bool, customizeAddr func(net.IP, uint16) string) (out []MapDump) {
	out = []string{}

	if customizeAddr == nil {
		customizeAddr = func(addr net.IP, port uint16) (s string) {
			s = addr.String()
			if addr.To4() == nil {
				s = "[" + s + "]"
			}
			return fmt.Sprintf("%s:%d", s, port)
		}
	}

	// BackendID corresponds to a union type in bpf/lib/common.h, and we stringify it differently depending on the case of the union.
	stringFromBackendID := func(svcValue lbmap.ServiceValue, slot int) string {
		if slot != 0 {
			return fmt.Sprintf("BEID=%s", sanitizeID(svcValue.GetBackendID(), sanitizeIDs))
		}
		if loadbalancer.ServiceFlags(svcValue.GetFlags()).IsL7LB() {
			return fmt.Sprintf("L7Proxy=%d", svcValue.GetL7LBProxyPort())
		}
		return fmt.Sprintf("LBALG=%s AFFTimeout=%d",
			loadbalancer.SVCLoadBalancingAlgorithm(svcValue.GetLbAlg()).String(),
			svcValue.GetSessionAffinityTimeoutSec(),
		)
	}

	svcCB := func(svcKey lbmap.ServiceKey, svcValue lbmap.ServiceValue) {
		svcKey = svcKey.ToHost()
		svcValue = svcValue.ToHost()
		addr := svcKey.GetAddress()
		addrS := customizeAddr(addr, svcKey.GetPort())
		addrS += "/" + loadbalancer.NewL4TypeFromNumber(svcKey.GetProtocol())
		if svcKey.GetScope() == loadbalancer.ScopeInternal {
			addrS += "/i"
		}
		out = append(out, fmt.Sprintf("SVC: ID=%s ADDR=%s SLOT=%d %s COUNT=%d QCOUNT=%d FLAGS=%s",
			sanitizeID(svcValue.GetRevNat(), sanitizeIDs),
			addrS,
			svcKey.GetBackendSlot(),
			stringFromBackendID(svcValue, svcKey.GetBackendSlot()),
			svcValue.GetCount(),
			svcValue.GetQCount(),
			strings.ReplaceAll(
				loadbalancer.ServiceFlags(svcValue.GetFlags()).String(),
				", ", "+"),
		))
	}
	if err := lbmaps.DumpService(svcCB); err != nil {
		panic(err)
	}

	beCB := func(beKey lbmap.BackendKey, beValue lbmap.BackendValue) {
		beValue = beValue.ToHost()
		addr := beValue.GetAddress()
		addrS := customizeAddr(addr, beValue.GetPort())
		addrS += "/" + loadbalancer.NewL4TypeFromNumber(beValue.GetProtocol())
		stateS, _ := loadbalancer.GetBackendStateFromFlags(beValue.GetFlags()).String()
		out = append(out, fmt.Sprintf("BE: ID=%s ADDR=%s STATE=%s",
			sanitizeID(beKey.GetID(), sanitizeIDs),
			addrS,
			stateS,
		))
	}
	if err := lbmaps.DumpBackend(beCB); err != nil {
		panic(err)
	}

	revCB := func(revKey lbmap.RevNatKey, revValue lbmap.RevNatValue) {
		revKey = revKey.ToHost()
		revValue = revValue.ToHost()

		var addr string

		switch v := revValue.(type) {
		case *lbmap.RevNat4Value:
			addr = customizeAddr(v.Address.IP(), v.Port)

		case *lbmap.RevNat6Value:
			addr = customizeAddr(v.Address.IP(), v.Port)
		}

		out = append(out, fmt.Sprintf("REV: ID=%s ADDR=%s",
			sanitizeID(revKey.GetKey(), sanitizeIDs),
			addr,
		))
	}
	if err := lbmaps.DumpRevNat(revCB); err != nil {
		panic(err)
	}

	affCB := func(affKey *lbmap.AffinityMatchKey, _ *lbmap.AffinityMatchValue) {
		affKey = affKey.ToHost()
		out = append(out, fmt.Sprintf("AFF: ID=%s BEID=%d",
			sanitizeID(affKey.RevNATID, sanitizeIDs),
			affKey.BackendID,
		))
	}

	if err := lbmaps.DumpAffinityMatch(affCB); err != nil {
		panic(err)
	}

	srcRangeCB := func(key lbmap.SourceRangeKey, _ *lbmap.SourceRangeValue) {
		key = key.ToHost()
		out = append(out, fmt.Sprintf("SRCRANGE: ID=%s CIDR=%s",
			sanitizeID(key.GetRevNATID(), sanitizeIDs),
			key.GetCIDR(),
		))
	}
	if err := lbmaps.DumpSourceRange(srcRangeCB); err != nil {
		panic(err)
	}

	maglevCB := func(key lbmap.MaglevOuterKey, _ lbmap.MaglevOuterVal, _ lbmap.MaglevInnerKey, innerValue *lbmap.MaglevInnerVal, _ bool) {
		key = lbmap.MaglevOuterKey{
			RevNatID: byteorder.NetworkToHost16(key.RevNatID),
		}
		idCounts := make(map[loadbalancer.BackendID]int)
		for _, backend := range innerValue.BackendIDs {
			idCounts[backend]++
		}
		type idWithCount struct {
			loadbalancer.BackendID
			count int
		}
		var compactIDs []idWithCount
		for id, count := range idCounts {
			compactIDs = append(compactIDs, idWithCount{id, count})
		}
		slices.SortFunc(compactIDs, func(a, b idWithCount) int {
			diff := a.count - b.count
			if diff != 0 {
				return -diff // Descending order by counts
			}
			return int(a.BackendID) - int(b.BackendID)
		})
		var ids []string
		for _, idWithCount := range compactIDs {
			ids = append(ids, fmt.Sprintf("%s(%d)", sanitizeID(idWithCount.BackendID, sanitizeIDs), idWithCount.count))
		}
		out = append(out, fmt.Sprintf("MAGLEV: ID=%s INNER=[%s]",
			sanitizeID(byteorder.HostToNetwork16(key.RevNatID), sanitizeIDs),
			strings.Join(ids, ", "),
		))
	}
	if err := lbmaps.DumpMaglev(maglevCB); err != nil {
		panic(err)
	}

	sort.Strings(out)
	return
}

func FastCheckTables(db *statedb.DB, writer *Writer, expectedFrontends int, lastPendingRevision statedb.Revision) (reconciled bool, nextRevision statedb.Revision) {
	txn := db.ReadTxn()
	if writer.Frontends().NumObjects(txn) < expectedFrontends {
		return false, 0
	}
	var rev uint64
	var fe *Frontend
	for fe, rev = range writer.Frontends().LowerBound(txn, statedb.ByRevision[*Frontend](lastPendingRevision)) {
		if fe.Status.Kind != reconciler.StatusKindDone {
			return false, rev
		}
	}
	return true, rev // Here, it is the last reconciled revision rather than the first non-reconciled revision.
}

func FastCheckEmptyTablesAndState(db *statedb.DB, writer *Writer, bo *BPFOps) bool {
	txn := db.ReadTxn()
	if writer.Frontends().NumObjects(txn) > 0 || writer.Backends().NumObjects(txn) > 0 || writer.Services().NumObjects(txn) > 0 {
		return false
	}
	if len(bo.backendReferences) > 0 || len(bo.backendStates) > 0 || len(bo.nodePortAddrByPort) > 0 || len(bo.serviceIDAlloc.entities) > 0 || len(bo.backendIDAlloc.entities) > 0 {
		return false
	}
	return true
}
