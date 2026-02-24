package netlink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// ConntrackTableType Conntrack table for the netlink operation
type ConntrackTableType uint8

const (
	// ConntrackTable Conntrack table
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink.h -> #define NFNL_SUBSYS_CTNETLINK		 1
	ConntrackTable = 1
	// ConntrackExpectTable Conntrack expect table
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink.h -> #define NFNL_SUBSYS_CTNETLINK_EXP 2
	ConntrackExpectTable = 2
)

const (
	// backward compatibility with golang 1.6 which does not have io.SeekCurrent
	seekCurrent = 1
)

// InetFamily Family type
type InetFamily uint8

//  -L [table] [options]          List conntrack or expectation table
//  -G [table] parameters         Get conntrack or expectation

//  -I [table] parameters         Create a conntrack or expectation
//  -U [table] parameters         Update a conntrack
//  -E [table] [options]          Show events

//  -C [table]                    Show counter
//  -S                            Show statistics

// ConntrackTableList returns the flow list of a table of a specific family.
// It pre-allocates a single []ConntrackFlow slice and reuses it to avoid per-flow allocations.
// conntrack -L [table] [options]          List conntrack or expectation table
//
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func ConntrackTableList(table ConntrackTableType, family InetFamily) ([]*ConntrackFlow, error) {
	return pkgHandle.ConntrackTableList(table, family)
}

// ConntrackTableFlush flushes all the flows of a specified table
// conntrack -F [table]            Flush table
// The flush operation applies to all the family types
func ConntrackTableFlush(table ConntrackTableType) error {
	return pkgHandle.ConntrackTableFlush(table)
}

// ConntrackCreate creates a new conntrack flow in the desired table
// conntrack -I [table]		Create a conntrack or expectation
func ConntrackCreate(table ConntrackTableType, family InetFamily, flow *ConntrackFlow) error {
	return pkgHandle.ConntrackCreate(table, family, flow)
}

// ConntrackUpdate updates an existing conntrack flow in the desired table using the handle
// conntrack -U [table]		Update a conntrack
func ConntrackUpdate(table ConntrackTableType, family InetFamily, flow *ConntrackFlow) error {
	return pkgHandle.ConntrackUpdate(table, family, flow)
}

// ConntrackDeleteFilter deletes entries on the specified table on the base of the filter
// conntrack -D [table] parameters         Delete conntrack or expectation
//
// Deprecated: use [ConntrackDeleteFilters] instead.
func ConntrackDeleteFilter(table ConntrackTableType, family InetFamily, filter CustomConntrackFilter) (uint, error) {
	return pkgHandle.ConntrackDeleteFilters(table, family, filter)
}

// ConntrackDeleteFilters deletes entries on the specified table matching any of the specified filters
// conntrack -D [table] parameters         Delete conntrack or expectation
func ConntrackDeleteFilters(table ConntrackTableType, family InetFamily, filters ...CustomConntrackFilter) (uint, error) {
	return pkgHandle.ConntrackDeleteFilters(table, family, filters...)
}

func ConntrackTableListStream(table ConntrackTableType, family InetFamily, handle chan *ConntrackFlow, allocator func() *ConntrackFlow) error {
	return pkgHandle.ConntrackTableListStream(table, family, handle, allocator)
}

// ConntrackTableList returns the flow list of a table of a specific family using the netlink handle passed.
// It pre-allocates a single []ConntrackFlow slice and reuses elements to avoid per-flow allocations.
// conntrack -L [table] [options]          List conntrack or expectation table
//
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func (h *Handle) ConntrackTableList(table ConntrackTableType, family InetFamily) ([]*ConntrackFlow, error) {
	res, executeErr := h.dumpConntrackTable(table, family)
	if executeErr != nil && !errors.Is(executeErr, ErrDumpInterrupted) {
		return nil, executeErr
	}

	flows := make([]ConntrackFlow, len(res))
	result := make([]*ConntrackFlow, len(res))
	i := 0
	allocator := func() *ConntrackFlow {
		p := &flows[i]
		i++
		return p
	}
	for j := range res {
		result[j] = parseRawData(res[j], allocator)
	}

	return result, executeErr
}

// ConntrackTableFlush flushes all the flows of a specified table using the netlink handle passed
// conntrack -F [table]            Flush table
// The flush operation applies to all the family types
func (h *Handle) ConntrackTableFlush(table ConntrackTableType) error {
	req := h.newConntrackRequest(table, unix.AF_INET, nl.IPCTNL_MSG_CT_DELETE, unix.NLM_F_ACK)
	_, err := req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}

func (h *Handle) NewConntrackCreateRequest(table ConntrackTableType, family InetFamily, ack bool) nl.NetlinkRequest {
	if ack {
		return h.newConntrackRequest(table, family, nl.IPCTNL_MSG_CT_NEW, unix.NLM_F_ACK|unix.NLM_F_CREATE)
	}
	return h.newConntrackRequest(table, family, nl.IPCTNL_MSG_CT_NEW, unix.NLM_F_CREATE)
}

// ConntrackCreate creates a new conntrack flow in the desired table using the handle
// conntrack -I [table]		Create a conntrack or expectation
func (h *Handle) ConntrackCreate(table ConntrackTableType, family InetFamily, flow *ConntrackFlow) error {
	req := h.newConntrackRequest(table, family, nl.IPCTNL_MSG_CT_NEW, unix.NLM_F_ACK|unix.NLM_F_CREATE)
	attr, err := flow.toNlData(nl.NewRtAttr, make([]nl.NetlinkRequestData, 32))
	if err != nil {
		return err
	}
	newData := make([]nl.NetlinkRequestData, 0, len(attr)+len(req.Data))
	newData = append(newData, req.Data...)
	for _, a := range attr {
		newData = append(newData, a)
	}
	req.Data = newData

	_, err = req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}

func (h *Handle) NewConntrackUpdateRequest(table ConntrackTableType, family InetFamily, ack bool) nl.NetlinkRequest {
	if ack {
		return h.newConntrackRequest(table, family, nl.IPCTNL_MSG_CT_NEW, unix.NLM_F_ACK|unix.NLM_F_REPLACE)
	}
	return h.newConntrackRequest(table, family, nl.IPCTNL_MSG_CT_NEW, unix.NLM_F_REPLACE)
}

// ConntrackUpdate updates an existing conntrack flow in the desired table using the handle
// conntrack -U [table]		Update a conntrack
func (h *Handle) ConntrackUpdate(table ConntrackTableType, family InetFamily, flow *ConntrackFlow) error {
	req := h.newConntrackRequest(table, family, nl.IPCTNL_MSG_CT_NEW, unix.NLM_F_ACK|unix.NLM_F_REPLACE)
	attr, err := flow.toNlData(nl.NewRtAttr, make([]nl.NetlinkRequestData, 32))
	if err != nil {
		return err
	}

	newData := make([]nl.NetlinkRequestData, 0, len(attr)+len(req.Data))
	newData = append(newData, req.Data...)
	for _, a := range attr {
		newData = append(newData, a)
	}
	req.Data = newData

	_, err = req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}

func (h *Handle) ExecuteConntrackRequest(req nl.NetlinkRequest, conntrackFlow *ConntrackFlow,
	newRtAttr func(attrType int, data []byte) *nl.RtAttr, buf []nl.NetlinkRequestData,
	checkError bool) error {
	attr, err := conntrackFlow.toNlData(newRtAttr, buf)
	if err != nil {
		return err
	}
	req.Data = append(req.Data, attr...)
	if !checkError {
		return req.ExecuteIter(unix.NETLINK_NETFILTER, 0, nil)
	}
	_, err = req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}

// ConntrackDeleteFilter deletes entries on the specified table on the base of the filter using the netlink handle passed
// conntrack -D [table] parameters         Delete conntrack or expectation
//
// Deprecated: use [Handle.ConntrackDeleteFilters] instead.
func (h *Handle) ConntrackDeleteFilter(table ConntrackTableType, family InetFamily, filter CustomConntrackFilter) (uint, error) {
	return h.ConntrackDeleteFilters(table, family, filter)
}

// ConntrackDeleteFilters deletes entries on the specified table matching any of the specified filters using the netlink handle passed
// conntrack -D [table] parameters         Delete conntrack or expectation
func (h *Handle) ConntrackDeleteFilters(table ConntrackTableType, family InetFamily, filters ...CustomConntrackFilter) (uint, error) {
	var finalErr error
	res, err := h.dumpConntrackTable(table, family)
	if err != nil {
		if !errors.Is(err, ErrDumpInterrupted) {
			return 0, err
		}
		// This allows us to at least do a best effort to try to clean the
		// entries matching the filter.
		finalErr = err
	}

	var totalFilterErrors int
	var matched uint
	var tempConntrackFlow ConntrackFlow
	allocator := func() *ConntrackFlow {
		return &tempConntrackFlow
	}
	for _, dataRaw := range res {
		flow := parseRawData(dataRaw, allocator)
		for _, filter := range filters {
			if match := filter.MatchConntrackFlow(flow); match {
				req2 := h.newConntrackRequest(table, family, nl.IPCTNL_MSG_CT_DELETE, unix.NLM_F_ACK)
				// skip the first 4 byte that are the netfilter header, the newConntrackRequest is adding it already
				req2.AddRawData(dataRaw[4:])
				if _, err = req2.Execute(unix.NETLINK_NETFILTER, 0); err == nil || errors.Is(err, fs.ErrNotExist) {
					matched++
					// flow is already deleted, no need to match on other filters and continue to the next flow.
					break
				} else {
					totalFilterErrors++
				}
			}
		}
	}
	if totalFilterErrors > 0 {
		finalErr = errors.Join(finalErr, fmt.Errorf("failed to delete %d conntrack flows with %d filters", totalFilterErrors, len(filters)))
	}
	return matched, finalErr
}

func (h *Handle) ConntrackTableListStream(table ConntrackTableType, family InetFamily, handle chan *ConntrackFlow, allocator func() *ConntrackFlow) error {
	req := h.newConntrackRequest(table, family, nl.IPCTNL_MSG_CT_GET, unix.NLM_F_DUMP)

	err := req.ExecuteIter(unix.NETLINK_NETFILTER, 0, func(dataRaw []byte) bool {
		handle <- parseRawData(dataRaw, allocator)
		return true
	})

	return err
}

func (h *Handle) newConntrackRequest(table ConntrackTableType, family InetFamily, operation, flags int) nl.NetlinkRequest {
	// Create the Netlink request object
	req := h.newNetlinkRequest((int(table)<<8)|operation, flags)
	// Add the netfilter header
	msg := &nl.Nfgenmsg{
		NfgenFamily: uint8(family),
		Version:     nl.NFNETLINK_V0,
		ResId:       0,
	}
	req.AddData(msg)
	return req
}

func (h *Handle) dumpConntrackTable(table ConntrackTableType, family InetFamily) ([][]byte, error) {
	req := h.newConntrackRequest(table, family, nl.IPCTNL_MSG_CT_GET, unix.NLM_F_DUMP)
	return req.Execute(unix.NETLINK_NETFILTER, 0)
}

// ProtoInfo wraps an L4-protocol structure - roughly corresponds to the
// __nfct_protoinfo union found in libnetfilter_conntrack/include/internal/object.h.
// Currently, only protocol names, and TCP state is supported.
type ProtoInfo interface {
	Protocol() string
}

// ProtoInfoTCP corresponds to the `tcp` struct of the __nfct_protoinfo union.
type ProtoInfoTCP struct {
	State          uint8
	WsacleOriginal uint8
	WsacleReply    uint8
	FlagsOriginal  uint16
	FlagsReply     uint16
}

// Protocol returns "tcp".
func (*ProtoInfoTCP) Protocol() string { return "tcp" }
func (p *ProtoInfoTCP) toNlData(newRtAttr func(attrType int, data []byte) *nl.RtAttr, buf []nl.NetlinkRequestData) ([]nl.NetlinkRequestData, error) {
	ctProtoInfo := newRtAttr(unix.NLA_F_NESTED|nl.CTA_PROTOINFO, []byte{})
	ctProtoInfoTCP := newRtAttr(unix.NLA_F_NESTED|nl.CTA_PROTOINFO_TCP, []byte{})
	ctProtoInfoTCPState := newRtAttr(nl.CTA_PROTOINFO_TCP_STATE, nl.Uint8Attr(p.State))
	ctProtoInfoTCPWscaleOriginal := newRtAttr(nl.CTA_PROTOINFO_TCP_WSCALE_ORIGINAL, nl.Uint8Attr(p.WsacleOriginal))
	ctProtoInfoTCPWscaleReply := newRtAttr(nl.CTA_PROTOINFO_TCP_WSCALE_REPLY, nl.Uint8Attr(p.WsacleReply))
	ctProtoInfoTCPFlagsOriginal := newRtAttr(nl.CTA_PROTOINFO_TCP_FLAGS_ORIGINAL, nl.BEUint16Attr(p.FlagsOriginal))
	ctProtoInfoTCPFlagsReply := newRtAttr(nl.CTA_PROTOINFO_TCP_FLAGS_REPLY, nl.BEUint16Attr(p.FlagsReply))

	ctProtoInfoTCP.AddChilds(ctProtoInfoTCPState, ctProtoInfoTCPWscaleOriginal, ctProtoInfoTCPWscaleReply, ctProtoInfoTCPFlagsOriginal, ctProtoInfoTCPFlagsReply)
	ctProtoInfo.AddChild(ctProtoInfoTCP)

	buf[0] = ctProtoInfo
	return buf[0:1], nil
}

// ProtoInfoSCTP only supports the protocol name.
type ProtoInfoSCTP struct{}

// Protocol returns "sctp".
func (*ProtoInfoSCTP) Protocol() string { return "sctp" }

// ProtoInfoDCCP only supports the protocol name.
type ProtoInfoDCCP struct{}

// Protocol returns "dccp".
func (*ProtoInfoDCCP) Protocol() string { return "dccp" }

// The full conntrack flow structure is very complicated and can be found in the file:
// http://git.netfilter.org/libnetfilter_conntrack/tree/include/internal/object.h
// For the time being, the structure below allows to parse and extract the base information of a flow
type IPTuple struct {
	Bytes    uint64
	DstIP    net.IP
	DstPort  uint16
	Packets  uint64
	Protocol uint8
	SrcIP    net.IP
	SrcPort  uint16

	// ICMP only
	ICMPID   uint16
	ICMPType uint8
	ICMPCode uint8
}

// toNlData generates the inner fields of a nested tuple netlink datastructure
// does not generate the "nested"-flagged outer message.
func (t *IPTuple) toNlData(family uint8, newRtAttr func(attrType int, data []byte) *nl.RtAttr, buf []nl.NetlinkRequestData) ([]nl.NetlinkRequestData, error) {
	var srcIPsFlag, dstIPsFlag int
	switch family {
	case nl.FAMILY_V4:
		srcIPsFlag = nl.CTA_IP_V4_SRC
		dstIPsFlag = nl.CTA_IP_V4_DST
	case nl.FAMILY_V6:
		srcIPsFlag = nl.CTA_IP_V6_SRC
		dstIPsFlag = nl.CTA_IP_V6_DST
	default:
		return []nl.NetlinkRequestData{}, fmt.Errorf("couldn't generate netlink message for tuple due to unrecognized FamilyType '%d'", family)
	}

	// For IPv4 the kernel expects exactly 4 bytes; use To4() so we never send nil or 16-byte form.
	var srcData, dstData []byte
	switch family {
	case nl.FAMILY_V4:
		if t.SrcIP != nil {
			srcData = t.SrcIP.To4()
		}
		if t.DstIP != nil {
			dstData = t.DstIP.To4()
		}
		if len(srcData) != 4 || len(dstData) != 4 {
			return []nl.NetlinkRequestData{}, fmt.Errorf("conntrack IPv4 tuple requires 4-byte SrcIP and DstIP, got len %d and %d", len(srcData), len(dstData))
		}
	case nl.FAMILY_V6:
		srcData = t.SrcIP
		dstData = t.DstIP
		if len(srcData) != 16 || len(dstData) != 16 {
			return []nl.NetlinkRequestData{}, fmt.Errorf("conntrack IPv6 tuple requires 16-byte SrcIP and DstIP, got len %d and %d", len(srcData), len(dstData))
		}
	}
	ctTupleIP := newRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_IP, nil)
	ctTupleIP.ReserveMoreChildren(6)
	srcIPsFlagAttr := newRtAttr(srcIPsFlag, srcData)
	dstIPsFlagAttr := newRtAttr(dstIPsFlag, dstData)

	ctTupleIP.AddChilds(srcIPsFlagAttr, dstIPsFlagAttr)

	ctTupleProto := newRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
	ctTupleProtoNum := newRtAttr(nl.CTA_PROTO_NUM, []byte{t.Protocol})
	ctTupleProto.AddChild(ctTupleProtoNum)

	// Protocol-specific attribute handling:
	// The kernel's ctnetlink_parse_tuple_proto() calls l4proto->nlattr_to_tuple() for each protocol.
	// Different protocols use different netlink attribute parsers:
	//
	// 1. ICMP/ICMPv6: Use custom nlattr_to_tuple (icmp_nlattr_to_tuple/icmpv6_nlattr_to_tuple)
	//    - Require: CTA_PROTO_ICMP_ID/TYPE/CODE (or ICMPV6 variants)
	//    - Files: nf_conntrack_proto_icmp.c, nf_conntrack_proto_icmpv6.c
	//
	// 2. Port-based protocols: Use nf_ct_port_nlattr_to_tuple()
	//    - Require: CTA_PROTO_SRC_PORT and CTA_PROTO_DST_PORT (even if 0 for protocols like GRE)
	//    - Protocols: TCP(6), UDP(17), DCCP(33), SCTP(132), UDPLite(136), GRE(47)
	//    - Files: nf_conntrack_proto_tcp.c, nf_conntrack_proto_udp.c, etc.
	//    - Note: GRE doesn't have ports, but still uses port_nlattr_to_tuple, so ports must be 0
	//
	// 3. Generic protocols: Use nf_conntrack_l4proto_generic (no nlattr_to_tuple)
	//    - Require: Only CTA_PROTO_NUM (no additional attributes)
	//    - Protocols: IPIP(4) and all other unregistered protocols
	//    - File: nf_conntrack_proto_generic.c
	switch t.Protocol {
	case unix.IPPROTO_ICMP:
		// ICMP uses icmp_nlattr_to_tuple, requires ID/Type/Code
		ctTupleProtoICMPID := newRtAttr(nl.CTA_PROTO_ICMP_ID, nl.BEUint16Attr(t.ICMPID))
		ctTupleProtoICMPType := newRtAttr(nl.CTA_PROTO_ICMP_TYPE, []byte{t.ICMPType})
		ctTupleProtoICMPCode := newRtAttr(nl.CTA_PROTO_ICMP_CODE, []byte{t.ICMPCode})
		ctTupleProto.AddChilds(ctTupleProtoICMPID, ctTupleProtoICMPType, ctTupleProtoICMPCode)
	case unix.IPPROTO_ICMPV6:
		// ICMPv6 uses icmpv6_nlattr_to_tuple, requires ID/Type/Code
		ctTupleProtoICMPV6ID := newRtAttr(nl.CTA_PROTO_ICMPV6_ID, nl.BEUint16Attr(t.ICMPID))
		ctTupleProtoICMPV6Type := newRtAttr(nl.CTA_PROTO_ICMPV6_TYPE, []byte{t.ICMPType})
		ctTupleProtoICMPV6Code := newRtAttr(nl.CTA_PROTO_ICMPV6_CODE, []byte{t.ICMPCode})
		ctTupleProto.AddChilds(ctTupleProtoICMPV6ID, ctTupleProtoICMPV6Type, ctTupleProtoICMPV6Code)
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_DCCP, unix.IPPROTO_SCTP, unix.IPPROTO_UDPLITE, unix.IPPROTO_GRE:
		// All these protocols use nf_ct_port_nlattr_to_tuple() which requires both port attributes.
		// For protocols without ports (like GRE), ports must be set to 0, but the attributes must still be present.
		// Without these attributes, ctnetlink_parse_tuple_proto() will return -EINVAL.
		ctTupleProtoSrcPort := newRtAttr(nl.CTA_PROTO_SRC_PORT, nl.BEUint16Attr(t.SrcPort))
		ctTupleProtoDstPort := newRtAttr(nl.CTA_PROTO_DST_PORT, nl.BEUint16Attr(t.DstPort))
		ctTupleProto.AddChilds(ctTupleProtoSrcPort, ctTupleProtoDstPort)
	case unix.IPPROTO_IPIP:
		fallthrough
	default:
		// Generic protocols (IPIP and all others) use nf_conntrack_l4proto_generic
		// which has no nlattr_to_tuple function, so only CTA_PROTO_NUM is required.
		// No additional attributes needed.
	}
	buf[0] = ctTupleIP
	buf[1] = ctTupleProto

	return buf[0:2], nil
}

type ConntrackFlow struct {
	FamilyType    uint8
	Forward       IPTuple
	Reverse       IPTuple
	Mark          uint32
	Zone          uint16
	TimeStart     uint64
	TimeStop      uint64
	TimeOut       uint32
	Status        uint32
	Use           uint32
	ID            uint32
	Labels        [16]byte
	HasLabels     bool
	LabelsMask    [16]byte
	HasLabelsMask bool
	ProtoInfo     ProtoInfo
}

func (s *ConntrackFlow) String() string {
	// conntrack cmd output:
	// udp      17 src=127.0.0.1 dst=127.0.0.1 sport=4001 dport=1234 packets=5 bytes=532 [UNREPLIED] src=127.0.0.1 dst=127.0.0.1 sport=1234 dport=4001 packets=10 bytes=1078 mark=0 labels=0x00000000050012ac4202010000000000 zone=100
	//             start=2019-07-26 01:26:21.557800506 +0000 UTC stop=1970-01-01 00:00:00 +0000 UTC timeout=30(sec)
	start := time.Unix(0, int64(s.TimeStart))
	stop := time.Unix(0, int64(s.TimeStop))
	timeout := int32(s.TimeOut)

	var out string
	if s.Forward.Protocol == unix.IPPROTO_ICMP || s.Forward.Protocol == unix.IPPROTO_ICMPV6 {
		out = fmt.Sprintf("%s\t%d src=%s dst=%s id=%d type=%d code=%d packets=%d bytes=%d\tsrc=%s dst=%s id=%d type=%d code=%d packets=%d bytes=%d",
			nl.L4ProtoMap[s.Forward.Protocol], s.Forward.Protocol,
			s.Forward.SrcIP.String(), s.Forward.DstIP.String(), s.Forward.ICMPID, s.Forward.ICMPType, s.Forward.ICMPCode, s.Forward.Packets, s.Forward.Bytes,
			s.Reverse.SrcIP.String(), s.Reverse.DstIP.String(), s.Reverse.ICMPID, s.Reverse.ICMPType, s.Reverse.ICMPCode, s.Reverse.Packets, s.Reverse.Bytes)
	} else {
		out = fmt.Sprintf("%s\t%d src=%s dst=%s sport=%d dport=%d packets=%d bytes=%d\tsrc=%s dst=%s sport=%d dport=%d packets=%d bytes=%d",
			nl.L4ProtoMap[s.Forward.Protocol], s.Forward.Protocol,
			s.Forward.SrcIP.String(), s.Forward.DstIP.String(), s.Forward.SrcPort, s.Forward.DstPort, s.Forward.Packets, s.Forward.Bytes,
			s.Reverse.SrcIP.String(), s.Reverse.DstIP.String(), s.Reverse.SrcPort, s.Reverse.DstPort, s.Reverse.Packets, s.Reverse.Bytes)
	}
	out += fmt.Sprintf(" mark=0x%x", s.Mark)
	if s.HasLabels {
		out += fmt.Sprintf(" labels=0x%x", s.Labels)
	}
	if s.HasLabelsMask {
		out += fmt.Sprintf("/0x%x", s.LabelsMask)
	}
	if s.Status != 0 {
		out += fmt.Sprintf(" status=0x%x", s.Status)
	}
	out += fmt.Sprintf(" zone=%d", s.Zone)
	if s.Use != 0 {
		out += fmt.Sprintf(" use=0x%x", s.Use)
	}
	out += fmt.Sprintf(" start=%v stop=%v timeout=%d(sec)", start, stop, timeout)
	return out
}

// toNlData generates netlink messages representing the flow.
func (s *ConntrackFlow) toNlData(newRtAttr func(attrType int, data []byte) *nl.RtAttr, buf []nl.NetlinkRequestData) ([]nl.NetlinkRequestData, error) {
	var err error
	// The message structure is built as follows:
	//	<len, NLA_F_NESTED|CTA_TUPLE_ORIG>
	//		<len, NLA_F_NESTED|CTA_TUPLE_IP>
	//			<len, [CTA_IP_V4_SRC|CTA_IP_V6_SRC]>
	//			<IP>
	//			<len, [CTA_IP_V4_DST|CTA_IP_V6_DST]>
	//			<IP>
	//		<len, NLA_F_NESTED|nl.CTA_TUPLE_PROTO>
	//			<len, CTA_PROTO_NUM>
	//			<uint8>
	//			<len, CTA_PROTO_SRC_PORT>
	//			<BEuint16>
	//			<len, CTA_PROTO_DST_PORT>
	//			<BEuint16>
	// 	<len, NLA_F_NESTED|CTA_TUPLE_REPLY>
	//		<len, NLA_F_NESTED|CTA_TUPLE_IP>
	//			<len, [CTA_IP_V4_SRC|CTA_IP_V6_SRC]>
	//			<IP>
	//			<len, [CTA_IP_V4_DST|CTA_IP_V6_DST]>
	//			<IP>
	//		<len, NLA_F_NESTED|nl.CTA_TUPLE_PROTO>
	//			<len, CTA_PROTO_NUM>
	//			<uint8>
	//			<len, CTA_PROTO_SRC_PORT>
	//			<BEuint16>
	//			<len, CTA_PROTO_DST_PORT>
	//			<BEuint16>
	//  <len, CTA_ZONE>
	//	<BEuint16>
	//	<len, CTA_STATUS>
	//	<uint64>
	//	<len, CTA_MARK>
	//	<BEuint64>
	//	<len, CTA_TIMEOUT>
	//	<BEuint64>
	//	<len, CTA_LABELS>
	//	<binary data>
	//  <len, CTA_LABELS_MASK>
	//	<binary data>
	//	<len, NLA_F_NESTED|CTA_PROTOINFO>

	// CTA_TUPLE_ORIG
	ctTupleOrig := newRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_ORIG, nil)
	var forwardFlowAttrs []nl.NetlinkRequestData
	forwardFlowAttrs, err = s.Forward.toNlData(s.FamilyType, newRtAttr, buf)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate netlink data for conntrack forward flow: %w", err)
	}
	buf = buf[len(forwardFlowAttrs):]
	ctTupleOrig.AddChilds(forwardFlowAttrs...)
	// CTA_TUPLE_REPLY
	ctTupleReply := newRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_REPLY, nil)
	var reverseFlowAttrs []nl.NetlinkRequestData
	reverseFlowAttrs, err = s.Reverse.toNlData(s.FamilyType, newRtAttr, buf[2:4])
	if err != nil {
		return nil, fmt.Errorf("couldn't generate netlink data for conntrack reverse flow: %w", err)
	}
	buf = buf[len(reverseFlowAttrs):]
	ctTupleReply.AddChilds(reverseFlowAttrs...)

	ctMark := newRtAttr(nl.CTA_MARK, nl.BEUint32Attr(s.Mark))
	ctTimeout := newRtAttr(nl.CTA_TIMEOUT, nl.BEUint32Attr(s.TimeOut))

	// Zone is required for matching conntrack entries in the kernel
	// The kernel uses zone when looking up conntrack entries: nf_conntrack_find_get(net, &zone, &otuple)
	ctZone := newRtAttr(nl.CTA_ZONE, nl.BEUint16Attr(s.Zone))
	ctStatus := newRtAttr(nl.CTA_STATUS, nl.BEUint32Attr(s.Status))

	var payload []nl.NetlinkRequestData
	if buf == nil {
		payload = make([]nl.NetlinkRequestData, 0, 9)
	} else {
		payload = buf[0:0]
	}

	payload = append(payload,
		ctTupleOrig, ctTupleReply,
		ctMark, ctTimeout, ctZone, ctStatus,
	)

	// Labels: HasLabels => update conntrack labels; else => do not send.
	if s.HasLabels {
		ctLabels := newRtAttr(nl.CTA_LABELS, s.Labels[:])
		payload = append(payload, ctLabels)
		// Labels Mask: HasLabelsMask => update conntrack labels with mask; else => do not send.
		if s.HasLabelsMask {
			ctLabelsMask := newRtAttr(nl.CTA_LABELS_MASK, s.LabelsMask[:])
			payload = append(payload, ctLabelsMask)
		}
	}

	if s.ProtoInfo != nil {
		switch p := s.ProtoInfo.(type) {
		case *ProtoInfoTCP:
			var attrs []nl.NetlinkRequestData
			attrs, err = p.toNlData(newRtAttr, buf[len(payload):])
			if err != nil {
				return nil, fmt.Errorf("couldn't generate netlink data for conntrack flow's TCP protoinfo: %w", err)
			}
			payload = append(payload, attrs...)
		default:
			return nil, errors.New("couldn't generate netlink data for conntrack: field 'ProtoInfo' only supports TCP or nil")
		}
	}

	return payload, nil
}

// This method parse the ip tuple structure
// The message structure is the following:
// <len, [CTA_IP_V4_SRC|CTA_IP_V6_SRC], 16 bytes for the IP>
// <len, [CTA_IP_V4_DST|CTA_IP_V6_DST], 16 bytes for the IP>
// <len, NLA_F_NESTED|nl.CTA_TUPLE_PROTO, 1 byte for the protocol, 3 bytes of padding>
// <len, CTA_PROTO_SRC_PORT, 2 bytes for the source port, 2 bytes of padding>
// <len, CTA_PROTO_DST_PORT, 2 bytes for the source port, 2 bytes of padding>
func parseIpTuple(data []byte, offset *int, tpl *IPTuple) uint8 {
	for i := 0; i < 2; i++ {
		_, t, _, v := parseNfAttrTLV(data, offset)
		switch t {
		case nl.CTA_IP_V4_SRC, nl.CTA_IP_V6_SRC:
			tpl.SrcIP = v
		case nl.CTA_IP_V4_DST, nl.CTA_IP_V6_DST:
			tpl.DstIP = v
		}
	}
	// Get total length of nested protocol-specific info.
	_, _, protoInfoTotalLen := parseNfAttrTL(data, offset)
	_, t, l, v := parseNfAttrTLV(data, offset)
	// Track the number of bytes read.
	protoInfoBytesRead := uint16(nl.SizeofNfattr) + l
	if t == nl.CTA_PROTO_NUM {
		tpl.Protocol = uint8(v[0])
	}
	// We only parse TCP, UDP, ICMP, ICMPv6 headers. Skip the others.
	if tpl.Protocol != unix.IPPROTO_TCP && tpl.Protocol != unix.IPPROTO_UDP && tpl.Protocol != unix.IPPROTO_ICMP && tpl.Protocol != unix.IPPROTO_ICMPV6 {
		// skip the rest
		bytesRemaining := protoInfoTotalLen - protoInfoBytesRead
		*offset += int(bytesRemaining)
		return tpl.Protocol
	}
	// Skip 3 bytes of padding
	*offset += 3
	protoInfoBytesRead += 3
	loopCount := 2
	if tpl.Protocol == unix.IPPROTO_ICMP || tpl.Protocol == unix.IPPROTO_ICMPV6 {
		loopCount = 3 // ID, Type, Code
	}
	var ICMPCodeDone, ICMPTypeDone bool
	for i := 0; i < loopCount; i++ {
		_, t, _ := parseNfAttrTL(data, offset)
		protoInfoBytesRead += uint16(nl.SizeofNfattr)
		switch t {
		case nl.CTA_PROTO_SRC_PORT:
			tpl.SrcPort = parseBERaw16(data, offset)
			protoInfoBytesRead += 2
		case nl.CTA_PROTO_DST_PORT:
			tpl.DstPort = parseBERaw16(data, offset)
			protoInfoBytesRead += 2
		case nl.CTA_PROTO_ICMP_ID:
			fallthrough
		case nl.CTA_PROTO_ICMPV6_ID:
			tpl.ICMPID = parseBERaw16(data, offset)
			protoInfoBytesRead += 2
		case nl.CTA_PROTO_ICMP_CODE:
			fallthrough
		case nl.CTA_PROTO_ICMPV6_CODE:
			tpl.ICMPCode = parseU8(data, offset)
			protoInfoBytesRead += 1
			ICMPCodeDone = true
		case nl.CTA_PROTO_ICMP_TYPE:
			fallthrough
		case nl.CTA_PROTO_ICMPV6_TYPE:
			tpl.ICMPType = parseU8(data, offset)
			protoInfoBytesRead += 1
			ICMPTypeDone = true
		}
		if (t == nl.CTA_PROTO_ICMP_CODE || t == nl.CTA_PROTO_ICMP_TYPE) && (!ICMPCodeDone || !ICMPTypeDone) {
			continue
		}
		// Skip 2 bytes of padding
		*offset += 2
		protoInfoBytesRead += 2
	}
	// Skip any remaining/unknown parts of the message
	bytesRemaining := protoInfoTotalLen - protoInfoBytesRead
	*offset += int(bytesRemaining)

	return tpl.Protocol
}

func parseNfAttrTLV(data []byte, offset *int) (isNested bool, attrType, len uint16, value []byte) {
	isNested, attrType, len = parseNfAttrTL(data, offset)

	value = data[*offset : *offset+int(len)]
	*offset += int(len)
	return isNested, attrType, len, value
}

func parseNfAttrTL(data []byte, offset *int) (isNested bool, attrType, len uint16) {
	len = parseRaw16(data, offset)
	len -= nl.SizeofNfattr

	attrType = parseRaw16(data, offset)
	isNested = (attrType & nl.NLA_F_NESTED) == nl.NLA_F_NESTED
	attrType = attrType & (nl.NLA_F_NESTED - 1)
	return isNested, attrType, len
}

// skipNfAttrValue seeks `r` past attr of length `len`.
// Maintains buffer alignment.
// Returns length of the seek performed.
func skipNfAttrValue(data []byte, offset *int, len uint16) uint16 {
	_ = data
	len = (len + nl.NLA_ALIGNTO - 1) & ^(nl.NLA_ALIGNTO - 1)
	*offset += int(len)
	return len
}

func parseU8(data []byte, offset *int) uint8 {
	value := data[*offset]
	*offset += 1
	return value
}

func parseBERaw16(data []byte, offset *int) uint16 {
	value := binary.BigEndian.Uint16(data[*offset : *offset+2])
	*offset += 2
	return value
}

func parseBERaw32(data []byte, offset *int) uint32 {
	value := binary.BigEndian.Uint32(data[*offset : *offset+4])
	*offset += 4
	return value
}

func parseBERaw64(data []byte, offset *int) uint64 {
	value := binary.BigEndian.Uint64(data[*offset : *offset+8])
	*offset += 8
	return value
}

// parseRaw16 reads 2 bytes in native (host) byte order. Used for netlink attribute
// header (len, type) which is always native per kernel ABI.
func parseRaw16(data []byte, offset *int) uint16 {
	buf := data[*offset : *offset+2]
	*offset += 2
	return nl.NativeEndian().Uint16(buf)
}

func parseByteAndPacketCounters(data []byte, offset *int) (bytes, packets uint64) {
	for i := 0; i < 2; i++ {
		switch _, t, _ := parseNfAttrTL(data, offset); t {
		case nl.CTA_COUNTERS_BYTES:
			bytes = parseBERaw64(data, offset)
		case nl.CTA_COUNTERS_PACKETS:
			packets = parseBERaw64(data, offset)
		default:
			return
		}
	}
	return
}

// when the flow is alive, only the timestamp_start is returned in structure
func parseTimeStamp(data []byte, offset *int, readSize uint16) (tstart, tstop uint64) {
	var numTimeStamps int
	oneItem := nl.SizeofNfattr + 8 // 4 bytes attr header + 8 bytes timestamp
	if readSize == uint16(oneItem) {
		numTimeStamps = 1
	} else if readSize == 2*uint16(oneItem) {
		numTimeStamps = 2
	} else {
		return
	}
	for i := 0; i < numTimeStamps; i++ {
		switch _, t, _ := parseNfAttrTL(data, offset); t {
		case nl.CTA_TIMESTAMP_START:
			tstart = parseBERaw64(data, offset)
		case nl.CTA_TIMESTAMP_STOP:
			tstop = parseBERaw64(data, offset)
		default:
			return
		}
	}
	return

}

func parseProtoInfoTCPState(data []byte, offset *int) (s uint8) {
	s = data[*offset]
	*offset += nl.SizeofNfattr // 1 + (nl.SizeofNfattr - 1)
	return s
}

// parseProtoInfoTCP reads the entire nested protoinfo structure, but only parses the state attr.
func parseProtoInfoTCP(data []byte, offset *int, attrLen uint16) *ProtoInfoTCP {
	p := new(ProtoInfoTCP)
	bytesRead := 0
	for bytesRead < int(attrLen) {
		_, t, l := parseNfAttrTL(data, offset)
		bytesRead += nl.SizeofNfattr

		switch t {
		case nl.CTA_PROTOINFO_TCP_STATE:
			p.State = parseProtoInfoTCPState(data, offset)
			bytesRead += nl.SizeofNfattr
		case nl.CTA_PROTOINFO_TCP_WSCALE_ORIGINAL:
			p.WsacleOriginal = parseU8(data, offset)
			*offset += int(nl.SizeofNfattr - 1)
			bytesRead += nl.SizeofNfattr
		case nl.CTA_PROTOINFO_TCP_WSCALE_REPLY:
			p.WsacleReply = parseU8(data, offset)
			*offset += int(nl.SizeofNfattr - 1)
			bytesRead += nl.SizeofNfattr
		case nl.CTA_PROTOINFO_TCP_FLAGS_ORIGINAL:
			p.FlagsOriginal = parseBERaw16(data, offset)
			*offset += int(nl.SizeofNfattr - 2)
			bytesRead += nl.SizeofNfattr
		case nl.CTA_PROTOINFO_TCP_FLAGS_REPLY:
			p.FlagsReply = parseBERaw16(data, offset)
			*offset += int(nl.SizeofNfattr - 2)
			bytesRead += nl.SizeofNfattr
		default:
			bytesRead += int(skipNfAttrValue(data, offset, l))
		}
	}

	return p
}

func parseProtoInfo(data []byte, offset *int, attrLen uint16) (p ProtoInfo) {
	bytesRead := 0
	for bytesRead < int(attrLen) {
		_, t, l := parseNfAttrTL(data, offset)
		bytesRead += nl.SizeofNfattr

		switch t {
		case nl.CTA_PROTOINFO_TCP:
			p = parseProtoInfoTCP(data, offset, l)
			bytesRead += int(l)
		// No inner fields of DCCP / SCTP currently supported.
		case nl.CTA_PROTOINFO_DCCP:
			p = new(ProtoInfoDCCP)
			skipped := skipNfAttrValue(data, offset, l)
			bytesRead += int(skipped)
		case nl.CTA_PROTOINFO_SCTP:
			p = new(ProtoInfoSCTP)
			skipped := skipNfAttrValue(data, offset, l)
			bytesRead += int(skipped)
		default:
			skipped := skipNfAttrValue(data, offset, l)
			bytesRead += int(skipped)
		}
	}

	return p
}

func parseTimeOut(data []byte, offset *int) (ttimeout uint32) {
	ttimeout = parseBERaw32(data, offset)
	return
}

func parseConnectionMark(data []byte, offset *int) (mark uint32) {
	mark = parseBERaw32(data, offset)
	return
}

func parseConnectionLabels(data []byte, offset *int) (label [16]byte) {
	copy(label[:], data[*offset:*offset+16])
	*offset += 16
	return
}

func parseConnectionZone(data []byte, offset *int) (zone uint16) {
	zone = parseBERaw16(data, offset)
	*offset += 2
	return
}

func parseRawData(data []byte, allocator func() *ConntrackFlow) *ConntrackFlow {
	var s *ConntrackFlow
	if allocator != nil {
		s = allocator()
	} else {
		s = &ConntrackFlow{}
	}

	tmp := 0
	offset := &tmp

	// First there is the Nfgenmsg header
	// consume only the family field

	s.FamilyType = data[*offset]
	*offset += 1

	// skip rest of the Netfilter header
	*offset += 3
	// The message structure is the following:
	// <len, NLA_F_NESTED|CTA_TUPLE_ORIG> 4 bytes
	// <len, NLA_F_NESTED|CTA_TUPLE_IP> 4 bytes
	// flow information of the forward flow
	// <len, NLA_F_NESTED|CTA_TUPLE_REPLY> 4 bytes
	// <len, NLA_F_NESTED|CTA_TUPLE_IP> 4 bytes
	// flow information of the reverse flow

	for *offset < len(data) {
		if nested, t, l := parseNfAttrTL(data, offset); nested {
			switch t {
			case nl.CTA_TUPLE_ORIG:
				if nested, t, l = parseNfAttrTL(data, offset); nested && t == nl.CTA_TUPLE_IP {
					parseIpTuple(data, offset, &s.Forward)
				}
			case nl.CTA_TUPLE_REPLY:
				if nested, t, l = parseNfAttrTL(data, offset); nested && t == nl.CTA_TUPLE_IP {
					parseIpTuple(data, offset, &s.Reverse)
				} else {
					// Header not recognized skip it
					skipNfAttrValue(data, offset, l)
				}
			case nl.CTA_COUNTERS_ORIG:
				s.Forward.Bytes, s.Forward.Packets = parseByteAndPacketCounters(data, offset)
			case nl.CTA_COUNTERS_REPLY:
				s.Reverse.Bytes, s.Reverse.Packets = parseByteAndPacketCounters(data, offset)
			case nl.CTA_TIMESTAMP:
				s.TimeStart, s.TimeStop = parseTimeStamp(data, offset, l)
			case nl.CTA_PROTOINFO:
				s.ProtoInfo = parseProtoInfo(data, offset, l)
			default:
				skipNfAttrValue(data, offset, l)
			}
		} else {
			switch t {
			case nl.CTA_MARK:
				s.Mark = parseConnectionMark(data, offset)
			case nl.CTA_ZONE:
				s.Zone = parseConnectionZone(data, offset)
			case nl.CTA_LABELS:
				s.Labels = parseConnectionLabels(data, offset)
				s.HasLabels = true
			case nl.CTA_LABELS_MASK:
				s.LabelsMask = parseConnectionLabels(data, offset)
				s.HasLabelsMask = true
			case nl.CTA_TIMEOUT:
				s.TimeOut = parseTimeOut(data, offset)
			case nl.CTA_STATUS:
				s.Status = parseBERaw32(data, offset)
			case nl.CTA_USE:
				s.Use = parseBERaw32(data, offset)
			case nl.CTA_ID:
				s.ID = parseBERaw32(data, offset)
			default:
				skipNfAttrValue(data, offset, l)
			}
		}
	}
	return s
}

// Conntrack parameters and options:
//   -n, --src-nat ip                      source NAT ip
//   -g, --dst-nat ip                      destination NAT ip
//   -j, --any-nat ip                      source or destination NAT ip
//   -m, --mark mark                       Set mark
//   -c, --secmark secmark                 Set selinux secmark
//   -e, --event-mask eventmask            Event mask, eg. NEW,DESTROY
//   -z, --zero                            Zero counters while listing
//   -o, --output type[,...]               Output format, eg. xml
//   -l, --label label[,...]               conntrack labels

// Common parameters and options:
//   -s, --src, --orig-src ip              Source address from original direction
//   -d, --dst, --orig-dst ip              Destination address from original direction
//   -r, --reply-src ip            Source address from reply direction
//   -q, --reply-dst ip            Destination address from reply direction
//   -p, --protonum proto          Layer 4 Protocol, eg. 'tcp'
//   -f, --family proto            Layer 3 Protocol, eg. 'ipv6'
//   -t, --timeout timeout         Set timeout
//   -u, --status status           Set status, eg. ASSURED
//   -w, --zone value              Set conntrack zone
//   --orig-zone value             Set zone for original direction
//   --reply-zone value            Set zone for reply direction
//   -b, --buffer-size             Netlink socket buffer size
//   --mask-src ip                 Source mask address
//   --mask-dst ip                 Destination mask address

// Layer 4 Protocol common parameters and options:
// TCP, UDP, SCTP, UDPLite and DCCP
//    --sport, --orig-port-src port    Source port in original direction
//    --dport, --orig-port-dst port    Destination port in original direction

// Filter types
type ConntrackFilterType uint8

const (
	ConntrackOrigSrcIP     = iota                // -orig-src ip    Source address from original direction
	ConntrackOrigDstIP                           // -orig-dst ip    Destination address from original direction
	ConntrackReplySrcIP                          // --reply-src ip  Reply Source IP
	ConntrackReplyDstIP                          // --reply-dst ip  Reply Destination IP
	ConntrackReplyAnyIP                          // Match source or destination reply IP
	ConntrackOrigSrcPort                         // --orig-port-src port    Source port in original direction
	ConntrackOrigDstPort                         // --orig-port-dst port    Destination port in original direction
	ConntrackMatchLabels                         // --label label1,label2   Labels used in entry
	ConntrackUnmatchLabels                       // --label label1,label2   Labels not used in entry
	ConntrackNatSrcIP      = ConntrackReplySrcIP // deprecated use instead ConntrackReplySrcIP
	ConntrackNatDstIP      = ConntrackReplyDstIP // deprecated use instead ConntrackReplyDstIP
	ConntrackNatAnyIP      = ConntrackReplyAnyIP // deprecated use instead ConntrackReplyAnyIP
)

type CustomConntrackFilter interface {
	// MatchConntrackFlow applies the filter to the flow and returns true if the flow matches
	// the filter or false otherwise
	MatchConntrackFlow(flow *ConntrackFlow) bool
}

type ConntrackFilter struct {
	ipNetFilter map[ConntrackFilterType]*net.IPNet
	portFilter  map[ConntrackFilterType]uint16
	protoFilter uint8
	labelFilter map[ConntrackFilterType][][16]byte
	zoneFilter  *uint16
}

// AddIPNet adds a IP subnet to the conntrack filter
func (f *ConntrackFilter) AddIPNet(tp ConntrackFilterType, ipNet *net.IPNet) error {
	if ipNet == nil {
		return fmt.Errorf("Filter attribute empty")
	}
	if f.ipNetFilter == nil {
		f.ipNetFilter = make(map[ConntrackFilterType]*net.IPNet)
	}
	if _, ok := f.ipNetFilter[tp]; ok {
		return errors.New("Filter attribute already present")
	}
	f.ipNetFilter[tp] = ipNet
	return nil
}

// AddIP adds an IP to the conntrack filter
func (f *ConntrackFilter) AddIP(tp ConntrackFilterType, ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("Filter attribute empty")
	}
	return f.AddIPNet(tp, NewIPNet(ip))
}

// AddPort adds a Port to the conntrack filter if the Layer 4 protocol allows it
func (f *ConntrackFilter) AddPort(tp ConntrackFilterType, port uint16) error {
	switch f.protoFilter {
	// TCP, UDP, DCCP, SCTP, UDPLite
	case 6, 17, 33, 132, 136:
	default:
		return fmt.Errorf("Filter attribute not available without a valid Layer 4 protocol: %d", f.protoFilter)
	}

	if f.portFilter == nil {
		f.portFilter = make(map[ConntrackFilterType]uint16)
	}
	if _, ok := f.portFilter[tp]; ok {
		return errors.New("Filter attribute already present")
	}
	f.portFilter[tp] = port
	return nil
}

// AddProtocol adds the Layer 4 protocol to the conntrack filter
func (f *ConntrackFilter) AddProtocol(proto uint8) error {
	if f.protoFilter != 0 {
		return errors.New("Filter attribute already present")
	}
	f.protoFilter = proto
	return nil
}

// AddLabels adds the provided list (zero or more) of labels to the conntrack filter
// ConntrackFilterType here can be either:
//  1. ConntrackMatchLabels: This matches every flow that has a label value (len(flow.Labels) > 0)
//     against the list of provided labels. If `flow.Labels` contains ALL the provided labels
//     it is considered a match. This can be used when you want to match flows that contain
//     one or more labels.
//  2. ConntrackUnmatchLabels:  This matches every flow that has a label value (len(flow.Labels) > 0)
//     against the list of provided labels. If `flow.Labels` does NOT contain ALL the provided labels
//     it is considered a match. This can be used when you want to match flows that don't contain
//     one or more labels.
func (f *ConntrackFilter) AddLabels(tp ConntrackFilterType, labels [][16]byte) error {
	if len(labels) == 0 {
		return errors.New("Invalid length for provided labels")
	}
	if f.labelFilter == nil {
		f.labelFilter = make(map[ConntrackFilterType][][16]byte)
	}
	if _, ok := f.labelFilter[tp]; ok {
		return errors.New("Filter attribute already present")
	}
	f.labelFilter[tp] = labels
	return nil
}

// AddZone adds a zone to the conntrack filter
func (f *ConntrackFilter) AddZone(zone uint16) error {
	if f.zoneFilter != nil {
		return errors.New("Filter attribute already present")
	}
	f.zoneFilter = &zone
	return nil
}

// MatchConntrackFlow applies the filter to the flow and returns true if the flow matches the filter
// false otherwise
func (f *ConntrackFilter) MatchConntrackFlow(flow *ConntrackFlow) bool {
	if len(f.ipNetFilter) == 0 && len(f.portFilter) == 0 && f.protoFilter == 0 && len(f.labelFilter) == 0 && f.zoneFilter == nil {
		// empty filter always not match
		return false
	}

	// -p, --protonum proto          Layer 4 Protocol, eg. 'tcp'
	if f.protoFilter != 0 && flow.Forward.Protocol != f.protoFilter {
		// different Layer 4 protocol always not match
		return false
	}

	// Conntrack zone filter
	if f.zoneFilter != nil && *f.zoneFilter != flow.Zone {
		return false
	}

	match := true

	// IP conntrack filter
	if len(f.ipNetFilter) > 0 {
		// -orig-src ip   Source address from original direction
		if elem, found := f.ipNetFilter[ConntrackOrigSrcIP]; found {
			match = match && elem.Contains(flow.Forward.SrcIP)
		}

		// -orig-dst ip   Destination address from original direction
		if elem, found := f.ipNetFilter[ConntrackOrigDstIP]; match && found {
			match = match && elem.Contains(flow.Forward.DstIP)
		}

		// -src-nat ip    Source NAT ip
		if elem, found := f.ipNetFilter[ConntrackReplySrcIP]; match && found {
			match = match && elem.Contains(flow.Reverse.SrcIP)
		}

		// -dst-nat ip    Destination NAT ip
		if elem, found := f.ipNetFilter[ConntrackReplyDstIP]; match && found {
			match = match && elem.Contains(flow.Reverse.DstIP)
		}

		// Match source or destination reply IP
		if elem, found := f.ipNetFilter[ConntrackReplyAnyIP]; match && found {
			match = match && (elem.Contains(flow.Reverse.SrcIP) || elem.Contains(flow.Reverse.DstIP))
		}
	}

	// Layer 4 Port filter
	if len(f.portFilter) > 0 {
		// -orig-port-src port	Source port from original direction
		if elem, found := f.portFilter[ConntrackOrigSrcPort]; match && found {
			match = match && elem == flow.Forward.SrcPort
		}

		// -orig-port-dst port	Destination port from original direction
		if elem, found := f.portFilter[ConntrackOrigDstPort]; match && found {
			match = match && elem == flow.Forward.DstPort
		}
	}

	// Label filter
	if len(f.labelFilter) > 0 {
		if flow.HasLabels {
			// --label label1,label2 in conn entry;
			// every label passed should be contained in flow.Labels for a match to be true
			if elem, found := f.labelFilter[ConntrackMatchLabels]; match && found {
				for _, label := range elem {
					match = match && (bytes.Contains(flow.Labels[:], label[:]))
				}
			}
			// --label label1,label2 in conn entry;
			// every label passed should be not contained in flow.Labels for a match to be true
			if elem, found := f.labelFilter[ConntrackUnmatchLabels]; match && found {
				for _, label := range elem {
					match = match && !(bytes.Contains(flow.Labels[:], label[:]))
				}
			}
		} else {
			// flow doesn't contain labels, so it doesn't contain or notContain any provided matches
			match = false
		}
	}

	return match
}

var _ CustomConntrackFilter = (*ConntrackFilter)(nil)
