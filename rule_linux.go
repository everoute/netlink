package netlink

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const FibRuleInvert = 0x2

// RuleAdd adds a rule to the system.
// Equivalent to: ip rule add
func RuleAdd(rule *Rule) error {
	return pkgHandle.RuleAdd(rule)
}

// RuleAdd adds a rule to the system.
// Equivalent to: ip rule add
func (h *Handle) RuleAdd(rule *Rule) error {
	req := h.newNetlinkRequest(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	return ruleHandle(rule, req)
}

// RuleDel deletes a rule from the system.
// Equivalent to: ip rule del
func RuleDel(rule *Rule) error {
	return pkgHandle.RuleDel(rule)
}

// RuleDel deletes a rule from the system.
// Equivalent to: ip rule del
func (h *Handle) RuleDel(rule *Rule) error {
	req := h.newNetlinkRequest(unix.RTM_DELRULE, unix.NLM_F_ACK)
	return ruleHandle(rule, req)
}

func ruleHandle(rule *Rule, req *nl.NetlinkRequest) error {
	msg := nl.NewRtMsg()
	msg.Family = unix.AF_INET
	msg.Protocol = unix.RTPROT_BOOT
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	msg.Table = unix.RT_TABLE_UNSPEC
	msg.Type = rule.Type // usually 0, same as unix.RTN_UNSPEC
	if msg.Type == 0 && req.NlMsghdr.Flags&unix.NLM_F_CREATE > 0 {
		msg.Type = unix.RTN_UNICAST
	}
	if rule.Invert {
		msg.Flags |= FibRuleInvert
	}
	if rule.Family != 0 {
		msg.Family = uint8(rule.Family)
	}
	if rule.Table >= 0 && rule.Table < 256 {
		msg.Table = uint8(rule.Table)
	}
	if rule.Tos != 0 {
		msg.Tos = uint8(rule.Tos)
	}

	var dstFamily uint8
	var rtAttrs []*nl.RtAttr
	if rule.Dst != nil && rule.Dst.IP != nil {
		dstLen, _ := rule.Dst.Mask.Size()
		msg.Dst_len = uint8(dstLen)
		msg.Family = uint8(nl.GetIPFamily(rule.Dst.IP))
		dstFamily = msg.Family
		var dstData []byte
		if msg.Family == unix.AF_INET {
			dstData = rule.Dst.IP.To4()
		} else {
			dstData = rule.Dst.IP.To16()
		}
		rtAttrs = append(rtAttrs, nl.NewRtAttr(unix.RTA_DST, dstData))
	}

	if rule.Src != nil && rule.Src.IP != nil {
		msg.Family = uint8(nl.GetIPFamily(rule.Src.IP))
		if dstFamily != 0 && dstFamily != msg.Family {
			return fmt.Errorf("source and destination ip are not the same IP family")
		}
		srcLen, _ := rule.Src.Mask.Size()
		msg.Src_len = uint8(srcLen)
		var srcData []byte
		if msg.Family == unix.AF_INET {
			srcData = rule.Src.IP.To4()
		} else {
			srcData = rule.Src.IP.To16()
		}
		rtAttrs = append(rtAttrs, nl.NewRtAttr(unix.RTA_SRC, srcData))
	}

	req.AddData(msg)
	for i := range rtAttrs {
		req.AddData(rtAttrs[i])
	}

	if rule.Priority >= 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.Priority))
		req.AddData(nl.NewRtAttr(nl.FRA_PRIORITY, b))
	}
	if rule.Mark != 0 || rule.Mask != nil {
		b := make([]byte, 4)
		native.PutUint32(b, rule.Mark)
		req.AddData(nl.NewRtAttr(nl.FRA_FWMARK, b))
	}
	if rule.Mask != nil {
		b := make([]byte, 4)
		native.PutUint32(b, *rule.Mask)
		req.AddData(nl.NewRtAttr(nl.FRA_FWMASK, b))
	}
	if rule.Flow >= 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.Flow))
		req.AddData(nl.NewRtAttr(nl.FRA_FLOW, b))
	}
	if rule.TunID > 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.TunID))
		req.AddData(nl.NewRtAttr(nl.FRA_TUN_ID, b))
	}
	if rule.Table >= 256 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.Table))
		req.AddData(nl.NewRtAttr(nl.FRA_TABLE, b))
	}
	if msg.Table > 0 {
		if rule.SuppressPrefixlen >= 0 {
			b := make([]byte, 4)
			native.PutUint32(b, uint32(rule.SuppressPrefixlen))
			req.AddData(nl.NewRtAttr(nl.FRA_SUPPRESS_PREFIXLEN, b))
		}
		if rule.SuppressIfgroup >= 0 {
			b := make([]byte, 4)
			native.PutUint32(b, uint32(rule.SuppressIfgroup))
			req.AddData(nl.NewRtAttr(nl.FRA_SUPPRESS_IFGROUP, b))
		}
	}
	if rule.IifName != "" {
		req.AddData(nl.NewRtAttr(nl.FRA_IIFNAME, []byte(rule.IifName+"\x00")))
	}
	if rule.OifName != "" {
		req.AddData(nl.NewRtAttr(nl.FRA_OIFNAME, []byte(rule.OifName+"\x00")))
	}
	if rule.Goto >= 0 {
		msg.Type = nl.FR_ACT_GOTO
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.Goto))
		req.AddData(nl.NewRtAttr(nl.FRA_GOTO, b))
	}

	if rule.IPProto > 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.IPProto))
		req.AddData(nl.NewRtAttr(nl.FRA_IP_PROTO, b))
	}

	if rule.Dport != nil {
		b := rule.Dport.toRtAttrData()
		req.AddData(nl.NewRtAttr(nl.FRA_DPORT_RANGE, b))
	}

	if rule.Sport != nil {
		b := rule.Sport.toRtAttrData()
		req.AddData(nl.NewRtAttr(nl.FRA_SPORT_RANGE, b))
	}

	if rule.UIDRange != nil {
		b := rule.UIDRange.toRtAttrData()
		req.AddData(nl.NewRtAttr(nl.FRA_UID_RANGE, b))
	}

	if rule.Protocol > 0 {
		req.AddData(nl.NewRtAttr(nl.FRA_PROTOCOL, nl.Uint8Attr(rule.Protocol)))
	}

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// RuleList lists rules in the system.
// Equivalent to: ip rule list
//
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func RuleList(family int) ([]Rule, error) {
	return pkgHandle.RuleList(family)
}

// RuleList lists rules in the system.
// Equivalent to: ip rule list
//
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func (h *Handle) RuleList(family int) ([]Rule, error) {
	return h.RuleListFiltered(family, nil, 0)
}

// RuleListFiltered gets a list of rules in the system filtered by the
// specified rule template `filter`.
// Equivalent to: ip rule list
//
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func RuleListFiltered(family int, filter *Rule, filterMask uint64) ([]Rule, error) {
	return pkgHandle.RuleListFiltered(family, filter, filterMask)
}

// RuleListFiltered lists rules in the system.
// Equivalent to: ip rule list
//
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func (h *Handle) RuleListFiltered(family int, filter *Rule, filterMask uint64) ([]Rule, error) {
	req := h.newNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP|unix.NLM_F_REQUEST)
	msg := nl.NewIfInfomsg(family)
	req.AddData(msg)

	msgs, executeErr := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
	if executeErr != nil && !errors.Is(executeErr, ErrDumpInterrupted) {
		return nil, executeErr
	}

	var res = make([]Rule, 0)
	for i := range msgs {
		rule, err := deserializeRule(msgs[i])
		if err != nil {
			return nil, err
		}

		if filter != nil {
			switch {
			case filterMask&RT_FILTER_SRC != 0 &&
				(rule.Src == nil || rule.Src.String() != filter.Src.String()):
				continue
			case filterMask&RT_FILTER_DST != 0 &&
				(rule.Dst == nil || rule.Dst.String() != filter.Dst.String()):
				continue
			case filterMask&RT_FILTER_TABLE != 0 &&
				filter.Table != unix.RT_TABLE_UNSPEC && rule.Table != filter.Table:
				continue
			case filterMask&RT_FILTER_TOS != 0 && rule.Tos != filter.Tos:
				continue
			case filterMask&RT_FILTER_PRIORITY != 0 && rule.Priority != filter.Priority:
				continue
			case filterMask&RT_FILTER_MARK != 0 && rule.Mark != filter.Mark:
				continue
			case filterMask&RT_FILTER_MASK != 0 && !ptrEqual(rule.Mask, filter.Mask):
				continue
			}
		}

		res = append(res, *rule)
	}

	return res, executeErr
}

func (pr *RulePortRange) toRtAttrData() []byte {
	b := [][]byte{make([]byte, 2), make([]byte, 2)}
	native.PutUint16(b[0], pr.Start)
	native.PutUint16(b[1], pr.End)
	return bytes.Join(b, []byte{})
}

func (pr *RuleUIDRange) toRtAttrData() []byte {
	b := [][]byte{make([]byte, 4), make([]byte, 4)}
	native.PutUint32(b[0], pr.Start)
	native.PutUint32(b[1], pr.End)
	return bytes.Join(b, []byte{})
}

func ptrEqual(a, b *uint32) bool {
	if a == b {
		return true
	}
	if (a == nil) || (b == nil) {
		return false
	}
	return *a == *b
}

func (r Rule) typeString() string {
	switch r.Type {
	case unix.RTN_UNSPEC: // zero
		return ""
	case unix.RTN_UNICAST:
		return ""
	case unix.RTN_LOCAL:
		return "local"
	case unix.RTN_BROADCAST:
		return "broadcast"
	case unix.RTN_ANYCAST:
		return "anycast"
	case unix.RTN_MULTICAST:
		return "multicast"
	case unix.RTN_BLACKHOLE:
		return "blackhole"
	case unix.RTN_UNREACHABLE:
		return "unreachable"
	case unix.RTN_PROHIBIT:
		return "prohibit"
	case unix.RTN_THROW:
		return "throw"
	case unix.RTN_NAT:
		return "nat"
	case unix.RTN_XRESOLVE:
		return "xresolve"
	default:
		return fmt.Sprintf("type(0x%x)", r.Type)
	}
}

// deserializeRule decodes a binary netlink message into a Rule struct
func deserializeRule(m []byte) (*Rule, error) {
	msg := nl.DeserializeRtMsg(m)
	attrs, err := nl.ParseRouteAttr(m[msg.Len():])
	if err != nil {
		return nil, err
	}

	rule := NewRule()
	rule.Priority = 0 // The default priority from kernel

	rule.Invert = msg.Flags&FibRuleInvert > 0
	rule.Family = int(msg.Family)
	rule.Tos = uint(msg.Tos)

	for j := range attrs {
		switch attrs[j].Attr.Type {
		case unix.RTA_TABLE:
			rule.Table = int(native.Uint32(attrs[j].Value[0:4]))
		case nl.FRA_SRC:
			rule.Src = &net.IPNet{
				IP:   attrs[j].Value,
				Mask: net.CIDRMask(int(msg.Src_len), 8*len(attrs[j].Value)),
			}
		case nl.FRA_DST:
			rule.Dst = &net.IPNet{
				IP:   attrs[j].Value,
				Mask: net.CIDRMask(int(msg.Dst_len), 8*len(attrs[j].Value)),
			}
		case nl.FRA_FWMARK:
			rule.Mark = native.Uint32(attrs[j].Value[0:4])
		case nl.FRA_FWMASK:
			mask := native.Uint32(attrs[j].Value[0:4])
			rule.Mask = &mask
		case nl.FRA_TUN_ID:
			rule.TunID = uint(native.Uint64(attrs[j].Value[0:8]))
		case nl.FRA_IIFNAME:
			rule.IifName = string(attrs[j].Value[:len(attrs[j].Value)-1])
		case nl.FRA_OIFNAME:
			rule.OifName = string(attrs[j].Value[:len(attrs[j].Value)-1])
		case nl.FRA_SUPPRESS_PREFIXLEN:
			i := native.Uint32(attrs[j].Value[0:4])
			if i != 0xffffffff {
				rule.SuppressPrefixlen = int(i)
			}
		case nl.FRA_SUPPRESS_IFGROUP:
			i := native.Uint32(attrs[j].Value[0:4])
			if i != 0xffffffff {
				rule.SuppressIfgroup = int(i)
			}
		case nl.FRA_FLOW:
			rule.Flow = int(native.Uint32(attrs[j].Value[0:4]))
		case nl.FRA_GOTO:
			rule.Goto = int(native.Uint32(attrs[j].Value[0:4]))
		case nl.FRA_PRIORITY:
			rule.Priority = int(native.Uint32(attrs[j].Value[0:4]))
		case nl.FRA_IP_PROTO:
			rule.IPProto = int(native.Uint32(attrs[j].Value[0:4]))
		case nl.FRA_DPORT_RANGE:
			rule.Dport = NewRulePortRange(native.Uint16(attrs[j].Value[0:2]), native.Uint16(attrs[j].Value[2:4]))
		case nl.FRA_SPORT_RANGE:
			rule.Sport = NewRulePortRange(native.Uint16(attrs[j].Value[0:2]), native.Uint16(attrs[j].Value[2:4]))
		case nl.FRA_UID_RANGE:
			rule.UIDRange = NewRuleUIDRange(native.Uint32(attrs[j].Value[0:4]), native.Uint32(attrs[j].Value[4:8]))
		case nl.FRA_PROTOCOL:
			rule.Protocol = uint8(attrs[j].Value[0])
		}
	}

	return rule, nil
}

// RuleSubscribe takes a chan down which notifications will be sent
// when rules are added or deleted. Close the 'done' chan to stop subscription.
func RuleSubscribe(ch chan<- RuleUpdate, done <-chan struct{}) error {
	return ruleSubscribeAt(netns.None(), netns.None(), ch, done, nil, false, 0, nil, false)
}

// RuleSubscribeAt works like RuleSubscribe plus it allows the caller
// to choose the network namespace in which to subscribe (ns).
func RuleSubscribeAt(ns netns.NsHandle, ch chan<- RuleUpdate, done <-chan struct{}) error {
	return ruleSubscribeAt(ns, netns.None(), ch, done, nil, false, 0, nil, false)
}

// RuleSubscribeOptions contains a set of options to use with
// RuleSubscribeWithOptions.
type RuleSubscribeOptions struct {
	Namespace              *netns.NsHandle
	ErrorCallback          func(error)
	ListExisting           bool
	ReceiveBufferSize      int
	ReceiveBufferForceSize bool
	ReceiveTimeout         *unix.Timeval
}

// RuleSubscribeWithOptions work like RuleSubscribe but enable to
// provide additional options to modify the behavior. Currently, the
// namespace can be provided as well as an error callback.
func RuleSubscribeWithOptions(ch chan<- RuleUpdate, done <-chan struct{}, options RuleSubscribeOptions) error {
	if options.Namespace == nil {
		none := netns.None()
		options.Namespace = &none
	}
	return ruleSubscribeAt(*options.Namespace, netns.None(), ch, done, options.ErrorCallback, options.ListExisting,
		options.ReceiveBufferSize, options.ReceiveTimeout, options.ReceiveBufferForceSize)
}

func ruleSubscribeAt(newNs, curNs netns.NsHandle, ch chan<- RuleUpdate, done <-chan struct{}, cberr func(error), listExisting bool,
	rcvbuf int, rcvTimeout *unix.Timeval, rcvbufForce bool) error {
	s, err := nl.SubscribeAt(newNs, curNs, unix.NETLINK_ROUTE, unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE)
	if err != nil {
		return err
	}
	if rcvTimeout != nil {
		if err := s.SetReceiveTimeout(rcvTimeout); err != nil {
			return err
		}
	}
	if rcvbuf != 0 {
		err = s.SetReceiveBufferSize(rcvbuf, rcvbufForce)
		if err != nil {
			return err
		}
	}
	if done != nil {
		go func() {
			<-done
			s.Close()
		}()
	}
	if listExisting {
		req := pkgHandle.newNetlinkRequest(unix.RTM_GETRULE,
			unix.NLM_F_DUMP)
		infmsg := nl.NewIfInfomsg(unix.AF_UNSPEC)
		req.AddData(infmsg)
		if err := s.Send(req); err != nil {
			return err
		}
	}
	go func() {
		defer close(ch)
		for {
			msgs, from, err := s.Receive()
			if err != nil {
				if cberr != nil {
					cberr(fmt.Errorf("Receive failed: %v",
						err))
				}
				return
			}
			if from.Pid != nl.PidKernel {
				if cberr != nil {
					cberr(fmt.Errorf("Wrong sender portid %d, expected %d", from.Pid, nl.PidKernel))
				}
				continue
			}
			for _, m := range msgs {
				if m.Header.Type == unix.NLMSG_DONE {
					continue
				}
				if m.Header.Type == unix.NLMSG_ERROR {
					error := int32(native.Uint32(m.Data[0:4]))
					if error == 0 {
						continue
					}
					if cberr != nil {
						cberr(fmt.Errorf("error message: %v",
							syscall.Errno(-error)))
					}
					continue
				}
				rule, err := deserializeRule(m.Data)
				if err != nil {
					if cberr != nil {
						cberr(err)
					}
					continue
				}
				ch <- RuleUpdate{Type: m.Header.Type, Rule: *rule}
			}
		}
	}()

	return nil
}
