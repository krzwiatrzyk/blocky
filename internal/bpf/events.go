package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"blocky/internal/types"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/rs/zerolog"
)

// nameProbeBytes mirrors MAX_SNI_PROBE in blocky.c. Must stay in sync.
// The kernel field stores either the TLS SNI (tcp/443) or the DNS QNAME
// (udp/53) — userspace surfaces both as FlowEvent.Name.
const nameProbeBytes = 32

// Wire constants — must mirror the values emitted by blocky.c.
const (
	protoTCP uint8 = 6
	protoUDP uint8 = 17

	verdictAllowKernel uint8 = 1
	verdictDropKernel  uint8 = 2

	reasonNoPolicy         uint8 = 0
	reasonDNSExempt        uint8 = 1
	reasonSNIAllowed       uint8 = 2
	reasonSNIBlocked       uint8 = 3
	reasonNonTLSRestricted uint8 = 4
	reasonTLSParseFailed   uint8 = 5
	reasonCTAllowed        uint8 = 6
	reasonCTDenied         uint8 = 7
	reasonPortAllowed      uint8 = 8
	reasonPortBlocked      uint8 = 9
)

// kernelFlowEvent mirrors struct flow_event_t in blocky.c.
//
// Layout, in bytes (little-endian on bpfel targets):
//
//	 0: u64 ts_ns
//	 8: u32 ifindex
//	12: u32 sip          (network byte order; raw bytes from iphdr->saddr)
//	16: u32 dip
//	20: u16 sport        (already host-order: kernel does bpf_ntohs)
//	22: u16 dport
//	24: u8  proto
//	25: u8  verdict
//	26: u8  reason
//	27: u8  name_len     (kernel side: sni_len; field reused for DNS QNAME)
//	28: char name[32]    (kernel side: sni[]; field reused for DNS QNAME)
//	total: 60 bytes
type kernelFlowEvent struct {
	TsNs    uint64
	Ifindex uint32
	Sip     uint32
	Dip     uint32
	Sport   uint16
	Dport   uint16
	Proto   uint8
	Verdict uint8
	Reason  uint8
	NameLen uint8
	Name    [nameProbeBytes]byte
}

const kernelFlowEventSize = 8 + 4 + 4 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + nameProbeBytes // 60

// DNSResolved is one IPv4 A-record observation surfaced by the response-side
// BPF program. Userspace consumes a channel of these and feeds them into a
// per-container LRU IP→name cache for tap enrichment.
type DNSResolved struct {
	Ifindex int
	IP      string
	Name    string
}

// kernelDNSResolvedEvent mirrors struct dns_resolved_event_t in blocky.c.
//
//	 0: u64 ts_ns
//	 8: u32 ifindex
//	12: u32 ip            (network byte order, raw)
//	16: u8  name_len
//	17: u8  _pad[3]
//	20: char name[32]
//	total: 52 bytes
type kernelDNSResolvedEvent struct {
	TsNs    uint64
	Ifindex uint32
	IP      uint32
	NameLen uint8
	_       [3]uint8
	Name    [nameProbeBytes]byte
}

const kernelDNSResolvedEventSize = 8 + 4 + 4 + 1 + 3 + nameProbeBytes // 52

type dnsResolvedReader struct {
	r    *ringbuf.Reader
	out  chan<- DNSResolved
	log  zerolog.Logger
	done chan struct{}
}

func newDNSResolvedReader(m *ebpf.Map, out chan<- DNSResolved, log zerolog.Logger) (*dnsResolvedReader, error) {
	r, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("dns_resolved NewReader: %w", err)
	}
	d := &dnsResolvedReader{r: r, out: out, log: log, done: make(chan struct{})}
	go d.run()
	return d, nil
}

func (d *dnsResolvedReader) Close() error {
	if err := d.r.Close(); err != nil {
		return err
	}
	<-d.done
	return nil
}

func (d *dnsResolvedReader) run() {
	defer close(d.done)
	for {
		rec, err := d.r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			d.log.Error().Err(err).Msg("dns_resolved ringbuf read")
			continue
		}
		if len(rec.RawSample) < kernelDNSResolvedEventSize {
			d.log.Warn().Int("len", len(rec.RawSample)).Msg("short dns_resolved record")
			continue
		}
		var ev kernelDNSResolvedEvent
		if _, err := binary.Decode(rec.RawSample, binary.LittleEndian, &ev); err != nil {
			d.log.Error().Err(err).Msg("decode dns_resolved event")
			continue
		}
		if ev.NameLen == 0 {
			continue
		}
		n := int(ev.NameLen)
		if n > nameProbeBytes {
			n = nameProbeBytes
		}
		d.out <- DNSResolved{
			Ifindex: int(ev.Ifindex),
			IP:      ipToString(ev.IP),
			Name:    string(ev.Name[:n]),
		}
	}
}

type ringbufReader struct {
	r    *ringbuf.Reader
	out  chan<- types.FlowEvent
	log  zerolog.Logger
	done chan struct{}
}

func newRingbufReader(eventsMap *ebpf.Map, out chan<- types.FlowEvent, log zerolog.Logger) (*ringbufReader, error) {
	r, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("ringbuf NewReader: %w", err)
	}
	rb := &ringbufReader{r: r, out: out, log: log, done: make(chan struct{})}
	go rb.run()
	return rb, nil
}

func (r *ringbufReader) Close() error {
	if err := r.r.Close(); err != nil {
		return err
	}
	<-r.done
	return nil
}

func (r *ringbufReader) run() {
	defer close(r.done)
	for {
		rec, err := r.r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			r.log.Error().Err(err).Msg("ringbuf read")
			continue
		}
		if len(rec.RawSample) < kernelFlowEventSize {
			r.log.Warn().Int("len", len(rec.RawSample)).Msg("short ringbuf record")
			continue
		}
		var ev kernelFlowEvent
		if _, err := binary.Decode(rec.RawSample, binary.LittleEndian, &ev); err != nil {
			r.log.Error().Err(err).Msg("decode flow event")
			continue
		}
		r.out <- toFlowEvent(&ev)
	}
}

func toFlowEvent(k *kernelFlowEvent) types.FlowEvent {
	// Userspace decode time. Skew vs the kernel ts_ns is sub-millisecond,
	// well below what a per-flow tap stream cares about.
	out := types.FlowEvent{
		Timestamp: time.Now(),
		Ifindex:   int(k.Ifindex),
		SrcIP:     ipToString(k.Sip),
		DstIP:     ipToString(k.Dip),
		SrcPort:   k.Sport,
		DstPort:   k.Dport,
		Protocol:  protoString(k.Proto),
		Verdict:   verdictFromKernel(k.Verdict),
		Reason:    reasonFromKernel(k.Reason),
	}
	if k.NameLen > 0 {
		n := int(k.NameLen)
		if n > nameProbeBytes {
			n = nameProbeBytes
		}
		out.Name = string(k.Name[:n])
	}
	return out
}

func ipToString(raw uint32) string {
	// raw is in network byte order (as read from iphdr->saddr). On a
	// little-endian host the byte at LSB is the first octet. byte() of a
	// uint32 is defined to take the low 8 bits — the mask is for the linter.
	b := []byte{
		byte(raw & 0xff),         //nolint:gosec // explicit low byte
		byte((raw >> 8) & 0xff),  //nolint:gosec
		byte((raw >> 16) & 0xff), //nolint:gosec
		byte((raw >> 24) & 0xff), //nolint:gosec
	}
	return net.IP(b).String()
}

func protoString(p uint8) string {
	switch p {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	default:
		return fmt.Sprintf("proto-%d", p)
	}
}

func verdictFromKernel(v uint8) types.Verdict {
	switch v {
	case verdictAllowKernel:
		return types.VerdictAllow
	case verdictDropKernel:
		return types.VerdictDrop
	default:
		return types.VerdictDrop
	}
}

func reasonFromKernel(r uint8) types.Reason {
	switch r {
	case reasonNoPolicy:
		return types.ReasonNoPolicy
	case reasonDNSExempt:
		return types.ReasonDNSExempt
	case reasonSNIAllowed:
		return types.ReasonSNIAllowed
	case reasonSNIBlocked:
		return types.ReasonSNIBlocked
	case reasonNonTLSRestricted:
		return types.ReasonNonTLSRestricted
	case reasonTLSParseFailed:
		return types.ReasonTLSParseFailed
	case reasonCTAllowed:
		return types.ReasonCTAllowed
	case reasonCTDenied:
		return types.ReasonCTDenied
	case reasonPortAllowed:
		return types.ReasonPortAllowed
	case reasonPortBlocked:
		return types.ReasonPortBlocked
	default:
		return types.ReasonNoPolicy
	}
}
