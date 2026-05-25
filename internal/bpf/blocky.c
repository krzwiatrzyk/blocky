//go:build ignore

// blocky BPF program — TC clsact egress filter for per-container SNI policy.
//
// Map design (storing names as VALUES, not embedded in KEYS, keeps loops simple):
//   policy_meta[ifindex]              = {mode, n_exact, n_suffix}    HASH 4096
//   policy_exact[{ifindex, idx}]      = {len, name[253]}              HASH 4096*16
//   policy_suffix[{ifindex, idx}]     = {len, name[253]}              HASH 4096*16
//   ct[{ifindex,sip,sport,dip,dport,proto}] = {verdict, last_seen}    LRU_HASH 16384
//   events                                                            RINGBUF 256 KiB

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

#define MODE_PASS 0
#define MODE_DENY 1

#define MAX_RULES        8
#define MAX_PORTS        16
/* Practical hostname cap. RFC permits 253; we limit to 31 so the loops fit
 * the BPF verifier's 1M-insn budget. Real SNIs (e.g. www.googleapis.com) are
 * comfortably under this. */
#define MAX_NAME_LEN     31
#define NAME_BUF_LEN     32   /* pow-2 for verifier-friendly masking */
#define NAME_BUF_MASK    (NAME_BUF_LEN - 1)
#define MAX_TLS_EXTS     20
#define MAX_SNI_PROBE    32

#define VERDICT_PENDING 0
#define VERDICT_ALLOW   1
#define VERDICT_DENY    2

#define REASON_NO_POLICY          0
#define REASON_DNS_EXEMPT         1
#define REASON_SNI_ALLOWED        2
#define REASON_SNI_BLOCKED        3
#define REASON_NON_TLS_RESTRICTED 4
#define REASON_TLS_PARSE_FAILED   5
#define REASON_CT_ALLOWED         6
#define REASON_CT_DENIED          7
#define REASON_PORT_ALLOWED       8
#define REASON_PORT_BLOCKED       9

char LICENSE[] SEC("license") = "GPL";

struct policy_meta_t {
    __u8 mode;
    __u8 n_exact;
    __u8 n_suffix;
    __u8 n_ports;   /* 0 = legacy mode (DNS+443 hardcoded); >0 = port allowlist */
    __u8 observe;   /* 1 = observe-only: emit but never drop */
    __u8 _pad[3];
};

struct port_key_t {
    __u32 ifindex;
    __u16 port;
    __u16 _pad;
};

struct rule_key_t {
    __u32 ifindex;
    __u8  idx;
    __u8  _pad[3];
};

struct rule_val_t {
    __u16 len;
    __u8  _pad[2];
    char  name[NAME_BUF_LEN];
};

struct ct_key_t {
    __u32 ifindex;
    __u32 sip;
    __u32 dip;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  _pad[3];
};

struct ct_val_t {
    __u8  verdict;
    __u8  _pad[3];
    __u64 last_seen_ns;
};

struct flow_event_t {
    __u64 ts_ns;
    __u32 ifindex;
    __u32 sip;
    __u32 dip;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  verdict;
    __u8  reason;
    __u8  sni_len;
    char  sni[MAX_SNI_PROBE];
};

/* One A-record observation. Userspace inserts {ifindex, ip} -> name into its
 * per-container LRU cache so subsequent non-DNS flows can be enriched with the
 * domain the container resolved earlier. */
struct dns_resolved_event_t {
    __u64 ts_ns;
    __u32 ifindex;
    __u32 ip;             /* network byte order, raw from the A-record RDATA */
    __u8  name_len;
    __u8  _pad[3];
    char  name[NAME_BUF_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct policy_meta_t);
    __uint(max_entries, 4096);
} policy_meta SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rule_key_t);
    __type(value, struct rule_val_t);
    __uint(max_entries, 4096 * MAX_RULES);
} policy_exact SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rule_key_t);
    __type(value, struct rule_val_t);
    __uint(max_entries, 4096 * MAX_RULES);
} policy_suffix SEC(".maps");

/* Port allowlist membership: presence of key {ifindex, port} ⇒ allowed.
 * policy_meta.n_ports == 0 means "no port filter, apply legacy DNS/443 mode". */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_key_t);
    __type(value, __u8);
    __uint(max_entries, 4096 * MAX_PORTS);
} policy_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ct_key_t);
    __type(value, struct ct_val_t);
    __uint(max_entries, 16384);
} ct SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} dns_resolved SEC(".maps");

static __always_inline void emit(__u32 ifindex, __u32 sip, __u32 dip,
                                 __u16 sport, __u16 dport, __u8 proto,
                                 __u8 verdict, __u8 reason,
                                 const char *sni, __u8 sni_len)
{
    struct flow_event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return;
    }
    e->ts_ns   = bpf_ktime_get_ns();
    e->ifindex = ifindex;
    e->sip     = sip;
    e->dip     = dip;
    e->sport   = sport;
    e->dport   = dport;
    e->proto   = proto;
    e->verdict = verdict;
    e->reason  = reason;
    e->sni_len = sni_len;
    /* Constant-size copy keeps the verifier insn count flat. All callers pass
     * either NULL (no name) or a NAME_BUF_LEN-sized stack buffer, which is the
     * same size as e->sni. The buffers are zero-initialised by the caller, so
     * copying the full MAX_SNI_PROBE bytes is safe — sni_len bounds the valid
     * prefix for consumers. */
    if (sni) {
        __builtin_memcpy(e->sni, sni, MAX_SNI_PROBE);
    } else {
        __builtin_memset(e->sni, 0, MAX_SNI_PROBE);
    }
    bpf_ringbuf_submit(e, 0);
}

/* Bounds for verifier sanity. */
#define MAX_CIPHER_LEN     512
#define MAX_COMPR_LEN      16
#define MAX_SESSION_ID_LEN 32
#define MAX_EXT_TOTAL_LEN  2048
#define MAX_EXT_BODY_LEN   1024

#define MAX_DNS_LABELS     8
#define DNS_HEADER_LEN     12
#define DNS_LABEL_MAX      31
#define DNS_SCAN_LEN       64   /* pow-2; one-shot helper-call sized buffer */
#define DNS_SCAN_MASK      (DNS_SCAN_LEN - 1)

/* Context for the bpf_loop-driven QNAME walker. Lives on the BPF stack so the
 * callback body is verified once instead of unrolled MAX_DNS_LABELS times. */
struct dns_parse_ctx_t {
    __u8  buf[DNS_SCAN_LEN];      /* 64-byte snapshot of the DNS payload */
    char  out[NAME_BUF_LEN];      /* dotted, lowercased output */
    __u32 pos;                    /* read cursor inside buf */
    __u32 written;                /* write cursor inside out */
    __u8  done;                   /* sticky stop flag (also signals error) */
};

static long dns_label_cb(__u32 index, struct dns_parse_ctx_t *ctx)
{
    if (ctx->done) return 1;
    __u32 pos = ctx->pos;
    if (pos >= DNS_SCAN_LEN - 1) { ctx->done = 1; return 1; }

    __u8 label_len = ctx->buf[pos & DNS_SCAN_MASK];
    if (label_len == 0)             { ctx->done = 1; return 1; }
    if (label_len & 0xC0)           { ctx->done = 1; return 1; }
    if (label_len > DNS_LABEL_MAX)  { ctx->done = 1; return 1; }
    if (pos + 1u + (__u32)label_len > DNS_SCAN_LEN) {
        ctx->done = 1; return 1;
    }

    __u32 needed = (__u32)label_len + (ctx->written > 0 ? 1u : 0u);
    if (ctx->written + needed >= MAX_NAME_LEN) {
        /* Output would overflow — stop cleanly, keep the valid prefix. */
        ctx->done = 1; return 1;
    }

    if (ctx->written > 0) {
        ctx->out[ctx->written & NAME_BUF_MASK] = '.';
        ctx->written++;
    }
    for (__u32 j = 0; j < DNS_LABEL_MAX; j++) {
        if (j >= label_len) break;
        __u32 src = (pos + 1u + j) & DNS_SCAN_MASK;
        __u8  ch  = ctx->buf[src];
        if (ch >= 'A' && ch <= 'Z') ch += 32;
        ctx->out[(ctx->written + j) & NAME_BUF_MASK] = (char)ch;
    }
    ctx->written += label_len;
    ctx->pos     = pos + 1u + (__u32)label_len;
    return 0;
}

/* Parse the QNAME of the first question in a DNS query payload and write a
 * lowercased dotted form into `out` (NAME_BUF_LEN bytes). Returns 0 on success,
 * -1 if no QNAME could be extracted. */
static __always_inline int parse_dns_qname(struct __sk_buff *skb,
                                           __u32 payload_off,
                                           char *out, __u8 *out_len)
{
    struct dns_parse_ctx_t ctx = {};

    /* Real DNS queries are often shorter than DNS_SCAN_LEN bytes — a query for
     * "www.google.com" without EDNS0 is ~32 bytes total. bpf_skb_load_bytes
     * fails the whole load if any byte is past skb->len, so cap the requested
     * size at skb->len - payload_off. Bytes beyond the load remain zero from
     * the struct initializer above, which acts as a natural QNAME terminator. */
    __u32 skb_len = skb->len;
    if (skb_len <= payload_off) return -1;
    __u32 avail = skb_len - payload_off;
    if (avail < DNS_HEADER_LEN + 2u) return -1;
    __u32 to_load = avail < DNS_SCAN_LEN ? avail : DNS_SCAN_LEN;
    if (to_load > DNS_SCAN_LEN) to_load = DNS_SCAN_LEN;   /* verifier hint */
    if (bpf_skb_load_bytes(skb, payload_off, ctx.buf, to_load) < 0) return -1;

    /* QDCOUNT at offset 4..6 of the DNS header, big-endian. */
    __u16 qdcount = ((__u16)ctx.buf[4] << 8) | (__u16)ctx.buf[5];
    if (qdcount == 0) return -1;

    ctx.pos = DNS_HEADER_LEN;
    bpf_loop(MAX_DNS_LABELS, dns_label_cb, &ctx, 0);

    if (ctx.written == 0) return -1;
    __builtin_memcpy(out, ctx.out, NAME_BUF_LEN);
    *out_len = (__u8)(ctx.written > MAX_NAME_LEN ? MAX_NAME_LEN
                                                  : ctx.written);
    return 0;
}

/* ============================================================================
 * DNS response parsing (UDP/53 traffic going TO the container).
 * ============================================================================
 *
 * We need a bigger buffer than the query parser because responses include the
 * question echoed back PLUS the answer section. Typical A-record responses are
 * 80–200 bytes; we cap at 256.
 */
#define DNS_RESP_SCAN_LEN  256
#define DNS_RESP_SCAN_MASK (DNS_RESP_SCAN_LEN - 1)
#define MAX_DNS_ANSWERS    4

/* Context for the bpf_loop-driven question-QNAME walker over the bigger
 * response buffer. Same shape as dns_parse_ctx_t but with DNS_RESP_SCAN_LEN. */
struct dns_resp_ctx_t {
    __u8  buf[DNS_RESP_SCAN_LEN];
    char  qname[NAME_BUF_LEN];     /* parsed question QNAME */
    __u32 pos;
    __u32 qname_written;
    __u8  qname_done;
    __u8  qname_overflow;          /* set when truncation happened in qname */
};

static long resp_qname_cb(__u32 index, struct dns_resp_ctx_t *ctx)
{
    if (ctx->qname_done) return 1;
    __u32 pos = ctx->pos;
    if (pos >= DNS_RESP_SCAN_LEN - 1) { ctx->qname_done = 1; return 1; }

    __u8 label_len = ctx->buf[pos & DNS_RESP_SCAN_MASK];
    if (label_len == 0) {
        ctx->pos = pos + 1u;
        ctx->qname_done = 1;
        return 1;
    }
    if (label_len & 0xC0) {
        /* Compression pointer — 2-byte field terminates the QNAME. */
        ctx->pos = pos + 2u;
        ctx->qname_done = 1;
        return 1;
    }
    if (label_len > DNS_LABEL_MAX)              { ctx->qname_done = 1; return 1; }
    if (pos + 1u + (__u32)label_len > DNS_RESP_SCAN_LEN) {
        ctx->qname_done = 1; return 1;
    }

    __u32 needed = (__u32)label_len + (ctx->qname_written > 0 ? 1u : 0u);
    if (ctx->qname_written + needed >= MAX_NAME_LEN) {
        /* Output buffer full but we still need to advance pos past the label
         * so the answer-section walker reads from the right offset. */
        ctx->qname_overflow = 1;
        ctx->pos = pos + 1u + (__u32)label_len;
        return 0;
    }

    if (ctx->qname_written > 0) {
        ctx->qname[ctx->qname_written & NAME_BUF_MASK] = '.';
        ctx->qname_written++;
    }
    for (__u32 j = 0; j < DNS_LABEL_MAX; j++) {
        if (j >= label_len) break;
        __u32 src = (pos + 1u + j) & DNS_RESP_SCAN_MASK;
        __u8  ch  = ctx->buf[src];
        if (ch >= 'A' && ch <= 'Z') ch += 32;
        ctx->qname[(ctx->qname_written + j) & NAME_BUF_MASK] = (char)ch;
    }
    ctx->qname_written += label_len;
    ctx->pos            = pos + 1u + (__u32)label_len;
    return 0;
}

/* Context for the answer-section walker. Holds the skb so each answer is
 * read via bpf_skb_load_bytes — that avoids the verifier-pessimal pattern of
 * variable-offset reads off a single large stack buffer. */
struct dns_ans_ctx_t {
    struct __sk_buff *skb;
    const char       *qname;
    __u32            pos;        /* absolute byte offset into the skb */
    __u32            skb_len;
    __u32            ifindex;
    __u8             qname_len;
};

/* The answer-section walker reads directly from the skb via fixed-size loads
 * into small stack buffers, sidestepping the verifier's struggles with
 * variable-offset reads off larger stack buffers. We rely on the fact that
 * answer-section NAME fields are virtually always 2-byte compression pointers
 * pointing at the question section — true for every mainstream DNS server.
 * Answers using inline labels are skipped (we return early without emitting). */
static long resp_answer_cb(__u32 index, struct dns_ans_ctx_t *ctx)
{
    __u32 pos = ctx->pos;
    __u32 skb_len = ctx->skb_len;
    /* Need at least 2 (NAME compression pointer) + 10 (RR header). */
    if (pos + 12u > skb_len) return 1;
    if (pos + 12u < pos)      return 1;   /* defensive: wrap guard */

    /* Load NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) in one helper call. */
    __u8 hdr[12];
    if (bpf_skb_load_bytes(ctx->skb, pos, hdr, 12) < 0) return 1;

    /* Skip NAME. Compression pointers (0xC0..) take 2 bytes; anything else
     * is inline-labels in which case we bail on this answer for simplicity. */
    if ((hdr[0] & 0xC0) != 0xC0) {
        return 1;   /* not compression — give up; bpf_loop stops cleanly */
    }
    __u16 rtype  = ((__u16)hdr[2] << 8) | (__u16)hdr[3];
    __u16 rclass = ((__u16)hdr[4] << 8) | (__u16)hdr[5];
    __u16 rdlen  = ((__u16)hdr[10] << 8) | (__u16)hdr[11];

    __u32 rdata_off = pos + 12u;
    __u32 next_pos  = rdata_off + (__u32)rdlen;
    if (next_pos > skb_len || next_pos < rdata_off) return 1;

    if (rtype == 1 && rclass == 1 && rdlen == 4) {
        __u8 ipbuf[4];
        if (bpf_skb_load_bytes(ctx->skb, rdata_off, ipbuf, 4) >= 0) {
            __u32 ip = (__u32)ipbuf[0]
                     | ((__u32)ipbuf[1] << 8)
                     | ((__u32)ipbuf[2] << 16)
                     | ((__u32)ipbuf[3] << 24);
            struct dns_resolved_event_t *e =
                bpf_ringbuf_reserve(&dns_resolved, sizeof(*e), 0);
            if (e) {
                e->ts_ns    = bpf_ktime_get_ns();
                e->ifindex  = ctx->ifindex;
                e->ip       = ip;
                e->name_len = ctx->qname_len;
                __builtin_memcpy(e->name, ctx->qname, NAME_BUF_LEN);
                bpf_ringbuf_submit(e, 0);
            }
        }
    }

    ctx->pos = next_pos;
    return 0;
}

/* Read primitives use bpf_skb_load_bytes — no pkt-pointer arithmetic; the
 * helper handles bounds internally so the verifier just tracks stack buffers. */
#define LD_U8(off, dst)                                                       \
    do {                                                                      \
        __u8 tmp_;                                                            \
        if (bpf_skb_load_bytes(skb, (__u32)(off), &tmp_, 1) < 0) return -1;   \
        (dst) = tmp_;                                                         \
    } while (0)

#define LD_U16(off, dst)                                                      \
    do {                                                                      \
        __u8 tmp_[2];                                                         \
        if (bpf_skb_load_bytes(skb, (__u32)(off), tmp_, 2) < 0) return -1;    \
        (dst) = ((__u16)tmp_[0] << 8) | ((__u16)tmp_[1]);                     \
    } while (0)

static __always_inline int parse_sni(struct __sk_buff *skb, __u32 payload_off,
                                     char *out, __u8 *out_len)
{
    __u8  rec_type, hs_type;

    LD_U8(payload_off + 0, rec_type);
    if (rec_type != 0x16) return -1;

    LD_U8(payload_off + 5, hs_type);
    if (hs_type != 0x01) return -1;

    __u8 sid_len;
    LD_U8(payload_off + 5 + 4 + 2 + 32, sid_len);
    if (sid_len > MAX_SESSION_ID_LEN) return -1;

    __u32 off = payload_off + 5 + 4 + 2 + 32 + 1 + (__u32)sid_len;
    if (off > 2048) return -1;

    __u16 cs_len;
    LD_U16(off, cs_len);
    if (cs_len > MAX_CIPHER_LEN) return -1;
    off += 2u + (__u32)cs_len;
    if (off > 2048) return -1;

    __u8 cm_len;
    LD_U8(off, cm_len);
    if (cm_len > MAX_COMPR_LEN) return -1;
    off += 1u + (__u32)cm_len;
    if (off > 2048) return -1;

    __u16 ext_total;
    LD_U16(off, ext_total);
    if (ext_total > MAX_EXT_TOTAL_LEN) return -1;
    off += 2u;

    __u32 ext_remaining = ext_total;
    for (int i = 0; i < MAX_TLS_EXTS; i++) {
        if (ext_remaining < 4) return -1;
        __u16 ext_type, ext_len;
        LD_U16(off, ext_type);
        LD_U16(off + 2u, ext_len);
        if (ext_len > MAX_EXT_BODY_LEN) return -1;
        if ((__u32)ext_len + 4u > ext_remaining) return -1;

        if (ext_type == 0x0000) {
            if (ext_len < 5) return -1;
            __u32 sn_off = off + 4u;
            __u8 name_type;
            LD_U8(sn_off + 2u, name_type);
            if (name_type != 0x00) return -1;
            __u16 name_len;
            LD_U16(sn_off + 3u, name_len);
            if (name_len == 0 || name_len > MAX_NAME_LEN) return -1;
            __u32 name_off = sn_off + 5u;

            __u32 n = name_len;
            if (n > MAX_NAME_LEN) n = MAX_NAME_LEN;
            /* Load the entire (padded) name buffer in one helper call. */
            if (bpf_skb_load_bytes(skb, name_off, out, NAME_BUF_LEN) < 0) {
                /* If the packet has fewer than NAME_BUF_LEN bytes left,
                 * load only n bytes (n is bounded to MAX_NAME_LEN). */
                for (__u32 j = 0; j < NAME_BUF_LEN; j++) {
                    if (j >= n) break;
                    __u8 ch;
                    if (bpf_skb_load_bytes(skb, name_off + j, &ch, 1) < 0) return -1;
                    out[j & NAME_BUF_MASK] = (char)ch;
                }
            }
            /* Lowercase in place. */
            for (__u32 j = 0; j < NAME_BUF_LEN; j++) {
                if (j >= n) break;
                char c = out[j & NAME_BUF_MASK];
                if (c >= 'A' && c <= 'Z') c += 32;
                out[j & NAME_BUF_MASK] = c;
            }
            *out_len = (__u8)n;
            return 0;
        }
        off += 4u + (__u32)ext_len;
        ext_remaining -= 4u + (__u32)ext_len;
    }
    return -1;
}

#undef LD_U8
#undef LD_U16

static __always_inline int name_equal(const char *a, __u32 a_len,
                                      const char *b, __u32 b_len)
{
    if (a_len != b_len) return 0;
    if (a_len == 0 || a_len > MAX_NAME_LEN) return 0;
    for (__u32 i = 0; i < NAME_BUF_LEN; i++) {
        if (i >= a_len) break;
        __u32 idx = i & NAME_BUF_MASK;
        if (a[idx] != b[idx]) return 0;
    }
    return 1;
}

static __always_inline int suffix_match(const char *sni, __u32 sni_len,
                                        const char *suf, __u32 suf_len)
{
    if (suf_len == 0 || suf_len > MAX_NAME_LEN) return 0;
    if (sni_len < suf_len) return 0;
    if (sni_len > MAX_NAME_LEN) return 0;
    if (sni_len == suf_len) {
        return name_equal(sni, sni_len, suf, suf_len);
    }
    /* sni_len > suf_len: require '.' boundary just before the tail */
    __u32 boundary = (sni_len - suf_len - 1) & NAME_BUF_MASK;
    if (sni[boundary] != '.') return 0;
    __u32 off = sni_len - suf_len;
    for (__u32 i = 0; i < NAME_BUF_LEN; i++) {
        if (i >= suf_len) break;
        __u32 idx = (off + i) & NAME_BUF_MASK;
        __u32 sidx = i & NAME_BUF_MASK;
        if (sni[idx] != suf[sidx]) return 0;
    }
    return 1;
}

/* Callback context for bpf_loop. */
struct match_ctx_t {
    char     sni[NAME_BUF_LEN];
    __u32    sni_len;
    __u32    ifindex;
    __u8     kind;     /* 0 = exact, 1 = suffix */
    __u8     found;
};

static long match_cb(__u32 index, struct match_ctx_t *ctx)
{
    struct rule_key_t k = {};
    k.ifindex = ctx->ifindex;
    k.idx     = (__u8)index;

    struct rule_val_t *v;
    if (ctx->kind == 0) {
        v = bpf_map_lookup_elem(&policy_exact, &k);
        if (v && name_equal(ctx->sni, ctx->sni_len, v->name, v->len)) {
            ctx->found = 1;
            return 1;
        }
    } else {
        v = bpf_map_lookup_elem(&policy_suffix, &k);
        if (v && suffix_match(ctx->sni, ctx->sni_len, v->name, v->len)) {
            ctx->found = 1;
            return 1;
        }
    }
    return 0;
}

static __always_inline int match_policy(__u32 ifindex,
                                        const struct policy_meta_t *m,
                                        const char *sni, __u8 sni_len)
{
    struct match_ctx_t ctx = {};
    ctx.ifindex = ifindex;
    ctx.sni_len = sni_len;
    __u32 n = sni_len > NAME_BUF_LEN ? NAME_BUF_LEN : sni_len;
    for (__u32 i = 0; i < NAME_BUF_LEN; i++) {
        if (i >= n) break;
        ctx.sni[i & NAME_BUF_MASK] = sni[i & NAME_BUF_MASK];
    }

    ctx.kind  = 0;
    ctx.found = 0;
    bpf_loop(m->n_exact, match_cb, &ctx, 0);
    if (ctx.found) return 1;

    /* Suffix matching deferred. Tracked in TODO: implement either via
     * fnv1a-hashed dot-boundary tails (BPF) or via userspace DNS-proxy.
     * Currently suffix policies still parse and load but always miss.
     */
    return 0;
}

/* Insert a verdict into the connection-tracking map. Wrapped to keep the call
 * sites readable. */
static __always_inline void ct_put(const struct ct_key_t *ck, __u8 verdict)
{
    struct ct_val_t v = { .verdict = verdict,
                          .last_seen_ns = bpf_ktime_get_ns() };
    bpf_map_update_elem(&ct, ck, &v, BPF_ANY);
}

SEC("tc")
int blocky_egress(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;

    struct policy_meta_t *m = bpf_map_lookup_elem(&policy_meta, &ifindex);
    if (!m || m->mode == MODE_PASS) {
        return TC_ACT_OK;
    }

    /* Reload packet pointers AFTER any helper call: the verifier invalidates
     * pkt-typed registers across helpers. */
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    void *l3 = data + sizeof(struct ethhdr);
    if (l3 + sizeof(struct iphdr) > data_end) return TC_ACT_OK;
    struct iphdr *ip = l3;
    if (ip->ihl < 5) return TC_ACT_OK;
    __u32 ip_hlen = (__u32)ip->ihl * 4;
    void *l4 = l3 + ip_hlen;
    if (l4 > data_end) return TC_ACT_OK;

    __u32 sip = ip->saddr;
    __u32 dip = ip->daddr;
    __u8  proto = ip->protocol;
    __u16 sport = 0, dport = 0;
    __u32 tcp_hlen = 0;

    if (proto == IPPROTO_TCP) {
        if (l4 + sizeof(struct tcphdr) > data_end) return TC_ACT_OK;
        struct tcphdr *tcp = l4;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
        tcp_hlen = (__u32)tcp->doff * 4;
        if (tcp_hlen < 20 || tcp_hlen > 60) return TC_ACT_OK;
    } else if (proto == IPPROTO_UDP) {
        if (l4 + sizeof(struct udphdr) > data_end) return TC_ACT_OK;
        struct udphdr *u = l4;
        sport = bpf_ntohs(u->source);
        dport = bpf_ntohs(u->dest);
    }

    /* ct lookup short-circuits established flows without re-emitting. We skip
     * the cache for UDP/53 so every DNS query surfaces its QNAME — different
     * queries often reuse the same 5-tuple. */
    int is_dns_query = (proto == IPPROTO_UDP && dport == 53);
    struct ct_key_t ck = {
        .ifindex = ifindex, .sip = sip, .dip = dip,
        .sport = sport, .dport = dport, .proto = proto,
    };
    if (!is_dns_query) {
        struct ct_val_t *cv = bpf_map_lookup_elem(&ct, &ck);
        if (cv) {
            if (cv->verdict == VERDICT_ALLOW) return TC_ACT_OK;
            if (cv->verdict == VERDICT_DENY)  return TC_ACT_SHOT;
        }
    }

    /* Port gate. n_ports == 0 keeps the legacy hard-coded DNS/443 path
     * (backwards compatible with single-label deployments). In observe mode
     * every otherwise-blocked decision becomes an emit-and-allow so the
     * operator can see what the container is doing without breaking it. */
    if (m->n_ports > 0) {
        struct port_key_t pk = { .ifindex = ifindex, .port = dport };
        if (!bpf_map_lookup_elem(&policy_ports, &pk)) {
            if (m->observe) {
                emit(ifindex, sip, dip, sport, dport, proto,
                     VERDICT_ALLOW, REASON_PORT_ALLOWED, 0, 0);
                ct_put(&ck, VERDICT_ALLOW);
                return TC_ACT_OK;
            }
            emit(ifindex, sip, dip, sport, dport, proto,
                 VERDICT_DENY, REASON_PORT_BLOCKED, 0, 0);
            ct_put(&ck, VERDICT_DENY);
            return TC_ACT_SHOT;
        }
    } else {
        /* Legacy mode rejects anything that isn't DNS or TCP/443. The DNS
         * branches fall through to the per-protocol emit blocks below. */
        int is_dns = (dport == 53 &&
                      (proto == IPPROTO_UDP || proto == IPPROTO_TCP));
        int is_https = (proto == IPPROTO_TCP && dport == 443);
        if (!is_dns && !is_https) {
            if (m->observe) {
                emit(ifindex, sip, dip, sport, dport, proto,
                     VERDICT_ALLOW, REASON_PORT_ALLOWED, 0, 0);
                ct_put(&ck, VERDICT_ALLOW);
                return TC_ACT_OK;
            }
            emit(ifindex, sip, dip, sport, dport, proto,
                 VERDICT_DENY, REASON_NON_TLS_RESTRICTED, 0, 0);
            ct_put(&ck, VERDICT_DENY);
            return TC_ACT_SHOT;
        }
    }

    /* UDP/53: parse QNAME, emit dns-exempt, never ct (per-packet visibility). */
    if (is_dns_query) {
        __u32 udp_payload_off = (__u32)sizeof(struct ethhdr) + ip_hlen +
                                (__u32)sizeof(struct udphdr);
        char q_buf[NAME_BUF_LEN] = {0};
        __u8 q_len = 0;
        (void)parse_dns_qname(skb, udp_payload_off, q_buf, &q_len);
        emit(ifindex, sip, dip, sport, dport, proto,
             VERDICT_ALLOW, REASON_DNS_EXEMPT, q_buf, q_len);
        return TC_ACT_OK;
    }

    /* TCP/53: no QNAME parser yet, emit unnamed dns-exempt. */
    if (proto == IPPROTO_TCP && dport == 53) {
        emit(ifindex, sip, dip, sport, dport, proto,
             VERDICT_ALLOW, REASON_DNS_EXEMPT, 0, 0);
        ct_put(&ck, VERDICT_ALLOW);
        return TC_ACT_OK;
    }

    /* TCP/443 with a non-empty domain list ⇒ SNI matching applies. We also
     * parse SNI in observe-only mode so the dashboard sees which domains a
     * container is talking to even though every flow is allowed. */
    int sni_active = (proto == IPPROTO_TCP && dport == 443 &&
                      ((m->n_exact + m->n_suffix) > 0 || m->observe));
    if (sni_active) {
        __u32 payload_off = sizeof(struct ethhdr) + ip_hlen + tcp_hlen;
        /* SYN/ACK/FIN with no TLS payload: pass without ct so the next
         * (ClientHello) packet runs the full pipeline. */
        if (skb->len < payload_off + 5u) {
            return TC_ACT_OK;
        }
        char sni_buf[NAME_BUF_LEN] = {0};
        __u8 sni_len = 0;
        int rc = parse_sni(skb, payload_off, sni_buf, &sni_len);
        if (rc != 0 || sni_len == 0) {
            if (m->observe) {
                emit(ifindex, sip, dip, sport, dport, proto,
                     VERDICT_ALLOW, REASON_PORT_ALLOWED, 0, 0);
                ct_put(&ck, VERDICT_ALLOW);
                return TC_ACT_OK;
            }
            emit(ifindex, sip, dip, sport, dport, proto,
                 VERDICT_DENY, REASON_TLS_PARSE_FAILED, 0, 0);
            ct_put(&ck, VERDICT_DENY);
            return TC_ACT_SHOT;
        }
        if (match_policy(ifindex, m, sni_buf, sni_len)) {
            ct_put(&ck, VERDICT_ALLOW);
            emit(ifindex, sip, dip, sport, dport, proto,
                 VERDICT_ALLOW, REASON_SNI_ALLOWED, sni_buf, sni_len);
            return TC_ACT_OK;
        }
        if (m->observe) {
            ct_put(&ck, VERDICT_ALLOW);
            emit(ifindex, sip, dip, sport, dport, proto,
                 VERDICT_ALLOW, REASON_SNI_ALLOWED, sni_buf, sni_len);
            return TC_ACT_OK;
        }
        ct_put(&ck, VERDICT_DENY);
        emit(ifindex, sip, dip, sport, dport, proto,
             VERDICT_DENY, REASON_SNI_BLOCKED, sni_buf, sni_len);
        return TC_ACT_SHOT;
    }

    /* Port gate matched, no L7 inspection applies: emit one allow event per
     * new flow and let subsequent packets short-circuit via ct. */
    emit(ifindex, sip, dip, sport, dport, proto,
         VERDICT_ALLOW, REASON_PORT_ALLOWED, 0, 0);
    ct_put(&ck, VERDICT_ALLOW);
    return TC_ACT_OK;
}

/* blocky_response runs on the inverse TCX direction of the same veth — packets
 * heading TO the container. Its only job is to spot UDP/53 responses, extract
 * A-record {ip ↦ qname} pairs, and emit them so userspace can populate the
 * per-container IP→domain cache. It never drops or rewrites; always TC_ACT_OK. */
SEC("tc")
int blocky_response(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;

    /* Only attached containers get DNS-response parsing. Unmanaged containers
     * don't even reach this program (the manager only attaches when there's a
     * policy), but cheap to verify. */
    struct policy_meta_t *m = bpf_map_lookup_elem(&policy_meta, &ifindex);
    if (!m || m->mode == MODE_PASS) return TC_ACT_OK;

    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    void *l3 = data + sizeof(struct ethhdr);
    if (l3 + sizeof(struct iphdr) > data_end) return TC_ACT_OK;
    struct iphdr *ip = l3;
    if (ip->ihl < 5) return TC_ACT_OK;
    __u32 ip_hlen = (__u32)ip->ihl * 4;
    void *l4 = l3 + ip_hlen;
    if (l4 > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    if (l4 + sizeof(struct udphdr) > data_end) return TC_ACT_OK;
    struct udphdr *u = l4;
    __u16 sport = bpf_ntohs(u->source);
    if (sport != 53) return TC_ACT_OK;   /* not a DNS response */

    __u32 payload_off = (__u32)sizeof(struct ethhdr) + ip_hlen +
                       (__u32)sizeof(struct udphdr);
    __u32 skb_len = skb->len;
    if (skb_len <= payload_off) return TC_ACT_OK;
    __u32 avail = skb_len - payload_off;
    if (avail < DNS_HEADER_LEN + 4u) return TC_ACT_OK;
    __u32 to_load = avail < DNS_RESP_SCAN_LEN ? avail : DNS_RESP_SCAN_LEN;
    if (to_load > DNS_RESP_SCAN_LEN) to_load = DNS_RESP_SCAN_LEN; /* verifier */

    struct dns_resp_ctx_t rctx = {};
    if (bpf_skb_load_bytes(skb, payload_off, rctx.buf, to_load) < 0) {
        return TC_ACT_OK;
    }

    /* Bail unless it's a response with at least one question and one answer. */
    __u16 qdcount = ((__u16)rctx.buf[4] << 8) | (__u16)rctx.buf[5];
    __u16 ancount = ((__u16)rctx.buf[6] << 8) | (__u16)rctx.buf[7];
    if (qdcount == 0 || ancount == 0) return TC_ACT_OK;

    /* Walk the question's QNAME on the buffer copy to extract its text and
     * find where the answer section starts (QNAME terminator + 4 bytes
     * QTYPE/QCLASS). The answer-walker then reads from the skb directly. */
    rctx.pos = DNS_HEADER_LEN;
    bpf_loop(MAX_DNS_LABELS, resp_qname_cb, &rctx, 0);
    if (rctx.qname_written == 0) return TC_ACT_OK;
    if (rctx.pos > DNS_RESP_SCAN_LEN - 4u) return TC_ACT_OK;
    __u32 ans_off = payload_off + rctx.pos + 4u;   /* abs offset of 1st answer */

    /* Bound the answer count by both the wire-format counter and the local
     * iteration cap so the verifier sees a constant outer bound. */
    __u32 n = ancount < MAX_DNS_ANSWERS ? ancount : MAX_DNS_ANSWERS;
    if (n > MAX_DNS_ANSWERS) n = MAX_DNS_ANSWERS; /* verifier hint */

    struct dns_ans_ctx_t actx = {};
    actx.skb       = skb;
    actx.qname     = rctx.qname;
    actx.qname_len = (__u8)(rctx.qname_written > MAX_NAME_LEN ? MAX_NAME_LEN
                                                              : rctx.qname_written);
    actx.pos       = ans_off;
    actx.skb_len   = skb_len;
    actx.ifindex   = ifindex;
    bpf_loop(n, resp_answer_cb, &actx, 0);

    return TC_ACT_OK;
}
