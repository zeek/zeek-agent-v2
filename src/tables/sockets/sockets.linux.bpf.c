// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// TODO: - Expire map state on inactivity.
//
// Note: For unconnected UDP socket, we currently do not report new incoming
// flows. That's because there's no particular socket activuty to hook into
// other than the packets themselves. We would need to hok into `udp_recvmsg`
// and extract the addresses, and then maybe change our flow tracking as well
// to record 5-tuple instead of socket (or maybe not?).

#include "sockets.linux.event.h"

// clang-format off
#include <linux/bpf.h>
#include <linux/bpf_perf_event.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

#include <string.h>

#include <netinet/in.h>
#include <sys/socket.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL"; // don't change; must be a license known by kernel

// Ringer buffer for passing events to user land.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ring_buffer SEC(".maps");

struct bpfFlow {
    struct bpfSocketEvent event; // current event, filled out as much as possible
};

// Flow table tracking active sessions.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, const void*); // flow key
    __type(value, struct bpfFlow);
    __uint(max_entries, 1000);
} flow_table SEC(".maps");

static struct bpfFlow* startNewFlow(const void* key) {
    struct bpfFlow flow;
    bzero(&flow, sizeof(flow));
    flow.event.process.pid = (bpf_get_current_pid_tgid() >> 32);
    flow.event.process.uid = (bpf_get_current_uid_gid() & 0xffffffff);
    flow.event.process.gid = (bpf_get_current_uid_gid() >> 32);
    bpf_get_current_comm(flow.event.process.name, BPF_PROCESS_NAME_MAX);
    bpf_map_update_elem(&flow_table, &key, &flow, BPF_ANY);
    return bpf_map_lookup_elem(&flow_table, &key);
}

static void removeFlow(const void* key) { bpf_map_delete_elem(&flow_table, &key); }

static struct bpfFlow* lookupFlow(const void* key) { return bpf_map_lookup_elem(&flow_table, &key); }

// Map correlating kprove's enter/exit.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, const __u64);   // pid-tid
    __type(value, const void*); // arbitrary cookie to make available to exit handler
    __uint(max_entries, 1000);
} kprobe_trace_table SEC(".maps");

static void saveKprobeArgument(void* arg) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&kprobe_trace_table, &pid_tgid, &arg, BPF_ANY);
}

static void* restoreKprobeArgument() {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    void** arg = bpf_map_lookup_elem(&kprobe_trace_table, &pid_tgid);
    bpf_map_delete_elem(&kprobe_trace_table, &pid_tgid);
    return arg ? *arg : 0;
}

//// TCP flow tracking.

// From vmlinux.
//
// Accessed through CO-RE, so only declaring fields we need.
struct trace_event_raw_inet_sock_set_state {
    const void* skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    // ...
};

static void sendSocketEventTCP(struct bpfFlow* flow, struct trace_event_raw_inet_sock_set_state* args,
                               enum bpfSocketState state) {
    struct bpfSocketEvent* ev = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct bpfSocketEvent), 0);
    if ( ! ev )
        return; // no space (TODO: log)

    if ( flow )
        ev->process = flow->event.process;
    else
        bzero(&ev->process, sizeof(ev->process));

    ev->family = BPF_CORE_READ(args, family);
    ev->protocol = BPF_CORE_READ(args, protocol);
    ev->local_port = BPF_CORE_READ(args, sport);
    ev->remote_port = BPF_CORE_READ(args, dport);
    ev->state = state;

    switch ( ev->family ) {
        case AF_INET:
            bzero(&ev->local_addr, sizeof(ev->local_addr));
            bzero(&ev->remote_addr, sizeof(ev->remote_addr));
            BPF_CORE_READ_INTO(&ev->local_addr, args, saddr);
            BPF_CORE_READ_INTO(&ev->remote_addr, args, daddr);
            break;

        case AF_INET6:
            BPF_CORE_READ_INTO(&ev->local_addr, args, saddr_v6);
            BPF_CORE_READ_INTO(&ev->remote_addr, args, daddr_v6);
            break;

        default:
            bzero(&ev->local_addr, sizeof(ev->local_addr));
            bzero(&ev->remote_addr, sizeof(ev->remote_addr));
            break;
    }

    flow->event = *ev;
    bpf_ringbuf_submit(ev, 0);
}

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state* args) {
    int remove_flow = 0; // true to flush flow state at the end.

    const void* skaddr = BPF_CORE_READ(args, skaddr);
    const int oldstate = BPF_CORE_READ(args, oldstate);
    const int newstate = BPF_CORE_READ(args, newstate);

    // We only get a valid PID on:
    //
    //  BPF_TCP_CLOSE -> BPF_TCP_SYN_SENT
    //  BPF_TCP_CLOSE -> BPF_TCP_LISTEN
    //  BPF_TCP_LISTEN -> BPF_TCP_CLOSE
    //
    // So that's when we need to initialize then process information.
    //
    // This is according to
    // https://coroot.com/blog/building-a-service-map-using-ebp. Some of the
    // logic below is likewise inspired by that.
    if ( (oldstate == BPF_TCP_CLOSE && newstate == BPF_TCP_SYN_SENT) ||
         (oldstate == BPF_TCP_CLOSE && newstate == BPF_TCP_LISTEN) ) {
        // New session. If we have any currrent one with this key, expire that
        // (not sure if that can actually happen).
        struct bpfFlow* flow = lookupFlow(skaddr);
        if ( flow )
            sendSocketEventTCP(flow, args, BPF_SOCKET_STATE_EXPIRED);

        startNewFlow(skaddr);
    }

    enum bpfSocketState state = BPF_SOCKET_STATE_UNKNOWN;

    if ( oldstate == BPF_TCP_SYN_SENT && newstate == BPF_TCP_ESTABLISHED )
        state = BPF_SOCKET_STATE_ESTABLISHED;

    if ( oldstate == BPF_TCP_SYN_SENT && newstate == BPF_TCP_CLOSE )
        state = BPF_SOCKET_STATE_FAILED;

    if ( oldstate == BPF_TCP_ESTABLISHED && (newstate == BPF_TCP_FIN_WAIT1 || newstate == BPF_TCP_CLOSE_WAIT) ) {
        state = BPF_SOCKET_STATE_CLOSED;
        remove_flow = 1;
    }

    if ( oldstate == BPF_TCP_CLOSE && newstate == BPF_TCP_LISTEN )
        state = BPF_SOCKET_STATE_LISTEN;

    if ( oldstate == BPF_TCP_LISTEN && newstate == BPF_TCP_CLOSE ) {
        state = BPF_SOCKET_STATE_CLOSED;
        remove_flow = 1;
    }

    if ( state == BPF_SOCKET_STATE_UNKNOWN )
        // Not interested in reporting.
        return 0;

    struct bpfFlow* flow = lookupFlow(skaddr);
    if ( ! flow ) // can happen only if expired
        return 0;

    sendSocketEventTCP(flow, args, state);

    if ( remove_flow )
        removeFlow(skaddr);

    return 0;
}

//// UDP flow tracking.

typedef enum {
    SS_FREE = 0,
    SS_UNCONNECTED = 1,
    SS_CONNECTING = 2,
    SS_CONNECTED = 3,
    SS_DISCONNECTING = 4,
} socket_state;

// From vmlinux.
//
// Accessed through CO-RE, so only declaring fields we need.
struct sock_common {
    struct {
        __be32 skc_daddr;
        __be32 skc_rcv_saddr;
    };
    struct {
        __be16 skc_dport;
        __u16 skc_num;
    };
    short unsigned int skc_family;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
    // ...
};

// From vmlinux.
typedef struct {
    uid_t val;
} kuid_t;

// From vmlinux.
//
// Accessed through CO-RE, so only declaring fields we need.
struct sock {
    struct sock_common __sk_common; // NOLINT
    __u16 sk_protocol;
    kuid_t sk_uid;
    // ...
};

// From vmlinux.
//
// Accessed through CO-RE, so only declaring fields we need.
struct socket {
    socket_state state;
    short int type;
    struct sock* sk;
    // ...
};

static void sendSocketEventUDP(struct bpfFlow* flow, struct sock* sk, enum bpfSocketState state) {
    struct bpfSocketEvent* ev = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct bpfSocketEvent), 0);
    if ( ! ev )
        return; // no space (TODO: log)

    bzero(ev, sizeof(struct bpfSocketEvent));

    if ( sk ) {
        ev->process = flow->event.process;               // always use original process information
        ev->process.uid = BPF_CORE_READ(sk, sk_uid.val); // prefer the socket's state
        ev->protocol = BPF_CORE_READ(sk, sk_protocol);
        ev->family = BPF_CORE_READ(sk, __sk_common.skc_family);
        ev->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        ev->remote_port = ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        ev->state = state;

        switch ( ev->family ) {
            case AF_INET:
                bzero(&ev->local_addr, sizeof(ev->local_addr));
                bzero(&ev->remote_addr, sizeof(ev->remote_addr));
                BPF_CORE_READ_INTO(&ev->local_addr, sk, __sk_common.skc_rcv_saddr);
                BPF_CORE_READ_INTO(&ev->remote_addr, sk, __sk_common.skc_daddr);
                break;

            case AF_INET6:
                BPF_CORE_READ_INTO(&ev->local_addr, sk, __sk_common.skc_v6_rcv_saddr);
                BPF_CORE_READ_INTO(&ev->remote_addr, sk, __sk_common.skc_v6_daddr);
                break;

            default:
                bzero(&ev->local_addr, sizeof(ev->local_addr));
                bzero(&ev->remote_addr, sizeof(ev->remote_addr));
                break;
        }
    }
    else {
        *ev = flow->event; // reuse information from previous event
        ev->state = state;
    }

    flow->event = *ev;
    bpf_ringbuf_submit(ev, 0);
}


// It would be more efficient, and portable, to use fentry/fexit probes instead
// of kprobes (BPF tracing/trampoline, see
// https://github.com/torvalds/linux/commit/fec56f5890d93fc2ed74166c397dc186b1c25951).
// However, that isn't supported in ARM64 yet, per
// https://lore.kernel.org/lkml/20221108220651.24492-1-revest@chromium.org

static void datagram_connect(struct sock* sk, int rc) {
    struct bpfFlow* flow = lookupFlow(sk);
    if ( ! flow ) {
        flow = startNewFlow(sk);
        if ( ! flow )
            // Shouldn't happpen, but make the verifier happy.
            return;
    }

    if ( rc == 0 )
        sendSocketEventUDP(flow, sk, BPF_SOCKET_STATE_ESTABLISHED);
    else
        sendSocketEventUDP(flow, sk, BPF_SOCKET_STATE_FAILED);
}

SEC("kprobe/ip4_datagram_connect")
int BPF_KPROBE(ip4_datagram_connect, struct sock* sk, struct sockaddr* uaddr, int addr_len) {
    saveKprobeArgument(sk);
    return 0;
}

SEC("kprobe/ip6_datagram_connect")
int BPF_KPROBE(ip6_datagram_connect, struct sock* sk, struct sockaddr* uaddr, int addr_len) {
    saveKprobeArgument(sk);
    return 0;
}

SEC("kretprobe/ip4_datagram_connect")
int BPF_KRETPROBE(ip4_datagram_connect_return, int rc) {
    struct sock* sk = restoreKprobeArgument();
    if ( sk )
        datagram_connect(sk, rc);

    return 0;
}

SEC("kretprobe/ip6_datagram_connect")
int BPF_KRETPROBE(ip6_datagram_connect_return, int rc) {
    struct sock* sk = restoreKprobeArgument();
    if ( sk )
        datagram_connect(sk, rc);

    return 0;
}

SEC("kprobe/inet_bind")
int BPF_KPROBE(inet_bind, struct socket* socket, struct sockaddr* uaddr, int addr_len) {
    struct sockaddr_in* uaddr_in = (struct sockaddr_in*)uaddr;
    if ( BPF_CORE_READ(socket, type) == SOCK_DGRAM )
        saveKprobeArgument(socket);

    return 0;
}

SEC("kretprobe/inet_bind")
int BPF_KRETPROBE(inet_bind_return, int rc) {
    struct socket* socket = restoreKprobeArgument();
    if ( ! socket )
        return 0;

    struct sock* sk = BPF_CORE_READ(socket, sk); // NOLINT
    struct bpfFlow* flow = lookupFlow(sk);
    if ( ! flow ) {
        flow = startNewFlow(sk);
        if ( ! flow )
            // Shouldn't happpen, but make the verifier happy.
            return 0;
    }

    if ( rc == 0 ) {
        enum bpfSocketState state =
            (BPF_CORE_READ(socket, state) == SS_UNCONNECTED ? BPF_SOCKET_STATE_LISTEN : BPF_SOCKET_STATE_ESTABLISHED);
        sendSocketEventUDP(flow, sk, state);
    }
    else
        sendSocketEventUDP(flow, sk, BPF_SOCKET_STATE_FAILED);

    return 0;
}

SEC("kprobe/udp_destruct_sock")
int BPF_KPROBE(udp_destruct_sock, struct sock* sk, struct sockaddr* uaddr, int addr_len) {
    struct bpfFlow* flow = lookupFlow(sk);
    if ( flow ) {
        sendSocketEventUDP(flow, 0, BPF_SOCKET_STATE_CLOSED);
        removeFlow(sk);
    }

    return 0;
}
