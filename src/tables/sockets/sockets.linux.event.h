// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <linux/bpf.h>

#define BPF_PROCESS_NAME_MAX 128

struct bpfProcess {
    __u64 pid;
    char name[BPF_PROCESS_NAME_MAX];
    __u64 uid;
    __u64 gid;
};

enum bpfSocketState {
    BPF_SOCKET_STATE_UNKNOWN = 0,
    BPF_SOCKET_STATE_CLOSED,
    BPF_SOCKET_STATE_ESTABLISHED,
    BPF_SOCKET_STATE_EXPIRED,
    BPF_SOCKET_STATE_FAILED,
    BPF_SOCKET_STATE_LISTEN,
};

struct bpfSocketEvent {
    struct bpfProcess process; // valid only of process.pid > 0
    __u64 family;
    __u64 protocol;
    __u8 local_addr[16];
    __u64 local_port;
    __u8 remote_addr[16];
    __u64 remote_port;
    enum bpfSocketState state;
};
