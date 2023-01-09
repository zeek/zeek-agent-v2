// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <linux/bpf.h>

#define BPF_PROCESS_NAME_MAX 128
#define BPF_PROCESS_PRIORITY_MAX 16

enum bpfProcessState { BPF_PROCESS_STATE_UNKNOWN = 0, BPF_PROCESS_STATE_STARTED, BPF_PROCESS_STATE_STOPPED };

struct bpfProcessEvent {
    char name[BPF_PROCESS_NAME_MAX];
    __u64 pid;
    __u64 ppid;
    __u64 uid;
    __u64 gid;
    __u64 ruid;
    __u64 rgid;
    __s64 life_time; // -1 for unknown
    int priority;    // + MAX_RT_PRIO
    __u64 vsize;     // bytes
    __u64 rsize;     // pages
    __u64 utime;     // nsecs
    __u64 stime;     // nsecs
    enum bpfProcessState state;
};
