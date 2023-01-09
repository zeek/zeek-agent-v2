// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// TODO: - Expire map state on inactivity.
//       - This isn't capture all processes yet I believe (see TODO on empty names below; maybe more).
//       - Is our collection of executions times and memory usage correct for multiple threads? Do we need to aggregate?

#include "processes.linux.event.h"

// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf_perf_event.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

#include <string.h>

#include <sys/types.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL"; // don't change; must be a license known by kernel

// Ringer buffer for passing events to user land.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ring_buffer SEC(".maps");

// State maintained in map during process' lifetime.
struct bpfProcess {
    __s64 start_time;
    struct bpfProcessEvent event; // current event, filled out as much as possible
};

// Table tracking active processes.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, const void*); // process key
    __type(value, struct bpfProcess);
    __uint(max_entries, 1000);
} process_table SEC(".maps");

static struct bpfProcess* startNewProcess(const void* key, int seed_name) {
    struct bpfProcess process;
    bzero(&process, sizeof(process));

    process.start_time = (__s64)bpf_ktime_get_boot_ns();

    // Pre-fill event information that we got here. May be updated later.
    process.event.pid = (bpf_get_current_pid_tgid() >> 32);
    process.event.uid = (bpf_get_current_uid_gid() & 0xffffffff);
    process.event.gid = (bpf_get_current_uid_gid() >> 32);
    process.event.state = BPF_PROCESS_STATE_UNKNOWN;

    if ( seed_name ) {
        // Pre-seed with the current process name.
        char name[BPF_PROCESS_NAME_MAX];
        bpf_get_current_comm(process.event.name, BPF_PROCESS_NAME_MAX);
    }

    bpf_map_update_elem(&process_table, &key, &process, BPF_ANY);
    return bpf_map_lookup_elem(&process_table, &key);
}

static void removeProcess(const void* key) { bpf_map_delete_elem(&process_table, &key); }
static struct bpfProcess* lookupProcess(const void* key) { return bpf_map_lookup_elem(&process_table, &key); }

// From vmlinux.
typedef struct {
    uid_t val;
} kuid_t;

// From vmlinux.
typedef struct {
    gid_t val;
} kgid_t;

// From vmlinux.
struct cred {
    kuid_t uid;
    kgid_t gid;
    kuid_t suid;
    kgid_t sgid;
    kuid_t euid;
    kgid_t egid;
    kuid_t fsuid;
    kgid_t fsgid;
};

// From vmlinux.
typedef struct {
    __s64 counter;
} atomic64_t;

// From vmlinux.
typedef atomic64_t atomic_long_t;

// From vmlinux.
enum {
    MM_FILEPAGES,  /* Resident file mapping pages */
    MM_ANONPAGES,  /* Resident anonymous pages */
    MM_SWAPENTS,   /* Anonymous swap entries */
    MM_SHMEMPAGES, /* Resident shared memory pages */
    NR_MM_COUNTERS
};

// From vmlinux.
struct mm_rss_stat {
    atomic_long_t count[4];
};

// From vmlinux.
//
// Accessed through CO-RE, so only declaring fields we need.
struct mm_struct {
    struct {
        struct mm_rss_stat rss_stat;
        long unsigned int total_vm;
    };
    // ...
};

// From vmlinux.
//
// Accessed through CO-RE, so only declaring fields we need.
struct task_struct {
    pid_t pid;
    pid_t tgid;
    int prio;
    const struct cred* cred;
    const struct cred* real_cred;
    struct task_struct* real_parent;
    __u64 utime; // in nsecs since 4.11.0
    __u64 stime; // in nsecs since 4.11.0
    struct mm_struct* mm;
    // ...
};

static void sendProcessEvent(struct bpfProcess* process, struct task_struct* task, enum bpfProcessState state) {
    struct bpfProcessEvent* ev = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct bpfProcessEvent), 0);
    if ( ! ev )
        return; // no space (TODO: log)

    if ( process )
        memcpy(ev, &process->event, sizeof(*ev));
    else
        bzero(ev, sizeof(*ev));

    ev->uid = BPF_CORE_READ(task, cred, euid.val);
    ev->gid = BPF_CORE_READ(task, cred, egid.val);
    ev->life_time = (__s64)(process->start_time >= 0 ? (bpf_ktime_get_boot_ns() - process->start_time) : -1);
    ev->ruid = BPF_CORE_READ(task, cred, uid.val);
    ev->rgid = BPF_CORE_READ(task, cred, gid.val);
    ev->ppid = BPF_CORE_READ(task, real_parent, pid);
    ev->priority = BPF_CORE_READ(task, prio);

    ev->utime = BPF_CORE_READ(task, utime);
    ev->stime = BPF_CORE_READ(task, stime);

    // This follows:
    // https://elixir.bootlin.com/linux/v5.8/source/fs/proc/task_mmu.c#L82,
    // which is what /proc/<PID>/stat uses as well.
    __s64 file_pages = BPF_CORE_READ(task, mm, rss_stat.count[MM_FILEPAGES].counter);
    __s64 shmem_pages = BPF_CORE_READ(task, mm, rss_stat.count[MM_SHMEMPAGES].counter);
    __s64 anon_pages = BPF_CORE_READ(task, mm, rss_stat.count[MM_ANONPAGES].counter);
    ev->rsize = (file_pages + shmem_pages + anon_pages);
    ev->vsize = BPF_CORE_READ(task, mm, total_vm);

    ev->state = state;
    bpf_ringbuf_submit(ev, 0);
}

SEC("ksyscall/execve")
int BPF_KSYSCALL(execve, const char* filename, const char* const* argv, const char* const* envp) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

    char name[BPF_PROCESS_NAME_MAX];
    long name_len = bpf_probe_read_user_str(name, sizeof(name), filename);

    // TODO: An empty name means reading from an FD I believe. Not sure how to
    // handle that, ignoring for now.
    if ( name_len <= 0 )
        return 0;

    struct bpfProcess* process = lookupProcess(task);
    if ( ! process )
        process = startNewProcess(task, 0);

    if ( ! process )
        return 0; // make verifier happy

    if ( name_len > 1 )
        bpf_probe_read_user_str(process->event.name, sizeof(process->event.name), filename);

    return 0;
}

SEC("kretsyscall/execve")
int BPF_KSYSCALL(execve_ret, int rc) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

    struct bpfProcess* process = lookupProcess(task);
    if ( process )
        sendProcessEvent(process, task, BPF_PROCESS_STATE_STARTED);

    return 0;
}


SEC("kprobe/do_exit")
int BPF_KPROBE(do_exit, long code) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

    struct bpfProcess* process = lookupProcess(task);
    if ( ! process ) {
        // Missed the beginning, create a temporary process with whatever information we have.
        process = startNewProcess(task, 1);
        if ( ! process )
            return 0; // make verifier happy

        process->start_time = -1;
    }

    sendProcessEvent(process, task, BPF_PROCESS_STATE_STOPPED);
    removeProcess(task);

    return 0;
}
