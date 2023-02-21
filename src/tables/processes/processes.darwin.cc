// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "processes.h"

#include "autogen/config.h"
#include "core/configuration.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "platform/darwin/endpoint-security.h"
#include "util/fmt.h"

#include <algorithm>

#include <libproc.h>

#include <bsm/libbsm.h>
#include <mach/mach_time.h>

namespace zeek::agent::table {

struct ProcessInfo {
    Value name;
    Value pid;
    Value ppid;
    Value uid;
    Value gid;
    Value ruid;
    Value rgid;
    Value priority;
    Value startup;
    Value vsize;
    Value rsize;
    Value utime;
    Value stime;
};

static std::optional<ProcessInfo> getProcessInfo(pid_t pid) {
    static struct mach_timebase_info timebase = {0, 0};

    if ( timebase.denom == 0 && timebase.numer == 0 ) {
        if ( mach_timebase_info(&timebase) != KERN_SUCCESS ) {
            logger()->warn("[processes] cannot get MACH timebase, times will be wrong");
            return {};
        }

        if ( timebase.denom == 0 && timebase.numer == 0 ) {
            logger()->warn("[processes] unexpected MACH timebase, times will be wrong");
            return {};
        }
    }

    errno = 0;
    struct proc_bsdinfo pi;
    auto n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &pi, sizeof(pi));

    if ( n < static_cast<int>(sizeof(pi)) || errno != 0 ) {
        if ( errno == ESRCH ) // ESRCH -> process is gone
            return std::nullopt;

        ZEEK_AGENT_DEBUG("processes", "could not get process information for PID {}", pid);
        return {};
    }

    ProcessInfo process;
    process.name = value::fromOptionalString(pi.pbi_name);
    process.pid = pi.pbi_pid;
    process.ppid = pi.pbi_ppid;
    process.uid = pi.pbi_uid;
    process.gid = pi.pbi_gid;
    process.ruid = pi.pbi_ruid;
    process.rgid = pi.pbi_rgid;
    process.priority = std::to_string(-pi.pbi_nice);
    process.startup = to_interval_from_secs(pi.pbi_start_tvsec);

    struct proc_taskinfo ti;
    if ( proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof(ti)) >= 0 ) { // this should succeed now
        process.vsize = static_cast<int64_t>(ti.pti_virtual_size);
        process.rsize = static_cast<int64_t>(ti.pti_resident_size);
        process.utime = to_interval_from_ns(ti.pti_total_user * timebase.numer / timebase.denom);
        process.stime = to_interval_from_ns(ti.pti_total_system * timebase.numer / timebase.denom);
    }

    return process;
}

class ProcessesDarwin : public ProcessesCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
    void addProcess(std::vector<std::vector<Value>>* rows, const struct proc_bsdinfo* p,
                    const struct proc_taskinfo* ti);

    Init init() override;
};

namespace {
database::RegisterTable<ProcessesDarwin> _1;
}

Table::Init ProcessesDarwin::init() { return Init::Available; }

std::vector<std::vector<Value>> ProcessesDarwin::snapshot(const std::vector<table::Argument>& args) {
    auto buffer_size = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    pid_t pids[buffer_size / sizeof(pid_t)];
    buffer_size = proc_listpids(PROC_ALL_PIDS, 0, pids, static_cast<int>(sizeof(pids)));
    if ( buffer_size <= 0 ) {
        logger()->warn("sockets: cannot get pids");
        return {};
    }

    std::vector<std::vector<Value>> rows;

    for ( size_t i = 0; i < buffer_size / sizeof(pid_t); i++ ) {
        if ( pids[i] <= 0 )
            continue;

        if ( auto p = getProcessInfo(pids[i]) )
            rows.push_back({p->name, p->pid, p->ppid, p->uid, p->gid, p->ruid, p->rgid, p->priority, p->startup,
                            p->vsize, p->rsize, p->utime, p->stime});
    }

    return rows;
}

void ProcessesDarwin::addProcess(std::vector<std::vector<Value>>* rows, const struct proc_bsdinfo* pi,
                                 const struct proc_taskinfo* ti) {}

class ProcessesEventsDarwin : public ProcessesEventsCommon {
public:
    Init init() override;
    void activate() override;
    void deactivate() override;

private:
    std::unique_ptr<platform::darwin::es::Subscriber> _subscriber;
};

namespace {
database::RegisterTable<ProcessesEventsDarwin> _2;
}

static void handle_event(ProcessesEventsDarwin* table, const es_message_t* msg) {
    es_process_t* process = nullptr;

    Value state;
    switch ( msg->event_type ) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            process = msg->event.exec.target;
            state = "started";
            break;

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            process = msg->process;
            state = "stopped";
            break;

        default: break; // shouldn't happen, but just ignore
    };

    if ( ! process )
        return;

    auto pid_ = audit_token_to_pid(process->audit_token);

    Value t = to_time(msg->time);
    Value name = process->executable->path.data;
    Value pid = static_cast<int64_t>(pid_);
    Value ppid = static_cast<int64_t>(process->ppid);
    Value uid = static_cast<int64_t>(audit_token_to_euid(process->audit_token));
    Value gid = static_cast<int64_t>(audit_token_to_egid(process->audit_token));
    Value ruid = static_cast<int64_t>(audit_token_to_ruid(process->audit_token));
    Value rgid = static_cast<int64_t>(audit_token_to_rgid(process->audit_token));
    Value startup = std::chrono::system_clock::now() - to_time(process->start_time);

    Value priority;
    Value vsize;
    Value rsize;
    Value utime;
    Value stime;

    if ( auto p = getProcessInfo(pid_) ) {
        // Looks like we can't get this anymore at EXIT events, so just fill in
        // what we can.
        priority = p->priority;
        rsize = p->rsize;
        vsize = p->vsize;
        utime = p->utime;
        stime = p->stime;
    }

    table->newEvent({t, name, pid, ppid, uid, gid, ruid, rgid, priority, startup, vsize, rsize, utime, stime, state});
}

Table::Init ProcessesEventsDarwin::init() {
    auto es = platform::darwin::endpointSecurity();
    return es->isAvailable() ? Init::Available : Init::PermanentlyUnavailable;
}

void ProcessesEventsDarwin::activate() {
    auto es = platform::darwin::endpointSecurity();

    if ( auto subscriber = es->subscribe("processes-events", {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT},
                                         [this](const auto& event) { handle_event(this, event); }) )
        _subscriber = std::move(*subscriber);
    else
        logger()->warn(frmt("could not initialize EndpointSecurity subscriber: {}", subscriber.error()));
}

void ProcessesEventsDarwin::deactivate() { _subscriber.reset(); }

} // namespace zeek::agent::table
