// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "processes.h"

#include "autogen/config.h"
#include "core/configuration.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "platform/darwin/endpoint-security.h"
#include "platform/darwin/platform.h"
#include "util/fmt.h"

#include <algorithm>

#include <bsm/libbsm.h>

namespace zeek::agent::table {

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
    auto pids = platform::darwin::getProcesses();
    if ( ! pids ) {
        logger()->debug("could not get process list: {}", pids.error());
        return {};
    }

    std::vector<std::vector<Value>> rows;

    for ( auto pid : *pids ) {
        if ( pid <= 0 )
            continue;

        if ( auto p = platform::darwin::getProcessInfo(pid) )
            rows.push_back({p->name, p->pid, p->ppid, p->uid, p->gid, p->ruid, p->rgid, p->priority, p->startup,
                            p->vsize, p->rsize, p->utime, p->stime});
        else
            logger()->debug("could not get process info for PID {}: {}", pid, p.error());
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

    const Value t = to_time(msg->time);
    const Value name = process->executable->path.data;
    const Value pid = static_cast<int64_t>(pid_);
    const Value ppid = static_cast<int64_t>(process->ppid);
    const Value uid = static_cast<int64_t>(audit_token_to_euid(process->audit_token));
    const Value gid = static_cast<int64_t>(audit_token_to_egid(process->audit_token));
    const Value ruid = static_cast<int64_t>(audit_token_to_ruid(process->audit_token));
    const Value rgid = static_cast<int64_t>(audit_token_to_rgid(process->audit_token));
    const Value startup = std::chrono::system_clock::now() - to_time(process->start_time);

    Value priority;
    Value vsize;
    Value rsize;
    Value utime;
    Value stime;

    if ( auto p = platform::darwin::getProcessInfo(pid_) ) {
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
