// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "processes.h"

#include "autogen/config.h"
#include "core/configuration.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "processes.linux.event.h"
#include "util/fmt.h"

// clang-format off
#include "platform/linux/bpf.h"
#include "util/helpers.h"
// TODO
#define _Bool bool
#include "autogen/bpf/processes.skel.h"
#undef _Bool
// clang-format on

#include <pfs/procfs.hpp>

namespace zeek::agent::table {

class ProcessesLinux : public ProcessesCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
    bool init() override;

private:
    uint64_t _clock_tick;
};

namespace {
database::RegisterTable<ProcessesLinux> _1;
}

bool ProcessesLinux::init() {
    _clock_tick = sysconf(_SC_CLK_TCK);
    return true;
}

std::vector<std::vector<Value>> ProcessesLinux::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    try {
        pfs::procfs pfs;

        for ( const auto& p : pfs.get_processes() ) {
            try {
                auto stat = p.get_stat();
                auto status = p.get_status();
                Value name = p.get_comm();
                Value pid = static_cast<int64_t>(p.id());
                Value ppid = static_cast<int64_t>(stat.ppid);
                Value uid = static_cast<int64_t>(status.uid.effective);
                Value gid = static_cast<int64_t>(status.gid.effective);
                Value ruid = static_cast<int64_t>(status.uid.real);
                Value rgid = static_cast<int64_t>(status.gid.real);
                Value priority = std::to_string(stat.priority);
                Value startup = {};
                Value vsize = static_cast<int64_t>(stat.vsize);
                Value rsize = static_cast<int64_t>(stat.rss * getpagesize());
                Value utime = to_interval_from_secs(stat.utime / _clock_tick);
                Value stime = to_interval_from_secs(stat.stime / _clock_tick);

                rows.push_back({name, pid, ppid, uid, gid, ruid, rgid, priority, startup, vsize, rsize, utime, stime});
            } catch ( std::system_error& ) {
                // ignore, most likely a permission problem
            } catch ( std::runtime_error& ) {
                // ignore, most likely a permission problem
            }
        }

    } catch ( std::system_error& ) {
        logger()->warn("cannot read /proc filesystem (system error)");
    } catch ( std::runtime_error& ) {
        logger()->warn("cannot read /proc filesystem (runtime error)");
    }

    return rows;
}

class ProcessesEventsLinux : public ProcessesEventsCommon {
public:
    bool init() override;
    void activate() override;
    void deactivate() override;
};

namespace {
database::RegisterTable<ProcessesEventsLinux> _2;
}

template<typename T, typename S>
Value to_val(const S& i) {
    return i ? Value(static_cast<T>(i)) : Value();
}


static int handle_event(void* ctx, void* data, size_t data_sz) {
    auto table = reinterpret_cast<ProcessesEventsLinux*>(ctx);
    auto ev = reinterpret_cast<const bpfProcessEvent*>(data);

    auto name = (ev->name[0] ? Value(ev->name) : Value());
    auto pid = Value(static_cast<int64_t>(ev->pid));
    auto ppid = Value(static_cast<int64_t>(ev->ppid));
    auto uid = Value(static_cast<int64_t>(ev->uid));
    auto gid = Value(static_cast<int64_t>(ev->gid));
    auto ruid = Value(static_cast<int64_t>(ev->ruid));
    auto rgid = Value(static_cast<int64_t>(ev->rgid));
    auto priority = Value(std::to_string(ev->priority - 100)); // TODO: That's MAX_RT_PRIO, require kernel header?
    auto startup = (ev->life_time >= 0 ? Value(to_interval_from_ns(ev->life_time)) : Value());
    auto vsize = Value(static_cast<int64_t>(ev->vsize));
    auto rsize = Value(static_cast<int64_t>(ev->rsize * getpagesize()));
    auto utime = Value(to_interval_from_ns(ev->utime));
    auto stime = Value(to_interval_from_ns(ev->stime));

    Value state;
    switch ( ev->state ) {
        case BPF_PROCESS_STATE_STARTED: state = "started"; break;
        case BPF_PROCESS_STATE_STOPPED: state = "stopped"; break;
        case BPF_PROCESS_STATE_UNKNOWN: break; // leave unset
    }

    table->newEvent({table->systemTime(), name, pid, ppid, uid, gid, ruid, rgid, priority, startup, vsize, rsize, utime,
                     stime, state});

    return 1;
}

bool ProcessesEventsLinux::init() {
    auto bpf = platform::linux::bpf();
    if ( ! bpf->isAvailable() )
        return false;

    auto skel = platform::linux::BPF::Skeleton{.name = "Processes",
                                               .open = reinterpret_cast<void*>(processes__open),
                                               .load = reinterpret_cast<void*>(processes__load),
                                               .attach = reinterpret_cast<void*>(processes__attach),
                                               .detach = reinterpret_cast<void*>(processes__detach),
                                               .destroy = reinterpret_cast<void*>(processes__destroy),
                                               .event_callback = handle_event,
                                               .event_context = this};

    auto our_bpf = bpf->load<processes>(std::move(skel));
    if ( ! our_bpf ) {
        logger()->warn(frmt("could not load BPF program: {}", our_bpf.error()));
        return false;
    }

    if ( auto rc = bpf->init("Processes", (*our_bpf)->maps.ring_buffer); ! rc ) {
        logger()->warn(frmt("could not initialize BPF program: {}", our_bpf.error()));
        return false;
    }

    return true;
}

void ProcessesEventsLinux::activate() {
    if ( auto rc = platform::linux::bpf()->attach("Processes"); ! rc )
        logger()->error(frmt("could not attach BPF program: {}", rc.error()));
}

void ProcessesEventsLinux::deactivate() {
    if ( auto rc = platform::linux::bpf()->detach("Processes"); ! rc )
        logger()->error(frmt("could not detach BPF program: {}", rc.error()));
}


} // namespace zeek::agent::table
