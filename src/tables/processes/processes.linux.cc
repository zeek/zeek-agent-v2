// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "processes.h"

#include "autogen/config.h"
#include "core/configuration.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "util/fmt.h"

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
database::RegisterTable<ProcessesLinux> _;
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
                Value priority = static_cast<int64_t>(stat.priority);
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
} // namespace zeek::agent::table
