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
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override;
};

namespace {
database::RegisterTable<ProcessesLinux> _;
}

std::vector<std::vector<Value>> ProcessesLinux::snapshot(const std::vector<table::Where>& wheres) {
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
                Value startup = {}; // static_cast<int64_t>(pi->pbi_start_tvsec);
                Value vsize = static_cast<int64_t>(stat.vsize);
                Value rsize = static_cast<int64_t>(stat.rss * getpagesize());
                Value utime = static_cast<int64_t>(stat.utime);
                Value stime = static_cast<int64_t>(stat.stime);

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
