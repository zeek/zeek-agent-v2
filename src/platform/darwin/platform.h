// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/table.h"
#include "util/result.h"

#include <filesystem>
#include <optional>
#include <vector>

#include <sys/_types/_pid_t.h>
#include <util/filesystem.h>

namespace zeek::agent {
class Scheduler;
}

namespace zeek::agent::platform::darwin {

/**
 * Hands the IPC layer a reference to the running scheduler so that
 * remotely-requested shutdowns can be performed gracefully (instead of
 * calling `::exit()` from an XPC dispatch thread, which races with
 * static-destructor cleanup).
 */
extern void setScheduler(zeek::agent::Scheduler* scheduler);

/**
 * Returns the path to the `App[lication Support` directory appropiate for the
 * user running the agent (which might be the system-wide one for root).
 */
extern std::optional<std::filesystem::path> getApplicationSupport();

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

/**
 * Retrieves a list of all currently running processes
 *
 * @return a list of the PIDs of all processes, or an error if the list cannot
 * be obtained
 */
Result<std::vector<pid_t>> getProcesses();

/**
 * Given a process ID, returns information about the process.
 *
 * @param pid the process ID to retrieve information for @return information
 * about the process, or an error if the information cannot be obtained; even
 * if successful, the struct may have been filled only partially
 */
Result<ProcessInfo> getProcessInfo(pid_t pid);

} // namespace zeek::agent::platform::darwin
