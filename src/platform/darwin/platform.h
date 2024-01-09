// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/table.h"

#include <optional>
#include <vector>

#include <util/filesystem.h>

namespace zeek::agent::platform::darwin {

/**
 * Returns the path to the `App[lication Support` directory appropiate for the
 * user running the agent (which might be the system-wide one for root).
 */
extern std::optional<filesystem::path> getApplicationSupport();

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
