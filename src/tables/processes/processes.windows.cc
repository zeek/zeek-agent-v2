// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#include "processes.h"

#include "core/configuration.h"
#include "core/database.h"
#include "core/table.h"
#include "platform/platform.h"
#include "util/fmt.h"

#include <Psapi.h>
#include <TlHelp32.h>

using namespace zeek::agent::platform::windows;

namespace zeek::agent::table {

class ProcessesWindows : public ProcessesCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

namespace {
database::RegisterTable<ProcessesWindows> _;
}

static Interval filetime_to_interval(FILETIME t) {
    LARGE_INTEGER lt{.LowPart = t.dwLowDateTime, .HighPart = static_cast<LONG>(t.dwHighDateTime)};

    // Times like these are in 100ns intervals. Multiply by 100 to get nanosecond intervals, which we can
    // then convert to an interval object.
    auto tmp = lt.QuadPart * 100;

    return to_interval_from_ns(static_cast<int64_t>(tmp));
}

static std::string priority_string(DWORD value) {
    switch ( value ) {
        case ABOVE_NORMAL_PRIORITY_CLASS: return "above_normal";
        case BELOW_NORMAL_PRIORITY_CLASS: return "below_normal";
        case HIGH_PRIORITY_CLASS: return "high";
        case IDLE_PRIORITY_CLASS: return "idle";
        case NORMAL_PRIORITY_CLASS: return "normal";
        case REALTIME_PRIORITY_CLASS: return "realtime";
        default: return "unknown";
    }
}

std::vector<std::vector<Value>> ProcessesWindows::snapshot(const std::vector<table::Argument>& args) {
    HandlePtr snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if ( snapshot.get() == INVALID_HANDLE_VALUE )
        return {};

    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    if ( ! Process32First(snapshot.get(), &entry) )
        return {};

    std::vector<std::vector<Value>> rows;
    do {
        HandlePtr proc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID));

        CHAR proc_name[MAX_PATH];
        HRESULT res = GetModuleFileNameExA(proc.get(), NULL, proc_name, MAX_PATH);
        if ( FAILED(res) )
            continue;

        PROCESS_MEMORY_COUNTERS_EX memory{};
        if ( ! GetProcessMemoryInfo(proc.get(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory), sizeof(memory)) )
            continue;

        DWORD prio = GetPriorityClass(proc.get());
        if ( prio == 0 )
            continue;

        FILETIME creation_time, exit_time, kernel_time, user_time;
        if ( ! GetProcessTimes(proc.get(), &creation_time, &exit_time, &kernel_time, &user_time) )
            continue;

        Value name = proc_name;
        Value pid = static_cast<int64_t>(entry.th32ProcessID);
        Value priority = priority_string(prio);
        Value utime = filetime_to_interval(user_time);
        Value stime = filetime_to_interval(kernel_time);
        Value vsize = static_cast<int64_t>(memory.PrivateUsage); // Virtual size
        Value rsize = static_cast<int64_t>(memory.WorkingSetSize);

        // On Windows, it's possible for a parent process to spawn some children and then exit while
        // leaving the children running. In these cases, th32ParentProcessID will point at a PID that
        // that doesn't actually have a process running for it. Since that's possible, we just leave
        // that field empty.
        Value ppid{};

        // These fields are unknown for Windows. It's possible to get an SID matching a user
        // for a process ID but it's a bit complicated and might not be extremely useful here.
        Value uid{};
        Value gid{};
        Value ruid{};
        Value rgid{};
        Value startup{};

        rows.push_back({name, pid, ppid, uid, gid, ruid, rgid, priority, startup, vsize, rsize, utime, stime});

    } while ( Process32Next(snapshot.get(), &entry) );

    return rows;
}

} // namespace zeek::agent::table
