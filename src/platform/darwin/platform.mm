// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#include "platform/platform.h"

#include "autogen/config.h"
#include "core/logger.h"
#include "endpoint-security.h"
#include "xpc.h"

#include <libproc.h>

#include <mach/mach_time.h>

using namespace zeek::agent;
using namespace zeek::agent::platform::darwin;

static struct mach_timebase_info MachTimeBase = {0, 0};

std::string platform::name() { return "Darwin"; }

bool platform::isTTY() { return ::isatty(1); }

bool platform::runningAsAdmin() { return geteuid() == 0; }

std::optional<std::string> platform::getenv(const std::string& name) {
    if ( auto x = ::getenv(name.c_str()) )
        return {x};
    else
        return {};
}

Result<Nothing> platform::setenv(const char* name, const char* value, int overwrite) {
    if ( ::setenv(name, value, overwrite) == 0 )
        return Nothing();
    else
        return result::Error(strerror(errno));
}

std::optional<filesystem::path> platform::configurationFile() {
    if ( auto dir = getApplicationSupport() )
        return *dir / "zeek-agent.cfg";
    else
        return {};
}

std::optional<filesystem::path> platform::dataDirectory() { return getApplicationSupport(); }

std::optional<filesystem::path> platform::darwin::getApplicationSupport() {
    auto domain = platform::runningAsAdmin() ? NSLocalDomainMask : NSUserDomainMask;
    auto paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, domain, YES);
    auto dir = [paths firstObject];
    return filesystem::path([dir UTF8String]) / "ZeekAgent";
}

void platform::init(Configuration* cfg) {
    if ( MachTimeBase.denom == 0 && MachTimeBase.numer == 0 ) {
        if ( mach_timebase_info(&MachTimeBase) != KERN_SUCCESS )
            logger()->warn("[processes] cannot get MACH timebase, times will be wrong");

        if ( MachTimeBase.denom == 0 && MachTimeBase.numer == 0 )
            logger()->warn("[processes] unexpected MACH time base, times will be wrong");
    }

    platform::darwin::endpointSecurity();      // this initializes ES
    [[IPC sharedObject] setConfiguration:cfg]; // create the shared IPC object
    [[IPC sharedObject] updateOptions];        // read options from defaults and update the configuration
}

void platform::done() {}

void platform::initializeOptions(Options* options) {
    if ( auto service = platform::getenv("XPC_SERVICE_NAME"); service && *service != "0" )
        // Running as an installed system extension, log to oslog by default.
        options->log_type = options::LogType::System;
}

Result<std::vector<pid_t>> platform::darwin::getProcesses() {
    auto num_pids = proc_listallpids(nullptr, 0);
    pid_t pids[num_pids];
    num_pids = proc_listallpids(pids, static_cast<int>(sizeof(pids)));
    if ( num_pids > 0 )
        return std::vector<pid_t>(pids, pids + num_pids);
    else
        return result::Error("cannot get list if process IDs");
}

Result<ProcessInfo> platform::darwin::getProcessInfo(pid_t pid) {
    ProcessInfo process;

    // Get what we can from SHORTBSDINFO, this doesn't need root.
    errno = 0;
    struct proc_bsdshortinfo si;
    if ( auto n = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &si, sizeof(si)); n == sizeof(si) ) {
        process.pid = si.pbsi_pid;
        process.ppid = si.pbsi_ppid;
        process.uid = si.pbsi_uid;
        process.gid = si.pbsi_gid;
        process.ruid = si.pbsi_ruid;
        process.rgid = si.pbsi_rgid;
    }
    else {
        if ( errno == ESRCH )
            return result::Error("process is gone");
        else
            return result::Error("retrieving information failed");
    }

    // Try to get remainder from BSDINFO (needs root).
    errno = 0;
    struct proc_bsdinfo pi;
    if ( auto n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &pi, sizeof(pi)); n == sizeof(pi) ) {
        if ( pi.pbi_name[0] ) // from libproc.c
            process.name = value::fromOptionalString(pi.pbi_name);
        else
            process.name = value::fromOptionalString(pi.pbi_comm);

        process.priority = std::to_string(-pi.pbi_nice);
        process.startup = to_interval_from_secs(pi.pbi_start_tvsec);
    }
    else {
        /* ignore errors */
    }

    errno = 0;
    struct proc_taskinfo ti;
    if ( auto n = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof(ti)); n == sizeof(ti) ) {
        process.vsize = static_cast<int64_t>(ti.pti_virtual_size);
        process.rsize = static_cast<int64_t>(ti.pti_resident_size);
        process.utime = to_interval_from_ns(ti.pti_total_user * MachTimeBase.numer / MachTimeBase.denom);
        process.stime = to_interval_from_ns(ti.pti_total_system * MachTimeBase.numer / MachTimeBase.denom);
    }
    else {
        /* ignore errors */
    }

    return process;
}
