// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "platform/platform.h"

#include "autogen/config.h"
#include "core/logger.h"
#include "endpoint-security.h"
#include "xpc.h"

using namespace zeek::agent;
using namespace zeek::agent::platform::darwin;

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
