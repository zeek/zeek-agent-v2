// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "platform/platform.h"

#include "autogen/config.h"
#include "core/logger.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/testing.h"

#include <pathfind.hpp>

using namespace zeek::agent;

std::string platform::name() { return "Linux"; }

void platform::init(Configuration* cfg) {}

void platform::done() {}

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
    // TODO: These paths aren't necessarily right yet.
    filesystem::path exec = PathFind::FindExecutable();
    return exec / "../etc" / "zeek-agent.conf";
}

std::optional<filesystem::path> platform::dataDirectory() {
    // TODO: These paths aren't necessarily right yet.
    filesystem::path dir;

    if ( auto home = platform::getenv("HOME") )
        dir = filesystem::path(*home) / ".cache" / "zeek-agent";
    else
        dir = "/var/run/zeek-agent";

    std::error_code ec;
    filesystem::create_directories(dir, ec);
    if ( ec )
        throw FatalError(frmt("cannot create path '{}'", dir.native()));

    return dir;
}

void platform::initializeOptions(Options* options) {
    // Nothing to do.
}
