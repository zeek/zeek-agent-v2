// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "platform.h"

#include "autogen/config.h"
#include "core/logger.h"
#include "fmt.h"
#include "helpers.h"
#include "testing.h"

#include <pathfind.hpp>

using namespace zeek::agent;

std::string platform::name() { return "Linux"; }

filesystem::path platform::configurationFile() {
    // TODO: These paths aren't necessarily right yet.
    filesystem::path exec = PathFind::FindExecutable();
    return exec / "../etc" / "zeek-agent.conf";
}

filesystem::path platform::dataDirectory() {
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

std::optional<std::string> platform::retrieveConfigurationOption(const std::string& path) {
    // Nothing to do.
    return {};
}
