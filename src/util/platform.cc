// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "platform.h"

#include "autogen/config.h"
#include "core/logger.h"
#include "fmt.h"
#include "helpers.h"

#include <pathfind.hpp>

using namespace zeek::agent;

#ifdef HAVE_POSIX

#include <glob.h>

bool platform::isTTY() { return ::isatty(1); }

std::vector<filesystem::path> platform::glob(const filesystem::path& pattern, size_t max) {
    std::vector<filesystem::path> result;

    ::glob_t paths;
    memset(&paths, 0, sizeof(paths));

    if ( auto rc = glob(pattern.c_str(), 0, nullptr, &paths); rc == 0 ) {
        for ( auto i = 0U; i < paths.gl_pathc && result.size() < max; i++ )
            result.emplace_back(paths.gl_pathv[i]);
    }

    globfree(&paths);
    return result;
}

#endif

#ifdef HAVE_DARWIN

std::string platform::name() { return "Darwin"; }

filesystem::path platform::configurationFile() {
    // TODO: These paths aren't necessarily right yet.
    if ( auto home = getenv("HOME") )
        return filesystem::path(*home) / ".config" / "zeek-agent";
    else {
        filesystem::path exec = PathFind::FindExecutable();
        return exec / "../etc" / "zeek-agent.conf";
    }
}

filesystem::path platform::dataDirectory() {
    // TODO: These paths aren't necessarily right yet.
    filesystem::path dir;

    if ( auto home = getenv("HOME") )
        dir = filesystem::path(*home) / ".cache" / "zeek-agent";
    else
        dir = "/var/run/org.zeek.agent";

    std::error_code ec;
    filesystem::create_directories(dir, ec);
    if ( ec )
        throw FatalError(format("cannot create path '{}'", dir.native()));

    return dir;
}

#endif

#ifdef HAVE_LINUX

std::string platform::name() { return "Linux"; }

filesystem::path platform::configurationFile() {
    // TODO: These paths aren't necessarily right yet.
    filesystem::path exec = PathFind::FindExecutable();
    return exec / "../etc" / "zeek-agent.conf";
}

filesystem::path platform::dataDirectory() {
    // TODO: These paths aren't necessarily right yet.
    filesystem::path dir;

    if ( auto home = getenv("HOME") )
        dir = filesystem::path(*home) / ".cache" / "zeek-agent";
    else
        dir = "/var/run/zeek-agent";

    std::error_code ec;
    filesystem::create_directories(dir, ec);
    if ( ec )
        throw FatalError(format("cannot create path '{}'", dir.native()));

    return dir;
}

#endif

#ifdef HAVE_WINDOWS

std::string platform::name() { return "Windows"; }

filesystem::path platform::configurationFile() {
    // TODO: These paths aren't necessarily right yet.
    filesystem::path exec = PathFind::FindExecutable();
    return exec / "../etc" / "zeek-agent.conf";
}

filesystem::path platform::dataDirectory() {
    // TODO: These paths aren't necessarily right yet.
    filesystem::path dir;

    if ( auto home = getenv("HOME") )
        dir = filesystem::path(*home) / ".cache" / "zeek-agent";
    else
        dir = "/var/run/zeek-agent";

    std::error_code ec;
    filesystem::create_directories(dir, ec);
    if ( ec )
        throw FatalError(format("cannot create path '{}'", dir.string()));

    return dir;
}

bool platform::isTTY() { return false; }

std::vector<filesystem::path> platform::glob(const filesystem::path& pattern, size_t max) {
    logger()->error("platform::glob is not implemented on Windows");
    return {};
}

#endif
