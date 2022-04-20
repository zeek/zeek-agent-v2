// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "platform.h"

#include <string>
#include <vector>

#include <glob.h>
#include <pathfind.hpp>

#include <ghc/filesystem.hpp>

using namespace zeek::agent;

bool platform::isTTY() { return ::isatty(1); }

bool platform::runningAsAdmin() { return geteuid() != 0; }

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

int platform::setenv(const char* name, const char* value, int overwrite) { return ::setenv(name, value, overwrite); }

std::optional<std::string> platform::getenv(const std::string& name) {
    if ( auto x = ::getenv(name.c_str()) )
        return {x};
    else
        return {};
}
