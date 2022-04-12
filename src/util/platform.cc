// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "platform.h"

#include "autogen/config.h"
#include "core/logger.h"
#include "fmt.h"
#include "helpers.h"
#include "testing.h"

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

int platform::setenv(const char* name, const char* value, int overwrite) { return ::setenv(name, value, overwrite); }

std::optional<std::string> platform::getenv(const std::string& name) {
    if ( auto x = ::getenv(name.c_str()) )
        return {x};
    else
        return {};
}

bool platform::runningAsAdmin() { return geteuid() != 0; }

#endif

#ifdef HAVE_DARWIN

std::string platform::name() { return "Darwin"; }

filesystem::path platform::configurationFile() {
    // TODO: These paths aren't necessarily right yet.
    if ( auto home = platform::getenv("HOME") )
        return filesystem::path(*home) / ".config" / "zeek-agent";
    else {
        filesystem::path exec = PathFind::FindExecutable();
        return exec / "../etc" / "zeek-agent.conf";
    }
}

filesystem::path platform::dataDirectory() {
    // TODO: These paths aren't necessarily right yet.
    filesystem::path dir;

    if ( auto home = platform::getenv("HOME") )
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

    if ( auto home = platform::getenv("HOME") )
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

#include <memory>

#include <ztd/out_ptr/out_ptr.hpp>
using namespace ztd::out_ptr;

std::string platform::name() { return "Windows"; }

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
        throw FatalError(format("cannot create path '{}'", dir.string()));

    return dir;
}

bool platform::isTTY() { return true; }

std::vector<filesystem::path> platform::glob(const filesystem::path& pattern, size_t max) {
    logger()->error("platform::glob is not implemented on Windows");
    return {};
}

int platform::setenv(const char* name, const char* value, int overwrite) {
    if ( overwrite == 0 ) {
        // It doesn't matter what the length is set to here. The array is just being used
        // to check for existence.
        char existing[10];
        int ret = GetEnvironmentVariableA(name, existing, 10);

        // Anything non-zero means that a length of the existing value was returned and
        // that the variable exists.
        if ( ret != 0 )
            return 0;
    }

    if ( ! SetEnvironmentVariableA(name, value) )
        return -1;
    return 0;
}

extern std::optional<std::string> platform::getenv(const std::string& name) {
    constexpr DWORD max_buffer_size = 32768; // From GetEnvironmentVariable's documentation
    char* buf = NULL;
    char* tmp = NULL;
    DWORD ret = 1;
    DWORD requested_size = 0;

    while ( true ) {
        tmp = reinterpret_cast<char*>(realloc(NULL, ret));
        if ( ! tmp ) {
            free(buf);
            return std::nullopt;
        }

        buf = tmp;
        requested_size = ret;

        ret = GetEnvironmentVariableA(name.c_str(), buf, requested_size);
        if ( ret == 0 ) {
            free(buf);
            return std::nullopt;
        }

        // If ret is less than the size, then we got a good value and can just return.
        // Otherwise we need to expand the buffer and try again.
        if ( ret < requested_size ) {
            std::string value{buf};
            free(buf);
            return value;
        }
    }
}

struct SIDFreer {
    void operator()(PSID sid) { FreeSid(sid); }
};
using SIDPtr = std::unique_ptr<std::remove_pointer<PSID>::type, SIDFreer>;

bool platform::runningAsAdmin() {
    // Adapted from
    // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
    BOOL is_member;
    SIDPtr administrator_group;
    SID_IDENTIFIER_AUTHORITY auth_nt = SECURITY_NT_AUTHORITY;
    is_member = AllocateAndInitializeSid(&auth_nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0,
                                         0, 0, out_ptr<PSID>(administrator_group));

    if ( ! is_member )
        return false;

    if ( ! CheckTokenMembership(nullptr, administrator_group.get(), &is_member) )
        is_member = false;

    return is_member;
}

#endif

TEST_SUITE("Platform") {
    TEST_CASE("getenv") {
        CHECK_EQ(platform::getenv(""), std::nullopt);

#ifndef HAVE_WINDOWS
        const auto home = platform::getenv("HOME");
#else
        const auto home = platform::getenv("HOMEPATH");
#endif
        REQUIRE(home);
        CHECK_FALSE(home->empty());

        CHECK_EQ(platform::getenv("TEST_ENV_DOES_NOT_EXIST"), std::nullopt);
    }
}
