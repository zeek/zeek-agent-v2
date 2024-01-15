// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#include "zeek_agent.h"

#include "autogen/config.h"
#include "core/database.h"
#include "platform/platform.h"
#include "util/helpers.h"

#include <chrono>

#include <ifaddrs.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/utsname.h>

#ifdef HAVE_BROKER
#include <broker/version.hh>
#endif

using namespace zeek::agent;
using namespace zeek::agent::table;

namespace {

class ZeekAgentLinux : public ZeekAgent {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

database::RegisterTable<ZeekAgentLinux> _;

Value addresses() {
    // Get default interface, per https://stackoverflow.com/a/17940988.
    std::ifstream route("/proc/net/route");
    if ( ! route )
        return {};

    std::string interface;
    std::string line;
    while ( std::getline(route, line) ) {
        auto m = split(line);
        if ( m[1] == "00000000" )
            interface = m[0];
    }

    if ( interface.empty() )
        return {};

    // The following follows 'getifaddrs(3)'.
    struct ifaddrs* ifaddr;
    if ( getifaddrs(&ifaddr) < 0 )
        return {};

    Set addrs(value::Type::Address);

    for ( auto ifa = ifaddr; ifa; ifa = ifa->ifa_next ) {
        if ( ifa->ifa_name != interface )
            continue;

        auto family = ifa->ifa_addr->sa_family;
        if ( family != AF_INET && family != AF_INET6 )
            continue;

        auto sock_size = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        char buffer[NI_MAXHOST];
        if ( getnameinfo(ifa->ifa_addr, sock_size, buffer, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) == 0 ) {
            if ( strchr(buffer, '%') == nullptr ) // ignore link-local addresses ("....%eth0").
                addrs.insert(std::string(buffer));
        }
    }

    freeifaddrs(ifaddr);
    return addrs;
}

std::optional<std::string> getKeyFromFile(const char* file, const char* key) {
    std::ifstream in(file);
    if ( ! in )
        return {};

    std::string line;
    while ( std::getline(in, line) ) {
        line = trim(line);
        if ( line.empty() )
            continue;

        auto m = split1(line, "=");
        if ( trim(m.first) == key ) {
            auto value = trim(m.second);
            if ( value.size() >= 2 && value[0] == '"' && value[value.size() - 1] == '"' )
                value = value.substr(1, value.size() - 2);

            return value;
        }
    }

    return {};
}

Value distribution() {
    if ( auto x = getKeyFromFile("/etc/os-release", "PRETTY_NAME") )
        return *x;

    if ( auto x = getKeyFromFile("/etc/lsb-release", "DISTRIB_DESCRIPTION") )
        return *x;

    auto x = getKeyFromFile("/etc/lsb-release", "DISTRIB_ID");
    auto y = getKeyFromFile("/etc/lsb-release", "DISTRIB_RELEASE");
    if ( x ) {
        if ( y )
            return frmt("{} {}", *x, *y);
        else
            return *x;
    }

    std::ifstream in("/etc/redhat-release");
    if ( in ) {
        std::string line;
        std::getline(in, line);
        if ( line.size() )
            return trim(line);
    }

    std::ifstream in2("/etc/debian_version");
    if ( in2 ) {
        std::string line;
        std::getline(in2, line);
        if ( line.size() )
            return frmt("Debian {}", trim(line));
    }

    return {};
}

std::vector<std::vector<Value>> ZeekAgentLinux::snapshot(const std::vector<table::Argument>& args) {
    std::vector<char> hostname_buffer(1024);
    gethostname(hostname_buffer.data(), static_cast<int>(hostname_buffer.size()));
    hostname_buffer.push_back(0);

    Value id = options().agent_id;
    Value instance = options().instance_id;
    Value hostname = hostname_buffer.data();
    Value addrs = addresses();
    Value platform = platform::name();
    Value os_name = distribution();
    Value agent = options().version_number;
#ifdef HAVE_BROKER
    Value broker = broker::version::string();
#else
    Value broker = "n/a";
#endif
    Value uptime = std::chrono::system_clock::now() - startupTime();
    Value tables =
        Set(value::Type::Text, transform(database()->tables(), [](const auto* t) { return Value(t->name()); }));

    Value kernel_name;
    Value kernel_release;
    Value kernel_arch;

    struct utsname uname_info {};
    if ( uname(&uname_info) >= 0 ) {
        kernel_name = uname_info.sysname;
        kernel_release = uname_info.release;
        kernel_arch = uname_info.machine;
    }

    return {{id, instance, hostname, addrs, platform, os_name, kernel_name, kernel_release, kernel_arch, agent, broker,
             uptime, tables}};
}
} // namespace
