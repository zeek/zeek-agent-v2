// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "zeek_agent.h"

#include "autogen/config.h"
#include "core/database.h"
#include "platform/platform.h"
#include "util/helpers.h"

#include <chrono>

#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <ws2ipdef.h>

#ifdef HAVE_BROKER
#include <broker/version.hh>
#endif

using namespace zeek::agent;
using namespace zeek::agent::platform::windows;
using namespace zeek::agent::table;

namespace {

class ZeekAgentWindows : public ZeekAgent {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

database::RegisterTable<ZeekAgentWindows> _;

std::string get_address_string(const SOCKET_ADDRESS& addr, char* buff, int bufflen) {
    memset(buff, 0, bufflen);

    if ( addr.lpSockaddr->sa_family == AF_INET ) {
        auto* sa_in = reinterpret_cast<sockaddr_in*>(addr.lpSockaddr);
        inet_ntop(AF_INET, &(sa_in->sin_addr), buff, bufflen);
    }
    else if ( addr.lpSockaddr->sa_family == AF_INET6 ) {
        auto* sa_in6 = reinterpret_cast<sockaddr_in6*>(addr.lpSockaddr);
        inet_ntop(AF_INET6, &(sa_in6->sin6_addr), buff, bufflen);
    }

    return buff;
}

Value addresses() {
    ULONG buffer_size = 15360;
    PIP_ADAPTER_ADDRESSES ipaa = NULL;

    int tries = 0;
    ULONG retval = 0;
    do {
        ipaa = static_cast<PIP_ADAPTER_ADDRESSES>(malloc(buffer_size));
        retval = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, ipaa, &buffer_size);

        if ( retval == ERROR_BUFFER_OVERFLOW ) {
            free(ipaa);
            ipaa = NULL;
        }
        else
            break;
        tries++;
    } while ( retval == ERROR_BUFFER_OVERFLOW && tries < 3 );

    if ( ! ipaa )
        return {};

    char addr_str[128]{};

    Set addrs(value::Type::Address);
    PIP_ADAPTER_ADDRESSES curr = ipaa;
    while ( curr ) {
        PIP_ADAPTER_UNICAST_ADDRESS unicast = curr->FirstUnicastAddress;
        while ( unicast ) {
            addrs.insert(get_address_string(unicast->Address, addr_str, sizeof(addr_str)));
            unicast = unicast->Next;
        }

        PIP_ADAPTER_ANYCAST_ADDRESS anycast = curr->FirstAnycastAddress;
        while ( anycast ) {
            addrs.insert(get_address_string(anycast->Address, addr_str, sizeof(addr_str)));
            anycast = anycast->Next;
        }

        PIP_ADAPTER_MULTICAST_ADDRESS multicast = curr->FirstMulticastAddress;
        while ( multicast ) {
            addrs.insert(get_address_string(multicast->Address, addr_str, sizeof(addr_str)));
            multicast = multicast->Next;
        }
        curr = curr->Next;
    }

    free(ipaa);
    return addrs;
}

Value distribution() { return {WMIManager::Get().GetOSVersion()}; }

std::vector<std::vector<Value>> ZeekAgentWindows::snapshot(const std::vector<table::Argument>& args) {
    std::vector<char> hostname_buffer(1024);
    gethostname(hostname_buffer.data(), static_cast<int>(hostname_buffer.size()));
    hostname_buffer.push_back(0);

    Value id = options().agent_id;
    Value instance = options().instance_id;
    Value hostname = hostname_buffer.data();
    Value address = std::move(addresses());
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

    // Kernel information doesn't really exist for windows so those columns are returned as nulls.
    return {{id, instance, hostname, address, platform, os_name, {}, {}, {}, agent, broker, uptime, tables}};
}
} // namespace
