// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#include "sockets.h"

#include "autogen/config.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "platform/platform.h"
#include "util/fmt.h"
#include "util/helpers.h"

// These have to remain in this order or the build fails.
// clang-format off
#include <WS2tcpip.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <Psapi.h>
// clang-format on

using namespace zeek::agent::platform::windows;

namespace zeek::agent::table {

struct Socket {
    int64_t pid;
    std::string process;
    int64_t family;
    int64_t protocol;
    int64_t local_port;
    int64_t remote_port;
    std::string local_addr;
    std::string remote_addr;
    std::string status;
};

class SocketsWindows : public SocketsCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;

private:
    void getTCPSockets(std::vector<Socket>& result) const;
    void getTCP6Sockets(std::vector<Socket>& result) const;
    void getUDPSockets(std::vector<Socket>& result) const;
    void getUDP6Sockets(std::vector<Socket>& result) const;

    std::string getProcessFromPID(unsigned long pid) const;
    std::string getTCPStateString(unsigned long state) const;
};

namespace {
database::RegisterTable<SocketsWindows> _;
}

std::vector<std::vector<Value>> SocketsWindows::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    std::vector<Socket> open_sockets;

    getTCPSockets(open_sockets);
    getTCP6Sockets(open_sockets);
    getUDPSockets(open_sockets);
    getUDP6Sockets(open_sockets);

    for ( const auto& sock : open_sockets ) {
        std::string family = sock.family == AF_INET ? "IPv4" : "IPv6";

        rows.push_back({sock.pid, sock.process, family, sock.protocol, sock.local_addr, sock.local_port,
                        sock.remote_addr, sock.remote_port, sock.status});
    }

    return rows;
}

void SocketsWindows::getTCPSockets(std::vector<Socket>& result) const {
    DWORD buffer_size = sizeof(MIB_TCPTABLE_OWNER_MODULE);
    DWORD ret = GetExtendedTcpTable(NULL, &buffer_size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
    if ( (ret != NO_ERROR && ret != ERROR_INSUFFICIENT_BUFFER) || buffer_size < sizeof(MIB_TCPTABLE_OWNER_MODULE) )
        return;

    auto table = makeUniqueArray<char>(buffer_size);
    ret = GetExtendedTcpTable(table.get(), &buffer_size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
    if ( ret != NO_ERROR )
        return;

    char addr_str[16]{};

    auto tcp_table = reinterpret_cast<PMIB_TCPTABLE_OWNER_MODULE>(table.get());
    for ( DWORD i = 0; i < tcp_table->dwNumEntries; i++ ) {
        Socket s{};
        s.pid = tcp_table->table[i].dwOwningPid;
        s.process = getProcessFromPID(tcp_table->table[i].dwOwningPid);
        s.family = AF_INET;
        s.protocol = IPPROTO_TCP;
        s.local_port = ntohs(static_cast<uint16_t>(tcp_table->table[i].dwLocalPort));
        s.remote_port = ntohs(static_cast<uint16_t>(tcp_table->table[i].dwRemotePort));
        s.status = getTCPStateString(tcp_table->table[i].dwState);

        auto* ia_in = reinterpret_cast<struct in_addr*>(&tcp_table->table[i].dwLocalAddr);
        inet_ntop(AF_INET, ia_in, addr_str, sizeof(addr_str));
        s.local_addr = addr_str;

        ia_in = reinterpret_cast<struct in_addr*>(&tcp_table->table[i].dwRemoteAddr);
        inet_ntop(AF_INET, ia_in, addr_str, sizeof(addr_str));
        s.remote_addr = addr_str;

        result.push_back(std::move(s));
    }
}

void SocketsWindows::getTCP6Sockets(std::vector<Socket>& result) const {
    DWORD buffer_size = sizeof(MIB_TCP6TABLE_OWNER_MODULE);
    DWORD ret = GetExtendedTcpTable(NULL, &buffer_size, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0);
    if ( (ret != NO_ERROR && ret != ERROR_INSUFFICIENT_BUFFER) || buffer_size < sizeof(MIB_TCP6TABLE_OWNER_MODULE) )
        return;

    auto table = makeUniqueArray<char>(buffer_size);
    ret = GetExtendedTcpTable(table.get(), &buffer_size, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0);
    if ( ret != NO_ERROR )
        return;

    char addr_str[128]{};

    auto tcp_table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_MODULE>(table.get());
    for ( DWORD i = 0; i < tcp_table->dwNumEntries; i++ ) {
        Socket s{};
        s.pid = tcp_table->table[i].dwOwningPid;
        s.process = getProcessFromPID(tcp_table->table[i].dwOwningPid);
        s.family = AF_INET6;
        s.protocol = IPPROTO_TCP;
        s.local_port = ntohs(static_cast<uint16_t>(tcp_table->table[i].dwLocalPort));
        s.remote_port = ntohs(static_cast<uint16_t>(tcp_table->table[i].dwRemotePort));
        s.status = getTCPStateString(tcp_table->table[i].dwState);

        auto* ia_in = reinterpret_cast<struct in6_addr*>(&tcp_table->table[i].ucLocalAddr);
        inet_ntop(AF_INET6, ia_in, addr_str, sizeof(addr_str));
        s.local_addr = addr_str;

        ia_in = reinterpret_cast<struct in6_addr*>(&tcp_table->table[i].ucRemoteAddr);
        inet_ntop(AF_INET6, ia_in, addr_str, sizeof(addr_str));
        s.remote_addr = addr_str;

        result.push_back(std::move(s));
    }
}

void SocketsWindows::getUDPSockets(std::vector<Socket>& result) const {
    DWORD buffer_size = 0;
    DWORD ret = GetExtendedUdpTable(NULL, &buffer_size, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);
    if ( ret != NO_ERROR && ret != ERROR_INSUFFICIENT_BUFFER )
        return;

    auto table = makeUniqueArray<char>(buffer_size);
    ret = GetExtendedUdpTable(table.get(), &buffer_size, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);
    if ( ret != NO_ERROR )
        return;

    char addr_str[16]{};

    auto udp_table = reinterpret_cast<PMIB_UDPTABLE_OWNER_MODULE>(table.get());
    for ( DWORD i = 0; i < udp_table->dwNumEntries; i++ ) {
        Socket s{};
        s.pid = udp_table->table[i].dwOwningPid;
        s.process = getProcessFromPID(udp_table->table[i].dwOwningPid);
        s.family = AF_INET;
        s.protocol = IPPROTO_UDP;
        s.local_port = ntohs(static_cast<uint16_t>(udp_table->table[i].dwLocalPort));

        auto* ia_in = reinterpret_cast<struct in_addr*>(&udp_table->table[i].dwLocalAddr);
        inet_ntop(AF_INET, ia_in, addr_str, sizeof(addr_str));
        s.local_addr = addr_str;

        result.push_back(std::move(s));
    }
}

void SocketsWindows::getUDP6Sockets(std::vector<Socket>& result) const {
    DWORD buffer_size = 0;
    DWORD ret = GetExtendedUdpTable(NULL, &buffer_size, FALSE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0);
    if ( ret != NO_ERROR && ret != ERROR_INSUFFICIENT_BUFFER )
        return;

    auto table = makeUniqueArray<char>(buffer_size);
    ret = GetExtendedUdpTable(table.get(), &buffer_size, FALSE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0);
    if ( ret != NO_ERROR )
        return;

    char addr_str[128]{};

    auto udp_table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_MODULE>(table.get());
    for ( DWORD i = 0; i < udp_table->dwNumEntries; i++ ) {
        Socket s{};
        s.pid = udp_table->table[i].dwOwningPid;
        s.process = getProcessFromPID(udp_table->table[i].dwOwningPid);
        s.family = AF_INET6;
        s.protocol = IPPROTO_UDP;
        s.local_port = ntohs(static_cast<uint16_t>(udp_table->table[i].dwLocalPort));

        auto* ia_in = reinterpret_cast<struct in6_addr*>(&udp_table->table[i].ucLocalAddr);
        inet_ntop(AF_INET6, ia_in, addr_str, sizeof(addr_str));
        s.local_addr = addr_str;

        result.push_back(std::move(s));
    }
}

std::string SocketsWindows::getProcessFromPID(unsigned long pid) const {
    if ( pid == 4 )
        // PID 4 is always the windows system process. See https://superuser.com/a/571470/105420.
        return "System";
    else if ( pid == 0 )
        // PID 0 is always the system idle process.
        return "System Idle Process";

    // This requires the process to be run as Administrator in order to get the information needed
    HandlePtr process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if ( ! process ) {
        std::error_condition cond = std::system_category().default_error_condition(static_cast<int>(GetLastError()));
        ZEEK_AGENT_DEBUG("SocketsWindows", "Failed to open process handle for pid {}: {}", pid, cond.message());
        return {};
    }

    char name[MAX_PATH];
    if ( GetProcessImageFileNameA(process.get(), name, sizeof(name)) == 0 ) {
        std::error_condition cond = std::system_category().default_error_condition(static_cast<int>(GetLastError()));
        ZEEK_AGENT_DEBUG("SocketsWindows", "Failed to get process name for pid {}: {}", pid, cond.message());
        return {};
    }

    return {name};
}

std::string SocketsWindows::getTCPStateString(unsigned long state) const {
    switch ( state ) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RECEIVED";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT_1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT_2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "unknown";
    }
}
} // namespace zeek::agent::table
