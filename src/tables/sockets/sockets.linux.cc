// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "sockets.h"

#include "autogen/config.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "util/fmt.h"
#include "util/helpers.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pfs/procfs.hpp>

namespace zeek::agent::table {

class SocketsLinux : public SocketsCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

namespace {
database::RegisterTable<SocketsLinux> _;
}

// Maps inodes to pairs (pid, process name).
using InodeMap = std::unordered_map<ino_t, std::pair<int64_t, std::string>>;

static void addSockets(std::vector<std::vector<Value>>* rows, const std::vector<pfs::net_socket>& sockets,
                       int64_t proto, std::string family, const InodeMap& inodes) {
    for ( const auto& s : sockets ) {
        Value pid;
        Value process;
        if ( auto x = inodes.find(s.inode); x != inodes.end() ) {
            pid = x->second.first;
            process = x->second.second;
        }

        Value fak = family;
        Value protocol = proto;
        Value local_port = static_cast<int64_t>(s.local_port);
        Value remote_port = static_cast<int64_t>(s.remote_port);
        Value local_addr = s.local_ip.to_string();
        Value remote_addr = s.remote_ip.to_string();

        Value state;
        switch ( proto ) {
            case 6: {
                switch ( s.socket_net_state ) {
                    case pfs::net_socket::net_state::close: state = "CLOSED"; break;
                    case pfs::net_socket::net_state::close_wait: state = "CLOSE_WAIT"; break;
                    case pfs::net_socket::net_state::closing: state = "CLOSING"; break;
                    case pfs::net_socket::net_state::established: state = "ESTABLISHED"; break;
                    case pfs::net_socket::net_state::fin_wait1: state = "FIN_WAIT_1"; break;
                    case pfs::net_socket::net_state::fin_wait2: state = "FIN_WAIT_2"; break;
                    case pfs::net_socket::net_state::last_ack: state = "LAST_ACK"; break;
                    case pfs::net_socket::net_state::listen: state = "LISTEN"; break;
                    case pfs::net_socket::net_state::syn_recv: state = "SYN_RECEIVED"; break;
                    case pfs::net_socket::net_state::syn_sent: state = "SYN_SENT"; break;
                    case pfs::net_socket::net_state::time_wait: state = "TIME_WAIT"; break;
                    default: cannot_be_reached();
                }
            }
        }

        rows->push_back({pid, process, family, protocol, local_addr, local_port, remote_addr, remote_port, state});
    }
}

std::vector<std::vector<Value>> SocketsLinux::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    try {
        pfs::procfs pfs;

        InodeMap inodes;
        for ( const auto& p : pfs.get_processes() ) {
            try {
                for ( const auto& [id, fd] : p.get_fds() ) {
                    try {
                        auto inode = fd.get_target_stat().st_ino;
                        inodes.emplace(inode, std::make_pair(static_cast<int64_t>(p.id()), p.get_comm()));
                    } catch ( const std::system_error& ) {
                        // ignore, most likely a permission problem
                    }
                }
            } catch ( std::system_error& ) {
                // ignore, most likely a permission problem
            } catch ( std::runtime_error& ) {
                // ignore, most likely a permission problem
            }
        }

        auto net = pfs.get_net();
        addSockets(&rows, net.get_icmp(), IPPROTO_ICMP, "IPv4", inodes);
        addSockets(&rows, net.get_icmp6(), IPPROTO_ICMPV6, "IPv6", inodes);
        addSockets(&rows, net.get_raw(), IPPROTO_RAW, "IPv4", inodes);
        addSockets(&rows, net.get_raw6(), IPPROTO_RAW, "IPv6", inodes);
        addSockets(&rows, net.get_tcp(), IPPROTO_TCP, "IPv4", inodes);
        addSockets(&rows, net.get_tcp6(), IPPROTO_TCP, "IPv6", inodes);
        addSockets(&rows, net.get_udp(), IPPROTO_UDP, "IPv4", inodes);
        addSockets(&rows, net.get_udp6(), IPPROTO_UDP, "IPv6", inodes);
        addSockets(&rows, net.get_udplite(), IPPROTO_UDPLITE, "IPv4", inodes);
        addSockets(&rows, net.get_udplite6(), IPPROTO_UDPLITE, "IPv4", inodes);

    } catch ( std::system_error& ) {
        logger()->warn("cannot read /proc filesystem (system error)");
    } catch ( std::runtime_error& ) {
        logger()->warn("cannot read /proc filesystem (runtime error)");
    }

    return rows;
}
} // namespace zeek::agent::table
