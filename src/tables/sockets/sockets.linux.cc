// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#include "sockets.h"

#include "autogen/config.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "sockets.linux.event.h"
#include "util/fmt.h"
#include "util/helpers.h"

// clang-format off
#include "platform/linux/bpf.h"
#include "autogen/bpf/sockets.skel.h"
// clang-format on

#include <arpa/inet.h>
#include <linux/bpf.h>
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

class SocketsEventsLinux : public SocketsEventsCommon {
public:
    Init init() override;
    void activate() override;
    void deactivate() override;
};

namespace {
database::RegisterTable<SocketsEventsLinux> _2;
}

template<typename T, typename S>
Value to_val(const S& i) {
    return i ? Value(static_cast<T>(i)) : Value();
}

static int handle_event(void* ctx, void* data, size_t data_sz) {
    static auto addr_to_string = [](const void* addr, uint64_t family) -> Value {
        switch ( family ) {
            case AF_INET:
                if ( memcmp(addr, "\x00\x00\x00\x00", 4) == 0 )
                    return {};
                break;

            case AF_INET6:
                if ( memcmp(addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                            16) == 0 )
                    return {};

                break;

            default: break;
        }

        char buffer[INET6_ADDRSTRLEN];
        return inet_ntop(static_cast<int>(family), addr, buffer, sizeof(buffer));
    };

    auto table = reinterpret_cast<SocketsEventsLinux*>(ctx);
    auto ev = reinterpret_cast<const bpfSocketEvent*>(data);

    auto pid = to_val<int64_t>(ev->process.pid);
    auto uid = to_val<int64_t>(ev->process.uid);
    auto gid = to_val<int64_t>(ev->process.gid);
    auto process = Value(ev->process.name);

    Value family;
    switch ( ev->family ) {
        case AF_INET: family = "IPv4"; break;
        case AF_INET6: family = "IPv6"; break;
        default: family = frmt("family-{}", ev->family);
    }

    auto protocol = to_val<int64_t>(ev->protocol);
    auto local_addr = addr_to_string(&ev->local_addr, ev->family);
    auto local_port = to_val<int64_t>(ev->local_port);
    auto remote_addr = addr_to_string(&ev->remote_addr, ev->family);
    auto remote_port = to_val<int64_t>(ntohs(ev->remote_port));

    Value state;
    switch ( ev->state ) {
        case BPF_SOCKET_STATE_CLOSED: state = "closed"; break;
        case BPF_SOCKET_STATE_ESTABLISHED: state = "established"; break;
        case BPF_SOCKET_STATE_EXPIRED: state = "expired"; break;
        case BPF_SOCKET_STATE_FAILED: state = "failed"; break;
        case BPF_SOCKET_STATE_LISTEN: state = "listen"; break;
        case BPF_SOCKET_STATE_UNKNOWN: break; // leave unset
    }

    table->newEvent({table->systemTime(), pid, process, uid, gid, family, protocol, local_addr, local_port, remote_addr,
                     remote_port, state});

    return 1;
}

EventTable::Init SocketsEventsLinux::init() {
    auto bpf = platform::linux::bpf();
    if ( ! bpf->isAvailable() )
        return Init::PermanentlyUnavailable;

    auto skel = platform::linux::BPF::Skeleton{.name = "Sockets",
                                               .open = reinterpret_cast<void*>(sockets__open),
                                               .load = reinterpret_cast<void*>(sockets__load),
                                               .attach = reinterpret_cast<void*>(sockets__attach),
                                               .detach = reinterpret_cast<void*>(sockets__detach),
                                               .destroy = reinterpret_cast<void*>(sockets__destroy),
                                               .event_callback = handle_event,
                                               .event_context = this};

    auto our_bpf = bpf->load<sockets>(std::move(skel));
    if ( ! our_bpf ) {
        logger()->warn(frmt("could not load BPF program: {}", our_bpf.error()));
        return Init::PermanentlyUnavailable;
    }

    if ( auto rc = bpf->init("Sockets", (*our_bpf)->maps.ring_buffer); ! rc ) {
        logger()->warn(frmt("could not initialize BPF program: {}", our_bpf.error()));
        return Init::PermanentlyUnavailable;
    }

    return Init::Available;
}

void SocketsEventsLinux::activate() {
    if ( auto rc = platform::linux::bpf()->attach("Sockets"); ! rc )
        logger()->error(frmt("could not attach BPF program: {}", rc.error()));
}

void SocketsEventsLinux::deactivate() {
    if ( auto rc = platform::linux::bpf()->detach("Sockets"); ! rc )
        logger()->error(frmt("could not detach BPF program: {}", rc.error()));
}

} // namespace zeek::agent::table
