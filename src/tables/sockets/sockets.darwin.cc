// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// This is inspired by https://github.com/palominolabs/get_process_handles/blob/master/main.c and
// https://chromium.googlesource.com/external/github.com/giampaolo/psutil/+/refs/heads/master/psutil/_psutil_osx.c

#include "sockets.h"

#include "autogen/config.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "platform/darwin/network-extension.h"
#include "platform/darwin/platform.h"
#include "util/fmt.h"
#include "util/helpers.h"

#include <iostream>

#include <libproc.h>

#include <arpa/inet.h>

namespace zeek::agent::table {

class SocketsDarwin : public SocketsCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;

    void addSocketsForProcess(std::vector<std::vector<Value>>* rows, int pid, Value process);
    void addSocket(std::vector<std::vector<Value>>* rows, int pid, Value process, const struct socket_info& si);
};

namespace {
database::RegisterTable<SocketsDarwin> _1;
}

std::vector<std::vector<Value>> SocketsDarwin::snapshot(const std::vector<table::Argument>& args) {
    auto pids = platform::darwin::getProcesses();
    if ( ! pids ) {
        logger()->debug("could not get process list: {}", pids.error());
        return {};
    }

    std::vector<std::vector<Value>> rows;

    for ( auto pid : *pids ) {
        if ( pid <= 0 )
            continue;

        if ( auto p = platform::darwin::getProcessInfo(pid) )
            addSocketsForProcess(&rows, pid, p->name);
        else
            logger()->debug("could not get process info for PID {}: {}", pid, p.error());
    }

    return rows;
}

void SocketsDarwin::addSocketsForProcess(std::vector<std::vector<Value>>* rows, int pid, Value process) {
    auto buffer_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
    struct proc_fdinfo fds[buffer_size / sizeof(proc_fdinfo)];
    buffer_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, buffer_size);
    if ( buffer_size <= 0 ) {
        logger()->warn("sockets: cannot get FDs for process {}", pid);
        return;
    }

    for ( size_t i = 0; i < buffer_size / sizeof(proc_fdinfo); i++ ) {
        if ( fds[i].proc_fdtype != PROX_FDTYPE_SOCKET )
            continue;

        struct socket_fdinfo socket_info;
        errno = 0;
        auto n = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &socket_info, sizeof(socket_fdinfo));

        if ( n < static_cast<int>(sizeof(socket_fdinfo)) || errno != 0 ) {
            if ( errno == EBADF )
                continue; // assume closed

            if ( errno == EOPNOTSUPP )
                continue; // assume can happen apparently

            // We arrive here for lots of "Socket operation on non-socket". Could be files?
            logger()->warn("sockets: {} (pid {}, fd {})", strerror(errno), pid, fds[i].proc_fd);
            continue;
        }

        if ( socket_info.psi.soi_family == AF_INET || socket_info.psi.soi_family == AF_INET6 )
            addSocket(rows, pid, std::move(process), socket_info.psi);
    }
}

void SocketsDarwin::addSocket(std::vector<std::vector<Value>>* rows, int pid, Value process,
                              const struct socket_info& si) {
    static auto addr_to_string = [](const auto& addr, int family) -> std::string {
        char buffer[INET6_ADDRSTRLEN];

        switch ( family ) {
            case PF_INET: return inet_ntop(family, &addr.ina_46.i46a_addr4, buffer, sizeof(buffer));
            case PF_INET6: return inet_ntop(family, &addr.ina_6, buffer, sizeof(buffer));
            default: cannot_be_reached();
        }
    };

    Value family;
    switch ( si.soi_family ) {
        case PF_INET: family = "IPv4"; break;
        case PF_INET6: family = "IPv6"; break;
        default: return;
    }

    Value protocol = si.soi_protocol;
    Value local_port = ntohs(si.soi_proto.pri_in.insi_lport);
    Value remote_port = ntohs(si.soi_proto.pri_in.insi_fport);
    Value local_addr = addr_to_string(si.soi_proto.pri_in.insi_laddr, si.soi_family);
    Value remote_addr = addr_to_string(si.soi_proto.pri_in.insi_faddr, si.soi_family);

    Value state;
    switch ( si.soi_protocol ) {
        case 6: {
            switch ( si.soi_proto.pri_tcp.tcpsi_state ) {
                // Mapping from https://github.com/alecmocatta/socketstat/blob/master/src/mac.rs
                case 0: state = "CLOSED"; break;
                case 1: state = "LISTEN"; break;
                case 2: state = "SYN_SENT"; break;
                case 3: state = "SYN_RECEIVED"; break;
                case 4: state = "ESTABLISHED"; break;
                case 5: state = "CLOSE_WAIT"; break;
                case 6: state = "FIN_WAIT_1"; break;
                case 7: state = "CLOSING"; break;
                case 8: state = "LAST_ACK"; break;
                case 9: state = "FIN_WAIT_2"; break;
                case 10: state = "TIME_WAIT"; break;
                case 11: state = "RESERVED"; break;
                default: break;
            }
        }
    }

    rows->push_back(
        {pid, std::move(process), family, protocol, local_addr, local_port, remote_addr, remote_port, state});
}

class SocketsEventsDarwin : public SocketsEventsCommon {
public:
    Init init() override;
    void activate() override;
    void deactivate() override;

private:
    std::unique_ptr<platform::darwin::ne::Subscriber> _subscriber;
};

namespace {
database::RegisterTable<SocketsEventsDarwin> _2;
}

static void handle_event(SocketsEventsDarwin* table, const platform::darwin::ne::Flow& flow) {
    ZEEK_AGENT_DEBUG("sockets-events", "got flow");

    const Value t = table->systemTime();
    const Value pid = flow.pid;
    const Value process = flow.process.name;
    const Value uid = flow.process.uid;
    const Value gid = flow.process.gid;
    const Value family = flow.family;
    const Value protocol = flow.protocol;
    const Value state = flow.state;

    table->newEvent({t, pid, process, uid, gid, family, protocol, flow.local_addr, flow.local_port, flow.remote_addr,
                     flow.remote_port, state});
}

Table::Init SocketsEventsDarwin::init() {
    auto ne = platform::darwin::networkExtension();

    // It may take a bit for the network extension to start up, so we'll keep
    // trying.
    return ne->isAvailable() ? Init::Available : Init::TemporarilyUnavailable;
}

void SocketsEventsDarwin::activate() {
    auto ne = platform::darwin::networkExtension();
    _subscriber = ne->subscribe("sockets-events", [this](const auto& event) { handle_event(this, event); });
}

void SocketsEventsDarwin::deactivate() { _subscriber.reset(); }

} // namespace zeek::agent::table
