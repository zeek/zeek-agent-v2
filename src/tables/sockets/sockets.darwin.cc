// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// This is inspired by https://github.com/palominolabs/get_process_handles/blob/master/main.c and
// https://chromium.googlesource.com/external/github.com/giampaolo/psutil/+/refs/heads/master/psutil/_psutil_osx.c

#include "sockets.h"

#include "autogen/config.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "util/fmt.h"
#include "util/helpers.h"

#include <libproc.h>

#include <arpa/inet.h>

namespace zeek::agent::table {

class SocketsDarwin : public SocketsCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override;

    void addSocketsForProcess(std::vector<std::vector<Value>>* rows, int pid, const std::string& process);
    void addSocket(std::vector<std::vector<Value>>* rows, int pid, const std::string& process,
                   const struct socket_info& si);
};

namespace {
database::RegisterTable<SocketsDarwin> _;
}

std::vector<std::vector<Value>> SocketsDarwin::snapshot(const std::vector<table::Where>& wheres) {
    // TODO: The following is replicated from proceeses.darwin.cc, could merge.
    auto buffer_size = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    pid_t pids[buffer_size / sizeof(pid_t)];
    buffer_size = proc_listpids(PROC_ALL_PIDS, 0, pids, static_cast<int>(sizeof(pids)));
    if ( buffer_size <= 0 ) {
        logger()->warn(format("sockets: cannot get pids"));
        return {};
    }

    std::vector<std::vector<Value>> rows;

    for ( size_t i = 0; i < buffer_size / sizeof(pid_t); i++ ) {
        errno = 0;
        struct proc_bsdinfo pi;
        auto n = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &pi, sizeof(pi));

        if ( n < static_cast<int>(sizeof(pi)) || errno != 0 ) {
            if ( errno == ESRCH ) // ESRCH -> process is gone
                continue;

            logger()->debug(format("sockets: could not get process information for PID {}", pids[i]));
            continue;
        }

        if ( pids[i] > 0 )
            addSocketsForProcess(&rows, pids[i], pi.pbi_name);
    }

    return rows;
}

void SocketsDarwin::addSocketsForProcess(std::vector<std::vector<Value>>* rows, int pid, const std::string& process) {
    auto buffer_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
    struct proc_fdinfo fds[buffer_size / sizeof(proc_fdinfo)];
    buffer_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, buffer_size);
    if ( buffer_size <= 0 ) {
        logger()->warn(format("sockets: cannot get FDs for process {}", pid));
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
            logger()->warn(format("sockets: {} (pid {}, fd {})", strerror(errno), pid, fds[i].proc_fd));
            continue;
        }

        if ( socket_info.psi.soi_family == AF_INET || socket_info.psi.soi_family == AF_INET6 )
            addSocket(rows, pid, process, socket_info.psi);
    }
}

void SocketsDarwin::addSocket(std::vector<std::vector<Value>>* rows, int pid, const std::string& process,
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

    rows->push_back({pid, process, family, protocol, local_port, remote_port, local_addr, remote_addr, state});
}

} // namespace zeek::agent::table
