// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/table.h"

namespace zeek::agent::table {

class SocketsCommon : public SnapshotTable {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "sockets",
            .summary = "open network sockets",
            .description = R"(
                The table provides a list of all IP sockets that are open on
                the endpoint at the time of the query.
                )",
            .platforms = { Platform::Darwin, Platform::Linux, Platform::Windows },
            .columns = {
                {.name = "pid", .type = value::Type::Count, .summary = "ID of process holding socket"},
                {.name = "process", .type = value::Type::Text, .summary = "name of process holding socket"},
                {.name = "family", .type = value::Type::Text, .summary = "`IPv4` or `IPv6`"},
                {.name = "protocol", .type = value::Type::Count, .summary = "transport protocol"},
                {.name = "local_addr", .type = value::Type::Address, .summary = "local IP address"},
                {.name = "local_port", .type = value::Type::Count, .summary = "local port number"},
                {.name = "remote_addr", .type = value::Type::Address, .summary = "remote IP address"},
                {.name = "remote_port", .type = value::Type::Count, .summary = "remote port number"},
                {.name = "state", .type = value::Type::Text, .summary = "state of socket"},
        }
            // clang-format on
        };
    }
};

class SocketsEventsCommon : public EventTable {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "sockets_events",
            .summary = "open network sockets",
            .description = R"(
                The table reports IP sockets opening and closing on the endpoint.
                )",
            .platforms = { Platform::Darwin, Platform::Linux },
            .columns = {
                {.name = "time", .type = value::Type::Time, .summary = "timestamp"},
                {.name = "pid", .type = value::Type::Count, .summary = "ID of process holding socket"},
                {.name = "process", .type = value::Type::Text, .summary = "name of process holding socket"},
                {.name = "uid", .type = value::Type::Count, .summary = "user ID of process"},
                {.name = "gid", .type = value::Type::Count, .summary = "group ID of process"},
                {.name = "family", .type = value::Type::Text, .summary = "`IPv4` or `IPv6`"},
                {.name = "protocol", .type = value::Type::Count, .summary = "transport protocol"},
                {.name = "local_addr", .type = value::Type::Address, .summary = "local IP address"},
                {.name = "local_port", .type = value::Type::Count, .summary = "local port number"},
                {.name = "remote_addr", .type = value::Type::Address, .summary = "remote IP address"},
                {.name = "remote_port", .type = value::Type::Count, .summary = "remote port number"},
                {.name = "state", .type = value::Type::Text, .summary = "state of socket"},
        }
            // clang-format on
        };
    }
};

} // namespace zeek::agent::table
