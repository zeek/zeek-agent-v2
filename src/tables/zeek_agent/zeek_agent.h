// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/table.h"

namespace zeek::agent::table {

class ZeekAgent : public SnapshotTable {
public:
    ZeekAgent() { _startup = std::chrono::system_clock::now(); }
    auto startupTime() { return _startup; }

    Schema schema() const override {
        return {
            .name = "zeek_agent",
            .summary = "Zeek Agent information",
            .description = R"(
                An internal table providing information about the Zeek
                Agent process and the endpoint it's running on.
                )",
            .platforms = {Platform::Darwin, Platform::Linux},
            .columns = {{.name = "id",
                         .type = value::Type::Text,
                         .summary = "unique agent ID (stable across restarts)"},
                        {.name = "instance",
                         .type = value::Type::Text,
                         .summary = "unique ID for agent process (reset on restart)"},
                        {.name = "hostname", .type = value::Type::Text, .summary = "name of endpoint"},
                        {.name = "addresses",
                         .type = value::Type::Set,
                         .summary = "IP addresses of endpoint's primary network connection"},
                        {.name = "platform", .type = value::Type::Text, .summary = "`Darwin` or `Linux`"},
                        {.name = "os_name", .type = value::Type::Text, .summary = "name of operating system"},
                        {.name = "kernel_name", .type = value::Type::Text, .summary = "name of OS kernel"},
                        {.name = "kernel_version", .type = value::Type::Text, .summary = "version of OS kernel"},
                        {.name = "kernel_arch", .type = value::Type::Text, .summary = "build architecture"},
                        {.name = "agent_version", .type = value::Type::Count, .summary = "agent version"},
                        {.name = "broker", .type = value::Type::Text, .summary = "Broker version"},
                        {.name = "uptime", .type = value::Type::Interval, .summary = "agent uptime"},
                        {.name = "tables", .type = value::Type::Set, .summary = "tables available to queries"}},
        };
    }

private:
    Time _startup;
};

} // namespace zeek::agent::table
