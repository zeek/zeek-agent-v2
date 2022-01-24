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
            .description = "Information about the current Zeek Agent process",
            .columns = {{.name = "id", .type = value::Type::Text, .description = "unique agent ID"},
                        {.name = "instance",
                         .type = value::Type::Text,
                         .description = "unique ID for agent process instance"},
                        {.name = "hostname", .type = value::Type::Text, .description = ""},
                        {.name = "address", .type = value::Type::Text, .description = ""},
                        {.name = "platform", .type = value::Type::Text, .description = ""},
                        {.name = "os_name", .type = value::Type::Text, .description = ""},
                        {.name = "kernel_name", .type = value::Type::Text, .description = ""},
                        {.name = "kernel_version", .type = value::Type::Text, .description = ""},
                        {.name = "kernel_arch", .type = value::Type::Text, .description = ""},
                        {.name = "agent_version", .type = value::Type::Integer, .description = "agent version"},
                        {.name = "broker", .type = value::Type::Text, .description = "agent version"},
                        {.name = "uptime", .type = value::Type::Integer, .description = "process uptime in seconds"},
                        {.name = "tables", .type = value::Type::Text, .description = "tables available to queries"}},
        };
    }

private:
    Time _startup;
};

} // namespace zeek::agent::table
