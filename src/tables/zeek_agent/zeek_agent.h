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
            .summary = "Information about the current Zeek Agent process",
            .description = R"(
                )",
            .platforms = {Platform::Darwin, Platform::Linux},
            .columns = {{.name = "id", .type = value::Type::Text, .summary = "unique agent ID"},
                        {.name = "instance",
                         .type = value::Type::Text,
                         .summary = "unique ID for agent process instance"},
                        {.name = "hostname", .type = value::Type::Text, .summary = ""},
                        {.name = "address", .type = value::Type::Text, .summary = ""},
                        {.name = "platform", .type = value::Type::Text, .summary = ""},
                        {.name = "os_name", .type = value::Type::Text, .summary = ""},
                        {.name = "kernel_name", .type = value::Type::Text, .summary = ""},
                        {.name = "kernel_version", .type = value::Type::Text, .summary = ""},
                        {.name = "kernel_arch", .type = value::Type::Text, .summary = ""},
                        {.name = "agent_version", .type = value::Type::Integer, .summary = "agent version"},
                        {.name = "broker", .type = value::Type::Text, .summary = "agent version"},
                        {.name = "uptime", .type = value::Type::Integer, .summary = "process uptime in seconds"},
                        {.name = "tables", .type = value::Type::Text, .summary = "tables available to queries"}},
        };
    }

private:
    Time _startup;
};

} // namespace zeek::agent::table
