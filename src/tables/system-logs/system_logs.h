// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/table.h"

namespace zeek::agent::table {

class SystemLogs : public EventTable {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "system_logs_events",
            .summary = "Logs recorded by the operating system",
            .description = R"(
                )",
            .platforms = { Platform::Darwin, Platform::Linux },
            .columns = {
                {.name = "time", .type = value::Type::Integer, .summary = "unix timestamp"},
                {.name = "process", .type = value::Type::Text, .summary = ""},
                {.name = "level", .type = value::Type::Text, .summary = ""},
                {.name = "message", .type = value::Type::Text, .summary = ""}
            }
            // clang-format on
        };
    }
};

} // namespace zeek::agent::table
