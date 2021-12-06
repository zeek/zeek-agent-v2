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
            .description = "Logs recorded by the operating system",
            .columns = {
                {.name = "time", .type = value::Type::Integer, .description = "unix timestamp"},
                {.name = "process", .type = value::Type::Text, .description = ""},
                {.name = "level", .type = value::Type::Text, .description = ""},
                {.name = "message", .type = value::Type::Text, .description = ""}
            }
            // clang-format on
        };
    }
};

} // namespace zeek::agent::table
