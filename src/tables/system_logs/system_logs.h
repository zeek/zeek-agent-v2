// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/table.h"

namespace zeek::agent::table {

class SystemLogs : public EventTable {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "system_logs_events",
            .summary = "log messages recorded by the operating systems",
            .description = R"(
                The table provides access to log messages recorded by the
                operating system.

                On Linux, the table requires `systemd` and hooks into its journal.

                On macOS, the tables hooks into the unified logging system
                (`OSLog`).

                On Windows, the tables hook into the event logging system.

                This is an evented table that captures log messages as they
                appear. New messages will be returned with the next query.
                )",
            .platforms = { Platform::Darwin, Platform::Linux, Platform::Windows },
            .columns = {
                {.name = "time", .type = value::Type::Time, .summary = "timestamp"},
                {.name = "process", .type = value::Type::Text, .summary = "process name"},
                {.name = "level", .type = value::Type::Text, .summary = "severity level"},
                {.name = "message", .type = value::Type::Text, .summary = "log message"},
                {.name = "eventid", .type = value::Type::Text, .summary = "platform-specific identifier for the log event"}
            }
            // clang-format on
        };
    }
};

} // namespace zeek::agent::table
