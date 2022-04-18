// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/table.h"

namespace zeek::agent::table {

class ProcessesCommon : public SnapshotTable {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "processes",
            .summary = "current processes",
            .description = R"(
                The table provides a list of all processes that are running on
                the endpoint at the time of the query.
                )",
            .platforms = { Platform::Darwin, Platform::Linux, Platform::Windows },
            .columns = {
                {.name = "name", .type = value::Type::Text, .summary = "name of process"},
                {.name = "pid", .type = value::Type::Count, .summary = "process ID"},
                {.name = "ppid", .type = value::Type::Count, .summary = "parent's process ID"},
                {.name = "uid", .type = value::Type::Count, .summary = "effective user ID"},
                {.name = "gid", .type = value::Type::Count, .summary = "effective group ID"},
                {.name = "ruid", .type = value::Type::Count, .summary = "real user ID"},
                {.name = "rgid", .type = value::Type::Count, .summary = "real group ID"},
                {.name = "priority", .type = value::Type::Text, .summary = "process priority (representation is platform-specific)"},
                {.name = "startup", .type = value::Type::Interval, .summary = "time process started"},
                {.name = "vsize", .type = value::Type::Count, .summary = "virtual memory size"},
                {.name = "rsize", .type = value::Type::Count, .summary = "resident memory size"},
                {.name = "utime", .type = value::Type::Interval, .summary = "user CPU time"},
                {.name = "stime", .type = value::Type::Interval, .summary = "system CPU time"},
        }
            // clang-format on
        };
    }
};
} // namespace zeek::agent::table
