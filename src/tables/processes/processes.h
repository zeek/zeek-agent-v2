// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

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
            .platforms = { Platform::Darwin, Platform::Linux },
            .columns = {
                {.name = "name", .type = value::Type::Text, .summary = "name of process"},
                {.name = "pid", .type = value::Type::Integer, .summary = "process ID"},
                {.name = "ppid", .type = value::Type::Integer, .summary = "parent's process ID"},
                {.name = "uid", .type = value::Type::Integer, .summary = "effective user ID"},
                {.name = "gid", .type = value::Type::Integer, .summary = "effective group ID"},
                {.name = "ruid", .type = value::Type::Integer, .summary = "real user ID"},
                {.name = "rgid", .type = value::Type::Integer, .summary = "real group ID"},
                {.name = "priority", .type = value::Type::Integer, .summary = "process priority (higher is more)"},
                {.name = "startup", .type = value::Type::Integer, .summary = "time process started"},
                {.name = "vsize", .type = value::Type::Integer, .summary = "virtual memory size"},
                {.name = "rsize", .type = value::Type::Integer, .summary = "resident memory size"},
                {.name = "utime", .type = value::Type::Integer, .summary = "user CPU time"},
                {.name = "stime", .type = value::Type::Integer, .summary = "system CPU time"},
        }
            // clang-format on
        };
    }
};
} // namespace zeek::agent::table
