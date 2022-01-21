// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "core/table.h"

namespace zeek::agent::table {

class ProcessesCommon : public SnapshotTable {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "processes",
            .description = "List of current system processes",
            .columns = {
                {.name = "name", .type = value::Type::Text, .description = "name of process"},
                {.name = "pid", .type = value::Type::Integer, .description = "process ID"},
                {.name = "ppid", .type = value::Type::Integer, .description = "parent's process ID"},
                {.name = "uid", .type = value::Type::Integer, .description = "effective user ID"},
                {.name = "gid", .type = value::Type::Integer, .description = "effective group ID"},
                {.name = "ruid", .type = value::Type::Integer, .description = "real user ID"},
                {.name = "rgid", .type = value::Type::Integer, .description = "real group ID"},
                {.name = "priority", .type = value::Type::Integer, .description = "process priority (higher is more)"},
                {.name = "startup", .type = value::Type::Integer, .description = "time process started"},
                {.name = "vsize", .type = value::Type::Integer, .description = "virtual memory size"},
                {.name = "rsize", .type = value::Type::Integer, .description = "resident memory size"},
                {.name = "utime", .type = value::Type::Integer, .description = "user CPU time"},
                {.name = "stime", .type = value::Type::Integer, .description = "system CPU time"},
        }
            // clang-format on
        };
    }
};
} // namespace zeek::agent::table
