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
                {.name = "name", .type = value::Type::Text, .description = ""},
                {.name = "pid", .type = value::Type::Integer, .description = ""},
                {.name = "uid", .type = value::Type::Integer, .description = ""},
                {.name = "gid", .type = value::Type::Integer, .description = ""},
                {.name = "ppid", .type = value::Type::Integer, .description = ""},
                {.name = "niceness", .type = value::Type::Integer, .description = ""},
                {.name = "started", .type = value::Type::Integer, .description = ""},
                {.name = "vsize", .type = value::Type::Integer, .description = ""},
                {.name = "rsize", .type = value::Type::Integer, .description = ""},
                {.name = "utime", .type = value::Type::Integer, .description = ""},
                {.name = "stime", .type = value::Type::Integer, .description = ""},
        }
            // clang-format on
        };
    }
};
} // namespace zeek::agent::table
