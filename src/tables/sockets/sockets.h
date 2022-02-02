// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "core/table.h"

namespace zeek::agent::table {

class SocketsCommon : public SnapshotTable {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "sockets",
            .summary = "List of sockets open on system",
            .description = R"(
                )",
            .platforms = { Platform::Darwin, Platform::Linux },
            .columns = {
                {.name = "pid", .type = value::Type::Integer, .summary = ""},
                {.name = "process", .type = value::Type::Text, .summary = ""},
                {.name = "family", .type = value::Type::Text, .summary = ""},
                {.name = "protocol", .type = value::Type::Integer, .summary = ""},
                {.name = "local_port", .type = value::Type::Integer, .summary = ""},
                {.name = "remote_port", .type = value::Type::Integer, .summary = ""},
                {.name = "local_addr", .type = value::Type::Text, .summary = ""},
                {.name = "remote_addr", .type = value::Type::Text, .summary = ""},
                {.name = "state", .type = value::Type::Text, .summary = ""},
        }
            // clang-format on
        };
    }
};
} // namespace zeek::agent::table
