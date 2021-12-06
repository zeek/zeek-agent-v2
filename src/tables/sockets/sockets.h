// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "core/table.h"

namespace zeek::agent::table {

class SocketsCommon : public SnapshotTable {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "sockets",
            .description = "List of sockets open on system",
            .columns = {
                {.name = "pid", .type = value::Type::Integer, .description = ""},
                {.name = "process", .type = value::Type::Text, .description = ""},
                {.name = "family", .type = value::Type::Text, .description = ""},
                {.name = "protocol", .type = value::Type::Integer, .description = ""},
                {.name = "local_port", .type = value::Type::Integer, .description = ""},
                {.name = "remote_port", .type = value::Type::Integer, .description = ""},
                {.name = "local_addr", .type = value::Type::Text, .description = ""},
                {.name = "remote_addr", .type = value::Type::Text, .description = ""},
                {.name = "state", .type = value::Type::Text, .description = ""},
        }
            // clang-format on
        };
    }
};
} // namespace zeek::agent::table
