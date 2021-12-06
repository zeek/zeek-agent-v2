// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "core/table.h"

namespace zeek::agent::table {

class UsersCommon : public SnapshotTable {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "users",
            .description = "List of users on system",
            .columns = {
                {.name = "name", .type = value::Type::Text, .description = ""},
                {.name = "full_name", .type = value::Type::Text, .description = ""},
                {.name = "is_admin", .type = value::Type::Integer, .description = ""},
                {.name = "is_system", .type = value::Type::Integer, .description = ""},
                {.name = "uid", .type = value::Type::Integer, .description = ""},
                {.name = "gid", .type = value::Type::Integer, .description = ""},
                {.name = "home", .type = value::Type::Text, .description = ""},
                {.name = "shell", .type = value::Type::Text, .description = ""},
                {.name = "email", .type = value::Type::Text, .description = ""},
            }
            // clang-format on
        };
    }
};

} // namespace zeek::agent::table
