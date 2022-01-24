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
            .platforms = { Platform::Darwin, Platform::Linux },
            .columns = {
                {.name = "name", .type = value::Type::Text, .description = "short name"},
                {.name = "full_name", .type = value::Type::Text, .description = "full name"},
                {.name = "is_admin", .type = value::Type::Integer, .description = "1 if user has adminstrative privileges"},
                {.name = "is_system", .type = value::Type::Integer, .description = "1 if user correponds to OS service"},
                {.name = "uid", .type = value::Type::Integer, .description = "user ID"},
                {.name = "gid", .type = value::Type::Integer, .description = "group ID"},
                {.name = "home", .type = value::Type::Text, .description = "path to home directory"},
                {.name = "shell", .type = value::Type::Text, .description = "path to default shell"},
                {.name = "email", .type = value::Type::Text, .description = "email address"},
            }
            // clang-format on
        };
    }
};

} // namespace zeek::agent::table
