// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

#include "core/table.h"

namespace zeek::agent::table {

class UsersCommon : public SnapshotTable {
public:
    Schema schema() const override {
        return {
            // clang-format off
            .name = "users",
            .summary = "user accounts",
            .description = R"(
                The table provides a list of all user accounts that exist on
                the endpoint, retrieved at the time of the query from the
                operating system.
            )",
            .platforms = { Platform::Darwin, Platform::Linux, Platform::Windows },
            .columns = {
                {.name = "name", .type = value::Type::Text, .summary = "short name"},
                {.name = "full_name", .type = value::Type::Text, .summary = "full name"},
                {.name = "is_admin", .type = value::Type::Bool, .summary = "1 if user has adminstrative privileges"},
                {.name = "is_system", .type = value::Type::Bool, .summary = "1 if user correponds to OS service"},
                {.name = "uid", .type = value::Type::Text, .summary = "user ID (can be alpha-numeric on some platforms)"},
                {.name = "gid", .type = value::Type::Count, .summary = "group ID"},
                {.name = "home", .type = value::Type::Text, .summary = "path to home directory"},
                {.name = "shell", .type = value::Type::Text, .summary = "path to default shell"},
                {.name = "email", .type = value::Type::Text, .summary = "email address"},
            }
            // clang-format on
        };
    }
};

} // namespace zeek::agent::table
