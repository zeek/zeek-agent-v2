// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// This takes inspiration from https://stackoverflow.com/questions/3681895/get-all-users-on-os-x.

#include "users.h"

#include "autogen/config.h"
#include "core/configuration.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/table.h"
#include "util/fmt.h"

#include <pwd.h>

namespace zeek::agent::table {

class UsersLinux : public UsersCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

namespace {
database::RegisterTable<UsersLinux> _;
}

std::vector<std::vector<Value>> UsersLinux::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    setpwent();

    while ( true ) {
        auto pw = getpwent();
        if ( ! pw )
            break;

        Value short_name = pw->pw_name;
        Value full_name = pw->pw_gecos;
        Value is_admin = (pw->pw_uid == 0);
        Value is_system = {};
        Value uid = static_cast<int64_t>(pw->pw_uid);
        Value gid = static_cast<int64_t>(pw->pw_gid);
        Value home = pw->pw_dir;
        Value shell = pw->pw_shell;
        Value email = {};

        rows.push_back({short_name, full_name, is_admin, is_system, uid, gid, home, shell, email});
    }

    endpwent();
    return rows;
}

} // namespace zeek::agent::table
