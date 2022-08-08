// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// This takes inspiration from https://stackoverflow.com/questions/3681895/get-all-users-on-os-x.

#include "users.h"

#include "core/database.h"
#include "core/table.h"
#include "platform/windows/platform.h"

using namespace zeek::agent::platform::windows;

namespace zeek::agent::table {

class UsersWindows : public UsersCommon {
public:
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override;
};

namespace {
database::RegisterTable<UsersWindows> _;
}

std::vector<std::vector<Value>> UsersWindows::snapshot(const std::vector<table::Argument>& args) {
    std::vector<std::vector<Value>> rows;

    auto user_data = WMIManager::Get().GetUserData();

    for ( const auto& user : user_data ) {
        Value short_name = user.name;
        Value full_name = user.full_name;
        Value is_admin = user.is_admin;
        Value is_system = user.is_system_acct;
        Value uid = user.sid;
        Value gid = {};
        Value home = user.home_directory;
        Value shell = {};
        Value email = {};

        rows.push_back({short_name, full_name, is_admin, is_system, uid, gid, home, shell, email});
    }

    return rows;
}

} // namespace zeek::agent::table
