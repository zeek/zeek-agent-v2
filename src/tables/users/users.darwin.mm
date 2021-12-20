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

#include <libproc.h>
#include <pwd.h>

#import <Collaboration/Collaboration.h>
#import <CoreServices/CoreServices.h>

namespace zeek::agent::table {

class UsersDarwin : public UsersCommon {
public:
    UsersDarwin();
    std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override;
    void addUser(std::vector<std::vector<Value>>* rows, const CBIdentity* identity);

    std::vector<char> _buffer;
};

namespace {
database::RegisterTable<UsersDarwin> _;
}

UsersDarwin::UsersDarwin() {
    auto bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);

    if ( bufsize < 0 )
        bufsize = 32768; // giant

    _buffer.resize(bufsize);
}

std::vector<std::vector<Value>> UsersDarwin::snapshot(const std::vector<table::Where>& wheres) {
    std::vector<std::vector<Value>> rows;

    auto defaultAuthority = CSGetLocalIdentityAuthority();
    auto identityClass = kCSIdentityClassUser; // kCSIdentityClassGroup would be for groups
    auto query = CSIdentityQueryCreate(nullptr, identityClass, defaultAuthority);

    CFErrorRef error = nullptr;
    CSIdentityQueryExecute(query, kCSIdentityQueryIncludeHiddenIdentities, &error);

    auto results = CSIdentityQueryCopyResults(query);
    auto num_results = CFArrayGetCount(results);

    for ( int i = 0; i < num_results; ++i ) {
        auto cs_identity = (CSIdentityRef)CFArrayGetValueAtIndex(results, i);
        auto cb_identity = [CBIdentity identityWithCSIdentity:cs_identity];
        addUser(&rows, cb_identity);
    }

    CFRelease(results);
    CFRelease(query);
    return rows;
}

void UsersDarwin::addUser(std::vector<std::vector<Value>>* rows, const CBIdentity* identity) {
    Value short_name, full_name, is_admin, is_system, uid, gid, home, shell, email;

    if ( auto posix_name = [[identity posixName] UTF8String] ) {
        // 80 is the "admin" group.
        // TODO: Is it ok to assume that's a static value that's the same everywhere?
        CBGroupIdentity* admin =
            [CBGroupIdentity groupIdentityWithPosixGID:80 authority:[CBIdentityAuthority defaultIdentityAuthority]];

        short_name = posix_name;
        full_name = value::fromOptionalString([[identity fullName] UTF8String]);
        email = value::fromOptionalString([[identity emailAddress] UTF8String]);
        is_admin = value::fromBool([identity isMemberOfGroup:admin]);
        is_system = value::fromBool([identity isHidden]);

        struct passwd pwd;
        struct passwd* result = nullptr;
        if ( getpwnam_r(posix_name, &pwd, _buffer.data(), _buffer.size(), &result) == 0 && result ) {
            uid = pwd.pw_uid;
            gid = pwd.pw_gid;
            home = value::fromOptionalString(pwd.pw_dir);
            shell = value::fromOptionalString(pwd.pw_shell);
        }
        else
            logger()->warn(format("users: getpwname_r() failed for user {}", posix_name));
    }
    else
        logger()->warn("users: user without posix name");

    rows->push_back({short_name, full_name, is_admin, is_system, uid, gid, home, shell, email});
}

} // namespace zeek::agent::table
