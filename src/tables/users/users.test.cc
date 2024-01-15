// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#include "users.h"

#include "autogen/config.h"
#include "util/testing.h"

using namespace zeek::agent;

TEST_CASE_FIXTURE(test::TableFixture, "users" * doctest::test_suite("Tables")) {
    useTable("users");

    // We should always have root.
#ifdef HAVE_WINDOWS
    auto result = query(R"(SELECT is_admin from users WHERE uid like "S-1-5%-500")");
#else
    auto result = query("SELECT is_admin from users WHERE name = \"root\"");
#endif
    REQUIRE_EQ(result.rows.size(), 1);
    CHECK_EQ(result.get<bool>(0, "is_admin"), true);
}
