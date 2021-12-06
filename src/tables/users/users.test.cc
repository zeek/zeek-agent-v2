// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "users.h"

#include "autogen/config.h"
#include "util/testing.h"

using namespace zeek::agent;

TEST_CASE_FIXTURE(test::TableFixture, "users" * doctest::test_suite("Tables")) {
    useTable("users");

    // We should always have root.
    auto result = query("SELECT is_admin from users WHERE name = \"root\"");
    REQUIRE_EQ(result.rows.size(), 1);
    CHECK_EQ(result.get<int64_t>(0, "is_admin"), 1);
}
