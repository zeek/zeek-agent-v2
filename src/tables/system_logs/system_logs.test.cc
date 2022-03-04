// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "system_logs.h"

#include "autogen/config.h"
#include "util/testing.h"

using namespace zeek::agent;

TEST_CASE_FIXTURE(test::TableFixture, "system_logs_events" * doctest::test_suite("Tables")) {
    enableMockDataForTable("system_logs_events");
    useTable("system_logs_events");

    // Can use mock data only here.
    auto result = query("SELECT * from system_logs_events");
    REQUIRE_EQ(result.rows.size(), 3);
    CHECK_EQ(*result.get<std::string>(0, "message"), "text_a_d");
}
