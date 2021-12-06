// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "zeek_agent.h"

#include "autogen/config.h"
#include "util/testing.h"

using namespace zeek::agent;

TEST_CASE_FIXTURE(test::TableFixture, "zeek_agent" * doctest::test_suite("Tables")) {
    useTable("zeek_agent");

    auto result = query("SELECT * from zeek_agent");
    CHECK_EQ(result.get<int64_t>(0, "agent_version"), VersionNumber);
}
