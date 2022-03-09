// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "processes.h"

#include "autogen/config.h"
#include "util/testing.h"

using namespace zeek::agent;

TEST_CASE_FIXTURE(test::TableFixture, "processes" * doctest::test_suite("Tables")) {
    useTable("processes");

    // We should be able to see ourselves.
#ifdef _WIN32
    int ret = 0;
    TCHAR filename[MAX_PATH];

    if ( GetModuleFileNameA(NULL, filename, MAX_PATH) == 0 ) {
        std::error_condition cond = std::system_category().default_error_condition(static_cast<int>(GetLastError()));
        FAIL("Failed to get path to executable: ", cond.message());
    }

    auto result = query(format("SELECT pid from processes where name = \"{}\" AND pid = {}", filename, getpid()));
#else
    auto result = query(format("SELECT pid from processes WHERE name = \"zeek-agent\" AND pid = {}", getpid()));
#endif

    REQUIRE_EQ(result.rows.size(), 1);
}
