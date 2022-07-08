// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "processes.h"

#include "autogen/config.h"
#include "util/testing.h"

using namespace zeek::agent;

TEST_CASE_FIXTURE(test::TableFixture, "processes" * doctest::test_suite("Tables")) {
    useTable("processes");

    std::string name = "zeek-agent";

    // We should be able to see ourselves.
#ifdef HAVE_WINDOWS
    int ret = 0;
    TCHAR filename[MAX_PATH];

    if ( GetModuleFileNameA(NULL, filename, MAX_PATH) == 0 ) {
        std::error_condition cond = std::system_category().default_error_condition(static_cast<int>(GetLastError()));
        FAIL("Failed to get path to executable: ", cond.message());
    }

    name = filename;
#endif

    auto result = query(frmt("SELECT pid from processes WHERE name = \"{}\" AND pid = {}", name, getpid()));
    REQUIRE_EQ(result.rows.size(), 1);
}
