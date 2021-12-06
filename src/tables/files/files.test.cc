// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "files.h"

#include "autogen/config.h"
#include "util/helpers.h"
#include "util/testing.h"

#include <filesystem>

using namespace zeek::agent;

TEST_CASE_FIXTURE(test::TableFixture, "files" * doctest::test_suite("Tables")) {
    // Create a temp directory with some well-defined content.
    auto dir = std::filesystem::temp_directory_path() / format("zeek-agent-files-{}", ::getpid());
    // ScopeGuard _([dir] { std::filesystem::remove_all(dir); });
    std::filesystem::create_directory(dir);

    {
        auto f1 = std::ofstream(dir / "file1");
        f1 << "AAA1" << std::endl;
        f1 << "AAA2" << std::endl;
        auto f2 = std::ofstream(dir / "file2");
        f1 << "BBB1" << std::endl;
        std::filesystem::create_directory(dir / "sub");
        auto f3 = std::ofstream(dir / "sub" / "file3");
        auto f4 = std::ofstream(dir / "sub" / "file4");
    }

    // files_list
    useTable("files_list");
    auto result = query(format("SELECT type from files_list WHERE path = \"{}\"", (dir / "file2").native()));
    REQUIRE_EQ(result.rows.size(), 1);
    CHECK_EQ(*result.get<std::string>(0, "type"), "file");

    result = query(format("SELECT path from files_list WHERE path GLOB \"{}\"", (dir / "*").native()));
    REQUIRE_EQ(result.rows.size(), 3);

    result = query(format("SELECT path from files_list WHERE path GLOB \"{}\"", (dir / "sub" / "*").native()));
    REQUIRE_EQ(result.rows.size(), 2);

    // files_lines
    useTable("files_lines");
    result = query(format("SELECT data from files_lines WHERE path GLOB \"{}\"", (dir / "*").native()));
    REQUIRE_EQ(result.rows.size(), 3);
    CHECK_EQ(*result.get<std::string>(0, "data"), "AAA1");
    CHECK_EQ(*result.get<std::string>(1, "data"), "AAA2");
    CHECK_EQ(*result.get<std::string>(2, "data"), "BBB1");
}
