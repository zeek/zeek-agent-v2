// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "files.h"

#include "autogen/config.h"
#include "util/helpers.h"
#include "util/testing.h"

#include <algorithm>
#include <filesystem>
#include <variant>

using namespace zeek::agent;

Result<table::FilesColumnsCommon::Columns> table::FilesColumnsCommon::parseColumnsSpec(const std::string& spec) {
    table::FilesColumnsCommon::Columns columns;

    for ( const auto& c : split(trim(spec), ",") ) {
        auto m = split(trim(c), ":");
        if ( m.size() != 2 )
            return result::Error(format("invalid column specification: {}", c));

        if ( m[0].size() < 2 || ! startsWith(m[0], "$") )
            return result::Error(format("invalid column number: {}", m[0]));

        for ( auto i = 1; i < m[0].size(); i++ ) {
            if ( ! isdigit(m[0][i]) )
                return result::Error(format("invalid column number: {}", m[0]));
        }

        int column = std::stoi(m[0].substr(1));
        auto type = type::from_string(tolower(trim(m[1])));
        if ( ! type )
            return type.error();

        columns.emplace_back(column, *type);
    }

    if ( columns.empty() )
        return result::Error("no columns specified");

    return columns;
}

TEST_SUITE("Tables") {
    TEST_CASE("files_columns - parse spec") {
        using Columns = table::FilesColumnsCommon::Columns;
        Result<table::FilesColumnsCommon::Columns> columns;

        columns = table::FilesColumnsCommon::parseColumnsSpec("$2:text,$8:bool,$1:address");
        CHECK_EQ(*columns, Columns{{2, value::Type::Text}, {8, value::Type::Bool}, {1, value::Type::Address}});

        columns = table::FilesColumnsCommon::parseColumnsSpec("$0:int"); // take whole line
        CHECK_EQ(*columns, Columns{{0, value::Type::Integer}});
    }
}

TEST_CASE_FIXTURE(test::TableFixture, "files_list" * doctest::test_suite("Tables")) {
    // Create a temp directory with some well-defined content.
    auto dir = std::filesystem::temp_directory_path() / format("zeek-agent-files_list{}", ::getpid());
    ScopeGuard _([dir] { std::filesystem::remove_all(dir); });
    std::filesystem::create_directory(dir);

    {
        auto f1 = std::ofstream(dir / "file1");
        auto f2 = std::ofstream(dir / "file2");
        std::filesystem::create_directory(dir / "sub");
        auto f3 = std::ofstream(dir / "sub" / "file3");
        auto f4 = std::ofstream(dir / "sub" / "file4");
    }

    useTable("files_list");
    auto result = query(format("SELECT type from files_list(\"{}\")", (dir / "file2").native()));
    REQUIRE_EQ(result.rows.size(), 1);
    CHECK_EQ(*result.get<std::string>(0, "type"), "file");

    result = query(format("SELECT path from files_list(\"{}\")", (dir / "*").native()));
    REQUIRE_EQ(result.rows.size(), 3);

    result = query(format("SELECT path from files_list(\"{}\")", (dir / "sub" / "*").native()));
    REQUIRE_EQ(result.rows.size(), 2);
}

TEST_CASE_FIXTURE(test::TableFixture, "files_lines" * doctest::test_suite("Tables")) {
    // Create a temp directory with some well-defined content.
    auto dir = std::filesystem::temp_directory_path() / format("zeek-agent-files_lines-{}", ::getpid());
    ScopeGuard _([dir] { std::filesystem::remove_all(dir); });
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

    useTable("files_lines");
    auto result = query(format("SELECT content from files_lines(\"{}\")", (dir / "*").native()));
    REQUIRE_EQ(result.rows.size(), 3);
    CHECK_EQ(*result.get<std::string>(0, "content"), "AAA1");
    CHECK_EQ(*result.get<std::string>(1, "content"), "AAA2");
    CHECK_EQ(*result.get<std::string>(2, "content"), "BBB1");
}

TEST_CASE_FIXTURE(test::TableFixture, "files_columns" * doctest::test_suite("Tables")) {
    // Create a temp directory with some well-defined content.
    auto dir = std::filesystem::temp_directory_path() / format("zeek-agent-files_lines-{}", ::getpid());
    ScopeGuard _([dir] { std::filesystem::remove_all(dir); });
    std::filesystem::create_directory(dir);

    {
        auto f1 = std::ofstream(dir / "file1");
        f1 << "   -123   test   1.2.3.4  0 3.14   " << std::endl;
        f1 << "   # comment" << std::endl;
        f1 << "678" << std::endl;

        auto f2 = std::ofstream(dir / "file2");
        f2 << "::111:222::" << std::endl;
    }

    useTable("files_columns");
    auto result =
        query(format(R"(SELECT columns from files_columns("{}", "$1:int,$2:text,$3:blob,$4:count,$5:real,$0:blob"))",
                     (dir / "file1").native()));
    REQUIRE_EQ(result.rows.size(), 2);

    // Default parameters, all types.
    auto c0 = *result.get<Record>(0, "columns");
    CHECK_EQ(c0[0], Record::value_type(-123L, value::Type::Integer));
    CHECK_EQ(c0[1], Record::value_type("test", value::Type::Text));
    CHECK_EQ(c0[2], Record::value_type("1.2.3.4", value::Type::Blob));
    CHECK_EQ(c0[3], Record::value_type(0L, value::Type::Count));
    CHECK_EQ(c0[4], Record::value_type(3.14, value::Type::Double));
    CHECK_EQ(c0[5], Record::value_type("   -123   test   1.2.3.4  0 3.14   ", value::Type::Blob));

    auto c1 = *result.get<Record>(1, "columns");
    CHECK_EQ(c1[0], Record::value_type(678L, value::Type::Integer));
    CHECK(std::holds_alternative<std::monostate>(c1[1].first));
    CHECK(std::holds_alternative<std::monostate>(c1[2].first));
    CHECK(std::holds_alternative<std::monostate>(c1[3].first));
    CHECK(std::holds_alternative<std::monostate>(c1[4].first));
    CHECK_EQ(c1[5], Record::value_type("678", value::Type::Blob));

    // No comment pattern.
    result = query(format(R"(SELECT columns from files_columns("{}", "$1:int", "", ""))", (dir / "file1").native()));
    REQUIRE_EQ(result.rows.size(), 3);

    // Custom separator.
    result =
        query(format(R"(SELECT columns from files_columns("{}", "$1:int,$2:int,$3:int,$4:int,$5:text,$6:int", ":"))",
                     (dir / "file2").native()));
    REQUIRE_EQ(result.rows.size(), 1);

    c0 = *result.get<Record>(0, "columns");
    CHECK(std::holds_alternative<std::monostate>(c0[0].first));
    CHECK(std::holds_alternative<std::monostate>(c0[1].first));
    CHECK_EQ(c0[2], Record::value_type(111L, value::Type::Integer));
    CHECK_EQ(c0[3], Record::value_type(222L, value::Type::Integer));
    CHECK_EQ(c0[4], Record::value_type("", value::Type::Text));
    CHECK(std::holds_alternative<std::monostate>(c0[5].first));
}
