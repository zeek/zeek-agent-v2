// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#pragma once

// clang-format off
#include <doctest/doctest.h>
// clang-format on

#include "core/configuration.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/scheduler.h"

#include <string>
#include <utility>

namespace zeek::agent::test {

/**
 * Fixture class for tests of table implementations, making it easy to query
 * them for checking results.
 */
class TableFixture {
public:
    TableFixture() : db(&cfg, &scheduler) {}

    /**
     * Make global registered table of given name available for querying.
     *
     * @param table_name name of a table registered through `database::Register()`.
     */
    void useTable(std::string table_name) {
        const auto& tables = Database::registeredTables();
        auto t = tables.find(table_name);
        REQUIRE_MESSAGE(t != tables.end(), "table ", table_name, " is not available");
        db.addTable(t->second.get());
    }

    void enableMockDataForTable(std::string table_name) {
        const auto& tables = Database::registeredTables();
        auto t = tables.find(table_name);
        REQUIRE_MESSAGE(t != tables.end(), "table ", table_name, " is not available");
        t->second->enableMockData();
    }

    /**
     * Perform a single-shot query against all added tables. This will execute
     * an SQL statement and block until the result is available. If there's a
     * problem with the query, it will directly fail the current test and abort
     * it.
     *
     * @param stmt SQL statement to execute
     * @returns a valid query result (any prior errors are caught and lead to abortion)
     */
    query::Result query(std::string stmt) {
        std::optional<query::Result> result;
        Query q = {.sql_stmt = std::move(stmt),
                   .subscription = {},
                   .cookie = "",
                   .callback_result = [&](query::ID id, query::Result result_) { result = std::move(result_); }};

        auto rc = db.query(q);
        REQUIRE_MESSAGE(rc, rc.error());

        scheduler.advance(scheduler.currentTime() + 1s); // this will execute the query

        REQUIRE(result);
        return std::move(*result);
    };

    ~TableFixture() {}

    Configuration cfg;
    Scheduler scheduler;
    Database db;
};


} // namespace zeek::agent::test
