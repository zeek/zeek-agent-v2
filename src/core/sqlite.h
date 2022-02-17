// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "scheduler.h"
#include "table.h"
#include "util/pimpl.h"
#include "util/result.h"
#include "util/threading.h"

#include <memory>
#include <set>
#include <string>
#include <vector>

struct sqlite3_stmt;

namespace zeek::agent {

class Database;
class SQLite;

namespace sqlite {

/**
 * Represents a precompiled SQL statement. From outside of the SQLite backend,
 * this should be treated as an opaque container; the API here is just for
 * internal use. Ideally we'd just forward declare the class and move the code
 * into the implementation file, but then we couldn't wrap instances into a
 * `unique_ptr`.
 */
class PreparedStatement {
public:
    /**
     * Constructor.
     *
     * This is for internal use by our `SQLite` backend, which knowns how to
     * compute the constructor's arguments.
     *
     * @param stmt pre-compiled SQL statement, as returned by
     * `::sqlite3_prepare_v2`; the construcor takes ownership of the instance
     * @param tables set of tables that the statement accesses
     */
    PreparedStatement(::sqlite3_stmt* stmt, std::set<Table*> tables);
    ~PreparedStatement();

    PreparedStatement(const PreparedStatement& other) = delete;
    PreparedStatement(PreparedStatement&& other) = delete;
    PreparedStatement& operator=(const PreparedStatement& other) = delete;
    PreparedStatement& operator=(PreparedStatement&& other) = delete;

    // Returns the precompiled SQLite statement, as passed into the
    // constructor. For internaly use only.
    auto statement() const { return _statement; }

    // Returns the set of tables used, as passed into the constructor. For
    // internaly use only.
    const auto& tables() const { return _tables; }

private:
    ::sqlite3_stmt* _statement; // as passed into constructor
    std::set<Table*> _tables;   // as passed into constructor
};

/** Results of a SQLite statement. */
struct Result {
    std::vector<schema::Column> columns;  /**< schema for the result's rows */
    std::vector<std::vector<Value>> rows; /**< set of results rows */
};

} // namespace sqlite

/**
 * Backend class for all SQLite operations, interfacing internally to the
 * SQLite C library. This should be used only by the database, which will
 * internally create an instance it owns.
 *
 * All public methods are thread-safe.
 */
class SQLite : public Pimpl<SQLite>, SynchronizedBase {
public:
    SQLite();
    ~SQLite();

    /**
     * Pre-compiled an SQL statement.
     *
     * @param stmt the statement to compile
     * @return the compiled statement, or an error if there was any trouble
     * with the statement
     */
    Result<std::unique_ptr<sqlite::PreparedStatement>> prepareStatement(const std::string& stmt);

    /**
     * Execeutes an SQL statement against the currently registered tables.
     *
     * @param statement pre-compiled statement
     * @param t only entries associated with a timestamp equal or later than
     * this will be included in the result
     * @returns the rows resulting from the statement's execution, or an error
     * if there was trouble
     */
    Result<sqlite::Result> runStatement(const std::string& stmt, std::optional<Time> t = {});

    /**
     * Execeutes a previously compiled SQL statement against the currently registered tables.
     *
     * @param stmt pre-compiled statement
     * @param t only entries associated with a timestamp equal or later than
     * this will be included in the result
     * @returns the rows resulting from the statement's execution, or an error
     * if there was trouble
     */
    Result<sqlite::Result> runStatement(const sqlite::PreparedStatement& stmt, std::optional<Time> t = {});

    /**
     * Registers a table with the backend. Statements can only be run against
     * tables that have been previously registered.
     *
     * @param table table to register; method does not take ownership, caller
     * must ensure it stays around for the lifetime of the backend
     * @returns an error if SQLite had trouble setting up the table
     **/
    Result<Nothing> addTable(Table* table);
};

} // namespace zeek::agent
