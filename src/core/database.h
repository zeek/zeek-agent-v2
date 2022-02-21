// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "table.h"
#include "util/pimpl.h"
#include "util/result.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace zeek::agent {

namespace query {

/** Globally unique query ID. */
using ID = timer::ID;

namespace result {

/** Type of change to a table. */
enum class ChangeType {
    Add,   /**< rows was added to table */
    Delete /**< row was removed from table */
};

/** Describes one row of a table. */
struct Row {
    std::optional<ChangeType> type; /**< if row is part of a diff, the change type */
    std::vector<Value> values;      /**< the row's values, matching the corresponding schema */
};

} // namespace result

/**
 * Defines the result of a query against the database. The result can itself be
 * seen as a (temporary) table, with its own schema that's determined by the
 * columns the query selects.
 */
struct Result {
    std::vector<schema::Column> columns; /**< The schema  */
    std::vector<result::Row> rows;       /**< set of rows forming the query result */
    std::string cookie;                  /**< copy of cookie provided by caller along with the query */
    bool initial_result = true;          /**< true for the first result of subscription, false for subsequent diffs */

    /**
     * Helpers to extract a column's value of a given name from a particular row.
     *
     * @tparam T value's variant type to extract
     * @param row zero-based row number to extract value from
     * @param column name of column to extract
     */
    template<typename T>
    ::zeek::agent::Result<T> get(uint64_t row, const std::string_view& column) const;
};

template<typename T>
::zeek::agent::Result<T> query::Result::get(uint64_t row, const std::string_view& column) const {
    if ( row >= rows.size() )
        return ::zeek::agent::result::Error(format("row {} exceeds what's available", row));

    uint64_t i = 0;
    for ( ; i < columns.size(); i++ ) {
        if ( columns[i].name == column )
            return std::get<T>(rows[row].values[i]);
    }

    return ::zeek::agent::result::Error(format("column '{}' does not exist in result"));
}

/**
 * Callback executed with a query's result becomes available.
 *
 * @param id the querie's unique ID
 * @param result the query's freshly computed result
 */
using CallbackResult = std::function<void(ID id, const Result& results)>;

/**
 * Callback executed when a query terminates.
 *
 * @param id the querie's unique ID
 * @param canceled true if explicitly cancelyed, false for regular no-longer-scheduled
 */
using CallbackDone = std::function<void(ID id, bool cancelled)>;

/** For repeating queries, the type for follow up results. */
enum class SubscriptionType {
    Snapshots,  // keep returning new, complate snapshots
    Events,     // return only new rows
    Differences // return a diff of rows either added or deletec, marked accordingly
};

} // namespace query


/** Describes a query against the database. */
struct Query {
    std::string sql_stmt;                                /**< SQL statement to execute */
    std::optional<query::SubscriptionType> subscription; /**< enable subscription to updates of given type */
    Interval schedule = 0s;                  /**< for subscriptions, reschedule in such intervals until canceled */
    std::set<std::string> requires_tables;   /**< names of tables that must be present for this query */
    std::set<std::string> if_missing_tables; /**< names of tables that must *not* be present for this query */
    bool terminate = false; /**< if true, terminate the Zeek Agent after this query's callback has executed */
    bool cancelled = false; /**< if true, cancelled and scheduled to be removed */
    std::string cookie;     /**< arbitrary user-chosen string that will be copied into the result */
    std::optional<query::CallbackResult> callback_result; /**< Callback to execute when result is available; will
                                 execute inside the thread driving the database's scheduler */
    std::optional<query::CallbackDone> callback_done;     /**< Callback to execute when query has fully finished; will
                                     execute inside the thread driving the database's scheduler */
};

class Table;
class SQLite;
class Scheduler;

/**
 * Database of tables available for querying. This ties together the indivudual
 * tables that the Zeek Agent offers, with the SQLite-based query engine.
 * Tables are typically registered at agent startup, and then remain available
 * for querying through corresponding SQL statements.
 *
 * Note that database methods are not safe against access from different threads.
 */
class Database : public Pimpl<Database> {
public:
    /**
     * Constructor.
     *
     * @param cfg configuration to use for any options needed; caller must keep object around for the lifetime of the
     * database
     * @param timer_mgr timer manager to use for scheduling queries; caller must keep object around for the lifetime of
     * the database
     */
    Database(Configuration* configuration, Scheduler* scheduler);
    ~Database();

    /** Returns the configuration object provided to the constructor. */
    const Configuration& configuration() const;

    /** Returns the current time, per our scheduler. */
    Time currentTime() const;

    /** Returns the number of concurrently scheduled queries. */
    size_t numberQueries() const;

    /** Returns the table of a given name if that's been registered, or null if not. */
    Table* table(const std::string& name);

    /** Returns the set of all currently registered tables. */
    std::vector<const Table*> tables();

    /**
     * Performs a query against the database. The query may not be executed
     * immediately. Once it does, the query's callback will be run with the result.
     * The callback will execute from within the thread that's driving the
     * scheduler associated with the database.
     *
     * If the query's reschdule interval is set, the same query will
     * automatically be rescheduled afterwards until canceled. The query ID
     * will remain the same for all repeats.
     *
     * @param q query to run
     * @returns if succesful, a unique ID for the query, will be passed to the
     * callback; or an error if there was a problem with the query (such as an
     * error with the SQL statement). The ID may be unset if the DB decided to
     * not process the query, without than being an error situation (e.g.,
     * because it requires certain tables.)
     */
    Result<std::optional<query::ID>> query(const Query& q);

    /**
     * Cancels a previous scheduled query, both standard and subscription. The
     * callback for a canceled query is guaranteed to no longer execute.
     *
     * @param id id of the query to cancel; if no such query exists, the method becomes a no-op
     */
    void cancel(query::ID id);

    /**
     * Lets the database expire any state no longer needed. This should (and
     * must) be called reguarly. It'll get the current time from the scheduler
     * and determine for each table what state can be expired, based on
     * currently outstanding queries against it.
     */
    void expire();

    /**
     * Should (and must) be called regularly during operation to perform any
     * tasks that might be pending internally. This in turns call the `poll()`
     * methods of all registered tables.
     */
    void poll();

    /**
     * Adds a table to the database, so that it can be queried.
     *
     * @param t table to make available; database is not taking ownership, so table needs to stay around
     */
    void addTable(Table* t);

    /**
     * Globally registers a table with the runtime system for later lookup.
     *
     * This is primirarily meant for use by `Table::Register`, and should
     * normally not be called directly.
     */
    static void registerTable(std::unique_ptr<Table> t);

    /**
     * Returns a map of all tables registered globally with the runtime system.
     * The map is indexed by the names of the tables.
     */
    static const std::map<std::string, std::unique_ptr<Table>>& registeredTables();

    /**
     * Looks up a table registered globally with the runtime system by its name.
     *
     * @param name table name to look up.
     */
    static Table* findRegisteredTable(const std::string& name);

    /**
     * Returns JSON with the schema of all tables registered globally with the
     * runtime system.
     */
    static std::string documentRegisteredTables();
};

namespace database {

/**
 * Instantiantes a table and then globally registers the new instance with the
 * database runtime system. Such registered tables will be available through
 * the static Database::registeredTables() method. Note that they will still
 * need to added to individual database instances to make them available to
 * queries.
 *
 * @tparam T table type to instantiate
 */
template<typename T>
class RegisterTable {
public:
    RegisterTable();
};

template<typename T>
RegisterTable<T>::RegisterTable() {
    Database::registerTable(std::make_unique<T>());
}

} // namespace database

} // namespace zeek::agent
