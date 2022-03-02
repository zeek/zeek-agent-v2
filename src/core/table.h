// Copyrights (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include "configuration.h"
#include "scheduler.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace zeek::agent {

/**
 * Represents an individual value inside a row of a table. `monostate`
 * corresponds to an unset (null) value. See `Type` for how value types map to
 * what's stored in the variant here.
 */
using Value = std::variant<std::monostate, int64_t, std::string, double>;

namespace value {

/**
 * Captures the type of a value inside a row of a table. The type defines what's stored in the `Value` variant, as
 * follows:
 *
 *      `Null` -> `std::monostate`
 *      `Integer` -> `int64_t`
 *      `Text` -> `string`
 *      `Blob` -> `string`
 *      `Real` -> `double`
 *
 * Behind the scenes, these types also correspond 1:1 to the types that SQlite
 * can represent.
 */
enum class Type { Null, Integer, Text, Blob, Real };

} // namespace value

namespace value {

/** Instantiates a `Value` from a C string. */
inline Value fromOptionalString(const char* s) { return s ? s : Value(); }

/**
 * Instantiates a `Value` from a boolean. The value will have type integer,
 * with value 0 or 1.
 */
inline Value fromBool(bool b) { return b ? 1L : 0L; }

/**
 * Instantiates a `Value` from a time value. The value will have type integer
 * and reflects seconds since the Unix epoch.
 **/
inline Value fromTime(Time t) { return t.time_since_epoch().count(); }

/**
 * Instantiates a `Value` from an interval value. The value will have type
 * integer and reflect seconds.
 **/
inline Value fromInterval(Interval i) { return i.count(); }

} // namespace value

/** Renders a value type into a string representation for display. */
extern std::string to_string(value::Type type);

/** Renders a value into a string representation for display. */
extern std::string to_string(const Value& value);

/** Renders a row of values into a string representation for display. */
extern std::string to_string(const std::vector<Value>& values);

namespace schema {

/** Defines type and further meta-data for one column of a table. */
struct Column {
    std::string name; /**< name of the column */
    value::Type type; /**< type of the column's values */

    /** short human-readable summary of the column's semantics for documentation */
    std::string summary;

    /**< true if this is a hidden column representing a parameter to the table; if so, the name should start with an
     * underscore */
    bool is_parameter = false;

    /** Returns a human-readable representation of the column definition. */
    std::string str() const;
};

} // namespace schema

/** Enum to define platforms that a table supports. */
enum class Platform { Darwin, Linux };

/** Defines a table's schema, along with some further meta data. */
struct Schema {
    std::string name;                    /**< name of the table */
    std::string summary;                 /**< short human-readable description of the
                                                    table for documentation */
    std::string description;             /**< detailed human-readable description of the
                                                table for documentation */
    std::vector<Platform> platforms;     /**< platform that support the table */
    std::vector<schema::Column> columns; /**< the table's columns */

    /** Helper returning just the parameter columns. */
    std::vector<schema::Column> parameters() const;

    /** Returns a column by name, or null if it doesn't exist. */
    std::optional<schema::Column> column(const std::string_view& name);
};

/** Renders a table's schema into a string representation for display. */
extern std::string to_string(const std::vector<schema::Column>& values);

namespace table {

/** Captures a table argument as passed into a SQLite "table-valued function". */
struct Argument {
    std::string column; /**< colum being constrained */
    Value expression;   /**< value to compare againt */
};

/** Renders an argument into a string representation for display. */
extern std::string to_string(const Argument& arg);

} // namespace table

class Database;

namespace sqlite {
class PreparedStatement;
}

/**
 * Abstract base class for all tables providing data for queries.
 *
 * Implememtation will usually not derive from this class directly, but instead
 * from either `SnapshotTable` or `EventTable`. However, it's not forbidden to
 * derive from `Table`, if one so insists.
 */
class Table {
public:
    virtual ~Table();

    /** Shortcut to return the table's name, as provided by its schema. */
    std::string name() const { return schema().name; }

    /**
     * Returns true if the table is currently being used in any
     * ongoing/outstanding queries.
     */
    bool isActive() const;

    /**
     * Hook to return the table's schema.
     *
     * Must be provided by derived class.
     */
    virtual Schema schema() const = 0;

    /**
     * Returns a set of rows representing the table's current data. If a
     * non-zero time is given, the table must only return rows associated with
     * activity from that point onwards. The table may also need to pre-filter rows
     * according to a provided list of WHERE constraints. The filtering must be
     * performed for columns defined as `is_parameter` in the schema.
     * For all other columns, filtering is optional; SQLite will do it later
     * anyways.
     *
     * Must be provided by derived class.
     *
     * @param t earliest time of interest; must be equal to, or earlier than,
     * the current time, per the scheduler driver operation
     *
     * @param wheres constraints coming with the query that is requesting the
     * rows; the implementation may rely on all columns marked as
     * `is_parameter` in the schema, to be present in this list
     */
    virtual std::vector<std::vector<Value>> rows(Time t, const std::vector<table::Argument>& args) = 0;

    /**
     * Hook that's called once when tables gets registered with a `Database`.
     *
     * Derived classed may implement this to perform any one-time
     * initialization tasks, and also decide if the table should be made
     * available for queries. The default implementation just returns true.
     *
     * When this method executes, `options()` may already be used to access
     * global configuration options.
     *
     * This hook will not be called when mock data has been enabled for the table.
     *
     * @result false to completely disable the table at this point, so that it
     * will not be available for queries.
     */
    virtual bool init() { return true; }

    /**
     * Hook that will be called just before the first query against this table
     * becomes active. This hook will also be called if, at some later point,
     * `deactivate()` had been called because no query against the table had
     * remained active anymore, but then a new query comes in. (It's guaranteed
     * that `activate()` will not be called again before `deactivate()` execute.)
     *
     * This hook will not be called when mock data has been enabled for the table.
     *
     * Derived classes may implement this method to start, or restart, data
     * collection. The default implementation does nothing.
     */
    virtual void activate() {}

    /**
     * Hook that will be called when all active queries against this table
     * completed or got otherwise removed.
     *
     * This hook will not be called when mock data has been enabled for the table.
     *
     * Derived classes may implement this method to stop data collection. The
     * default implementation does nothing.
     */
    virtual void deactivate() {} // guarnateed to be called at termination if active

    /**
     * Hook that will be called in regular, but not further defined, intervals
     * during the agent's main processing loop while the table is active.
     *
     * This hook will not be called when mock data has been enabled for the table.
     *
     * Derived classes may implement this method to perform regular tasks, such
     * as collecting outstanding data from their sources. The default
     * implementation does nothing.
     */
    virtual void poll() {}

    /**
     * Hook that will be called when the database won't need any table content
     * anymore that's older than a provided point of time.
     *
     * Derived classes may implement this method to clear out state that's no
     * longer needed.
     *
     * This hook will not be called when mock data has been enabled for the table.
     *
     * @param t any state associated with times strictly older than this
     * can be cleared out
     */
    virtual void expire(Time t) {}

    /**
     * Internal callback from `SQLite` to signal that a new query against this
     * table became active.
     */
    void sqliteTrackStatement();

    /**
     * Internal callback from `SQLite` to signal that an existing query against this
     * table went away.
     */
    void sqliteUntrackStatement();

    /**
     * Switches the table into testing mode where it returns only determistic
     * mock data.
     **/
    void enableMockData() { _use_mock_data = true; }

    /**
     * Returns true if the table has been switched into testing mode where it
     * returns only determistic mock data.
     */
    bool usesMockData() const { return _use_mock_data; }

    /** Returns the database that the table is part of, or null if none. */
    Database* database() const { return _db; }

protected:
    /**
     * Returns the configuration options currently in effect. This won't be
     * available during construction, but it will be from `init()`-time
     * onwards.
     */
    const Options& options() const;

    /** Returns the current time, per our database's scheduler. */
    Time currentTime() const;

    /**
     * Helpers that returns one row of mock data. The value types will match
     * the schema, but the content is fake, and won't make sense semantically.
     * This is primarily for testing the agent from external, to produce
     * determistic data.
     *
     * @param i seed value for the mock row; same seed will return the same values
     */
    std::vector<Value> generateMockRow(int i);

private:
    friend Database;

    // Record the database that this table has been registered with.
    void setDatabase(Database* db) { _db = db; }

    Database* _db = nullptr;      // database set through `setDatabase()`
    int _current_connections = 0; // counter of active queries against this table
    bool _use_mock_data = false;  // if true, have table return mock data for testing
};

/**
 * Abstract base class for tables always providing a complete current snapshot
 * of their state.
 *
 * Derived classes must implement `snapshot()` to provide their data.
 *
 * The class inherits almost all of the hooks that `Table` provides, which
 * derived classes are free to implement them as desired. The one exception is
 * `rows()`, which this class implements itself.
 **/
class SnapshotTable : public Table {
public:
    /**
     * Returns a complete, current snapshot of the activity that the table
     * covers.
     *
     * Must be overridden by derived classes.
     *
     * @returns a vector of rows, each describing on element of the current
     * snapshot and matching the tables schema
     */
    virtual std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) = 0;

    /** Implements the parent class' corresponding method. */
    std::vector<std::vector<Value>> rows(Time t, const std::vector<table::Argument>& args) override;
};

/**
 * Abstract base class for tables providing a continuous stream of event
 * activity.
 *
 * To provide new events, derived classes should call `newEvent()` as data
 * becomes available.
 *
 * The class inherits most of the hooks that `Table` provides, which derived
 * classes are free to implement as desired. The two exceptions are `rows()`
 * and `expire()`, which this class implements itself.
 **/
class EventTable : public Table {
public:
    /**
     * Records an event that has occured.
     *
     * Derived classes need to call this as they observe their activity.
     *
     * @param row the column values associated with the event, which must match the table's schema
     */
    void newEvent(std::vector<Value> row);

    /** Implements the parent class' corresponding method. */
    void expire(Time t) override;

    /** Implements the parent class' corresponding method. */
    std::vector<std::vector<Value>> rows(Time t, const std::vector<table::Argument>& args) override;

protected:
    /**
     * Records an event that has occured, with the internal time explicitly provided.
     *
     * This is just for unit testing when we want define the internal timing of events.
     *
     * @param t event's timestamp, which must not be older than the most recent event currently buffered
     * @param row the column values associated with the event, which must match the table's schema
     */
    void newEvent(Time t, std::vector<Value> row);

private:
    // Captures a buffered event.
    struct Event {
        Time time;
        std::vector<Value> row;
        bool operator<(const Event& other) const { return time < other.time; }
    };

    std::vector<Event> _events; // set of currently buffered events, sorted by timestamp
    int _mock_seed = 0;         // when generating mock data, seed value for next round
};

} // namespace zeek::agent
