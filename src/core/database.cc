// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "database.h"

#include "core/table.h"
#include "logger.h"
#include "sqlite.h"
#include "util/helpers.h"
#include "util/testing.h"
#include "util/threading.h"

#include <algorithm>
#include <list>
#include <map>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>

#include <nlohmann/json.hpp>

using namespace zeek::agent;

// State for a currently active query.
struct ScheduledQuery {
    timer::ID id;                                                 // query's unique ID
    Query query;                                                  // query itself
    std::unique_ptr<sqlite::PreparedStatement> prepared_query;    // pre-compiled query statement
    std::optional<std::vector<std::vector<Value>>> previous_rows; // previous result set for subscription queries
    std::optional<Time> previous_execution;                       // time when query was most recently run
};

template<>
struct Pimpl<Database>::Implementation {
    // Clean up any state before destruction.
    void done();

    // Lookup table by name.
    Table* table(const std::string& name);

    // Perform query of given type.
    Result<std::optional<query::ID>> query(Query q);

    // Cancel query.
    void cancel(query::ID id, bool regular_shutdown);

    // Expire old state.
    void expire();

    // Regularly peforman pending tasks.
    void poll();

    // Adds table to database.
    void addTable(Table* t);

    // Callback for the timers we install for our queries.
    Interval timerCallback(timer::ID id);

    // Helper to lookup scheduled query.
    std::optional<std::list<ScheduledQuery>::iterator> lookupQuery(query::ID);

    SynchronizedBase* _synchronized =
        nullptr; // database's synchronizer, so that we can grab it during callback execution
    const Configuration* _configuration = nullptr; // configuration object, as passed into constructor
    Scheduler* _scheduler = nullptr;               // scheduler as passed into constructor
    std::unique_ptr<SQLite> _sqlite;               // SQLite backend for performing queries

    std::map<std::string, Table*> _tables; // registered tables indexed by name
    std::list<ScheduledQuery> _queries;    // outstanding queries; list so that iterators remain valid on changes
    std::map<query::ID, std::list<ScheduledQuery>::iterator> _queries_by_id; // outstanding queries indexed by their ID
    std::set<std::pair<query::ID, bool>> _cancelled_queries; // track cancelled, but not removed, queries

    static std::map<std::string, std::unique_ptr<Table>> _registered_tables; // tables registered globally
};

std::map<std::string, std::unique_ptr<Table>> Database::Implementation::_registered_tables;

void Database::Implementation::done() {
    for ( auto&& i : _tables ) {
        if ( i.second->isActive() && ! i.second->usesMockData() )
            i.second->deactivate();
    }

    _queries.clear();
    _sqlite.reset(); // ensure this gets released before the tables go away
}

Result<std::optional<query::ID>> Database::Implementation::query(Query query) {
    for ( const auto& t : query.requires_tables ) {
        if ( ! table(t) )
            return {std::nullopt};
    }

    for ( const auto& t : query.if_missing_tables ) {
        if ( table(t) )
            return {std::nullopt};
    }

    auto prepared_query = _sqlite->prepareStatement(query.sql_stmt);
    if ( ! prepared_query )
        return prepared_query.error();

    auto id = _scheduler->schedule(_scheduler->currentTime(), [this](auto id) { return timerCallback(id); });

    _queries.push_back({.id = id,
                        .query = std::move(query),
                        .prepared_query = std::move(*prepared_query),
                        .previous_rows = {},
                        .previous_execution = {}});
    _queries_by_id[id] = --_queries.end();

    return {id};
}

void Database::Implementation::cancel(query::ID id, bool regular_shutdown) {
    _scheduler->cancel(id);

    if ( auto i = lookupQuery(id) ) {
        // Just mark as cancelled here. We'll remove it later once we can call
        // the callback without trouble for the caller.
        (*i)->query.cancelled = true;
        _cancelled_queries.emplace(id, regular_shutdown);
    }
}

void Database::Implementation::expire() {
    // Cleanup cancelled queries. We split this into two loops in case a
    // callback modifies the set of queries.
    for ( const auto& [id, regular_shutdown] : _cancelled_queries ) {
        auto i = lookupQuery(id);
        if ( ! i )
            continue;

        if ( (*i)->query.callback_done )
            _synchronized->unlockWhile([&, id = id, regular_shutdown = regular_shutdown]() {
                (*(*i)->query.callback_done)(id, ! regular_shutdown);
            });
    }

    for ( const auto& [id, regular_shutdown] : _cancelled_queries ) {
        auto i = lookupQuery(id);
        if ( ! i )
            continue;

        _queries.erase(*i);
        _queries_by_id.erase(id);
    }

    _cancelled_queries.clear();

    // We go through all pending queries, and determine the oldest timestamp
    // per table that any of them might still need.
    std::unordered_map<std::string, Time> expire_times;

    for ( const auto& q : _queries ) {
        for ( const auto& t : q.prepared_query->tables() ) {
            Time expire_until = (q.previous_execution ? *q.previous_execution : 0_time);

            if ( auto i = expire_times.find(t->name()); i != expire_times.end() )
                i->second = std::min(i->second, expire_until);
            else
                expire_times[t->name()] = expire_until;
        }
    }

    const auto now = _scheduler->currentTime();

    for ( auto& [n, t] : _tables ) {
        auto expire_until = now;
        if ( auto i = expire_times.find(n); i != expire_times.end() )
            expire_until = i->second;

        if ( ! t->usesMockData() ) {
            ZEEK_AGENT_DEBUG("database", "[{}] expiring state until t={}", n, to_string(expire_until));
            t->expire(expire_until);
        }
    }
}

void Database::Implementation::poll() {
    for ( auto&& i : _tables ) {
        if ( ! i.second->usesMockData() )
            i.second->poll();
    }
}

void Database::Implementation::addTable(Table* t) {
    auto schema = t->schema();

    if ( _tables.find(schema.name) != _tables.end() )
        throw InternalError(format("table {} registered more than once", schema.name));

    auto rc = _sqlite->addTable(t);
    if ( ! rc )
        throw FatalError(format("error registering table {} with SQLite backend: {}", schema.name, rc.error()));

    _tables[schema.name] = t;
}

static auto diffRows(std::vector<std::vector<Value>> old, std::vector<std::vector<Value>> new_) {
    std::sort(old.begin(), old.end());
    std::sort(new_.begin(), new_.end());

    std::vector<std::vector<Value>> deletes;
    std::set_difference(old.begin(), old.end(), new_.begin(), new_.end(), std::back_inserter(deletes));

    std::vector<std::vector<Value>> adds;
    std::set_difference(new_.begin(), new_.end(), old.begin(), old.end(), std::back_inserter(adds));

    std::vector<query::result::Row> diff;

    diff.reserve(deletes.size());
    for ( auto&& i : deletes )
        diff.push_back({.type = query::result::ChangeType::Delete, .values = std::move(i)});

    for ( auto&& i : adds )
        diff.push_back({.type = query::result::ChangeType::Add, .values = std::move(i)});

    return diff;
}

static auto newRows(std::vector<std::vector<Value>> old, std::vector<std::vector<Value>> new_) {
    std::sort(old.begin(), old.end());
    std::sort(new_.begin(), new_.end());

    std::vector<std::vector<Value>> adds;
    std::set_difference(new_.begin(), new_.end(), old.begin(), old.end(), std::back_inserter(adds));

    std::vector<query::result::Row> diff;

    diff.reserve(adds.size());
    for ( auto&& i : adds )
        diff.push_back({.type = query::result::ChangeType::Add, .values = std::move(i)});

    return diff;
}

Interval Database::Implementation::timerCallback(timer::ID id) {
    SynchronizedBase::Synchronize _(_synchronized);

    auto i = lookupQuery(id);
    if ( ! i || (*i)->query.cancelled )
        // already gone, or will be cleaned up shortly
        return 0s;

    auto sql_result = _synchronized->unlockWhile([&]() { return _sqlite->runStatement(*(*i)->prepared_query); });

    // re-lookup because we released the lock
    i = lookupQuery(id);
    if ( ! i || (*i)->query.cancelled )
        // already gone, or will be cleaned up shortly
        return 0s;

    auto stype = (*i)->query.subscription;
    auto schedule = (stype ? (*i)->query.schedule : 0s);

    if ( sql_result ) {
        std::vector<query::result::Row> rows;

        if ( ! stype || *stype == query::SubscriptionType::Snapshots || ! (*i)->previous_rows ) {
            for ( const auto& sql_row : sql_result->rows )
                rows.push_back({.type = {}, .values = sql_row});
        }

        else if ( stype == query::SubscriptionType::Events )
            rows = newRows(*(*i)->previous_rows, sql_result->rows);

        else if ( stype == query::SubscriptionType::Differences )
            rows = diffRows(*(*i)->previous_rows, sql_result->rows);

        else
            cannot_be_reached();

        if ( (*i)->query.callback_result ) {
            _synchronized->unlockWhile([&]() {
                auto query_result = query::Result{.columns = std::move(sql_result->columns),
                                                  .rows = std::move(rows),
                                                  .cookie = (*i)->query.cookie,
                                                  .initial_result = ! (*i)->previous_rows.has_value()};

                (*(*i)->query.callback_result)(id, query_result);
            });

            // repeat search in case map was modified by callback
            i = lookupQuery(id);
        }

        (*i)->previous_execution = _scheduler->currentTime();

        if ( schedule > 0s )
            (*i)->previous_rows = std::move(sql_result->rows);
    }
    else
        logger()->error(format("table error: {}", sql_result.error()));

    if ( (*i)->query.terminate )
        _scheduler->terminate();

    if ( schedule == 0s )
        cancel(id, true);

    return schedule;
}

std::optional<std::list<ScheduledQuery>::iterator> Database::Implementation::lookupQuery(query::ID id) {
    if ( auto i = _queries_by_id.find(id); i != _queries_by_id.end() )
        return i->second;
    else
        return std::nullopt;
}

Table* Database::Implementation::table(const std::string& name) {
    if ( auto i = _tables.find(name); i != _tables.end() )
        return i->second;

    return nullptr;
}

Database::Database(Configuration* configuration, Scheduler* scheduler) {
    ZEEK_AGENT_DEBUG("database", "creating instance");
    pimpl()->_synchronized = this;
    pimpl()->_configuration = configuration;
    pimpl()->_scheduler = scheduler;
    pimpl()->_sqlite = std::make_unique<SQLite>();
}

Database::~Database() {
    ZEEK_AGENT_DEBUG("database", "destroying instance");
    pimpl()->done();
}

const Configuration& Database::configuration() const {
    // No lock to avoid dead-lock, will be safe because it's constant anyways.
    return *pimpl()->_configuration;
}

Time Database::currentTime() const {
    // No lock, scheduler locks itself.
    return pimpl()->_scheduler->currentTime();
}

size_t Database::numberQueries() const {
    Synchronize _(this);
    return pimpl()->_queries.size();
}

Table* Database::table(const std::string& name) {
    Synchronize _(this);
    return pimpl()->table(name);
}

std::vector<const Table*> Database::tables() {
    std::vector<const Table*> out;

    // Need to creaste a copy to avoid races.
    for ( const auto& [name, tables] : pimpl()->_tables )
        out.push_back(tables);

    return out;
}

Result<std::optional<query::ID>> Database::query(const Query& q) {
    ZEEK_AGENT_DEBUG("database", "new query: {} ", q.sql_stmt);
    Synchronize _(this);

    auto id = pimpl()->query(q);
    if ( id ) {
        if ( *id )
            ZEEK_AGENT_DEBUG("database", "query id is {}", **id);
        else
            ZEEK_AGENT_DEBUG("database", "query is skipped");
    }
    else
        ZEEK_AGENT_DEBUG("database", "query error: {}", id.error());

    return id;
}

void Database::cancel(query::ID id) {
    ZEEK_AGENT_DEBUG("database", "canceling query {}", id);
    Synchronize _(this);
    return pimpl()->cancel(id, false);
}

void Database::poll() {
    ZEEK_AGENT_DEBUG("database", "polling database");
    Synchronize _(this);
    pimpl()->poll();
    pimpl()->expire();
}

void Database::expire() {
    ZEEK_AGENT_DEBUG("database", "expiring database state");
    Synchronize _(this);
    pimpl()->expire();
}

void Database::addTable(Table* t) {
    Synchronize _(this);

    t->setDatabase(this);

    if ( configuration().options().use_mock_data )
        t->enableMockData();

    if ( ! t->usesMockData() ) {
        if ( ! t->init() ) {
            ZEEK_AGENT_DEBUG("database", "not adding table {} to database because it's disabled", t->name());
            t->setDatabase(nullptr);
            return;
        }
    }

    ZEEK_AGENT_DEBUG("database", "adding table {} to database", t->name());
    pimpl()->addTable(t);
}

void Database::registerTable(std::unique_ptr<Table> t) {
    ZEEK_AGENT_DEBUG("database", "registering table {} globally", t->name());
    Database::Implementation::_registered_tables.emplace(t->name(), std::move(t));
}

const std::map<std::string, std::unique_ptr<Table>>& Database::registeredTables() {
    return Database::Implementation::_registered_tables;
}

Table* Database::findRegisteredTable(const std::string& name) {
    for ( const auto& i : Database::Implementation::_registered_tables ) {
        if ( i.first == name )
            return i.second.get();
    }

    return nullptr;
}

std::string Database::documentRegisteredTables() {
    nlohmann::json tables;

    for ( const auto& t : registeredTables() ) {
        auto schema = t.second->schema();
        nlohmann::ordered_json columns; // preserve column order

        for ( const auto& c : schema.columns ) {
            nlohmann::json column;
            column["name"] = c.name;
            column["type"] = to_string(c.type);
            column["summary"] = c.summary;
            column["is_parameter"] = c.is_parameter;
            columns.emplace_back(std::move(column));
        }

        nlohmann::json table;
        table["summary"] = trim(schema.summary);
        table["description"] = trim(schema.description);
        table["platforms"] = transform(schema.platforms, [](auto p) {
            switch ( p ) {
                case Platform::Darwin: return "darwin";
                case Platform::Linux: return "linux";
            };
            cannot_be_reached();
        });

        table["columns"] = columns;
        tables[schema.name] = std::move(table);
    }

    nlohmann::json all;
    all["tables"] = std::move(tables);
    return all.dump(4);
}

TEST_SUITE("Database") {
    template<typename T>
    inline std::string str(const T& t) {
        using namespace table;
        return to_string(t);
    }

    class TestTable : public Table {
    public:
        TestTable(std::string name_postfix = "") : name_postfix(std::move(std::move(name_postfix))) {}
        Schema schema() const override {
            return {.name = "test_table" + name_postfix,
                    .description = "test-description",
                    .columns = {
                        schema::Column{.name = "x", .type = value::Type::Integer, .summary = "colum-description"}}};
        }

        ~TestTable() override {}

        bool init() override {
            initialized = true;
            return true;
        }

        std::vector<std::vector<Value>> rows(Time since, const std::vector<table::Argument>& args) override {
            if ( ! usesMockData() ) {
                CHECK(initialized);
            }

            ++counter;
            return {{counter}, {counter + 1}, {counter + 2}};
        }

        bool initialized = false;
        int64_t counter = 0;
        std::string name_postfix;
    };

    TEST_CASE("table management") {
        Configuration cfg;

        SUBCASE("registration") {
            TestTable t;
            Configuration cfg;
            Scheduler tmgr;
            Database db(&cfg, &tmgr);
            CHECK_EQ(db.tables().size(), 0);

            db.addTable(&t);

            REQUIRE(db.table("test_table"));
            CHECK_EQ(db.table("test_table")->schema().description, "test-description");

            REQUIRE_EQ(db.tables().size(), 1);
            CHECK_EQ(db.tables()[0]->schema().description, "test-description");
        }

        SUBCASE("disabled table") {
            class Disabled : public TestTable {
            public:
                Schema schema() const override {
                    auto schema = TestTable::schema();
                    schema.name = "disabled";
                    return schema;
                }

                bool init() override { return false; }
            };

            Disabled t;
            Configuration cfg;
            Scheduler tmgr;
            Database db(&cfg, &tmgr);
            db.addTable(&t);
            REQUIRE(! db.table("disabled"));
        }
    }

    TEST_CASE("state expiration") {
        class Expire : public TestTable {
        public:
            Expire(std::string name_postfix = "") : TestTable(std::move(name_postfix)) {}
            void expire(Time t_) override { t = t_; }
            Time t = 0_time;
        };

        Expire t;
        Expire t2("2");
        Configuration cfg;
        Scheduler tmgr;
        Database db(&cfg, &tmgr);
        db.addTable(&t);

        SUBCASE("no queries") {
            tmgr.advance(42_time);
            db.expire();
            CHECK_EQ(t.t, 42_time);
        }

        SUBCASE("single query") {
            auto query = Query{.sql_stmt = "SELECT * from test_table",
                               .subscription = {},
                               .schedule = 0s,
                               .cookie = "",
                               .callback_result = [&](query::ID id, const query::Result& result) {}};

            db.query(query);

            tmgr.advance(1_time);
            db.expire();
            CHECK_EQ(t.t, 1_time);
            tmgr.advance(5_time);
            db.expire();
            CHECK_EQ(t.t, 5_time); // previous execution time of query
        }

        SUBCASE("multiple queries, same table") {
            auto query1 = Query{.sql_stmt = "SELECT * from test_table",
                                .subscription = query::SubscriptionType::Snapshots,
                                .schedule = 3s,
                                .cookie = "",
                                .callback_result = [&](query::ID id, const query::Result& result) {}};

            auto query2 = Query{.sql_stmt = "SELECT x from test_table",
                                .subscription = query::SubscriptionType::Snapshots,
                                .schedule = 5s,
                                .cookie = "",
                                .callback_result = [&](query::ID id, const query::Result& result) {}};

            db.query(query1);
            db.query(query2);

            tmgr.advance(1_time);
            db.expire();
            CHECK_EQ(t.t, 1_time); // both have executed immediately at t=0

            tmgr.advance(5_time);
            db.expire();
            CHECK_EQ(t.t, 1_time); // q2 is behind, can't move forward

            tmgr.advance(7_time);
            db.expire();
            CHECK_EQ(t.t, 5_time); // q2 remains behind, can't move fully forward

            tmgr.advance(10_time);
            db.expire();
            CHECK_EQ(t.t, 7_time);

            tmgr.advance(100_time);
            db.expire();
            CHECK_EQ(t.t, 100_time);
        }

        SUBCASE("multiple queries, multiple tables") {
            db.addTable(&t2);

            auto query1 = Query{.sql_stmt = "SELECT * from test_table",
                                .subscription = query::SubscriptionType::Snapshots,
                                .schedule = 3s,
                                .cookie = "",
                                .callback_result = [&](query::ID id, const query::Result& result) {}};

            auto query2 = Query{.sql_stmt = "SELECT * from test_table2",
                                .subscription = query::SubscriptionType::Snapshots,
                                .schedule = 5s,
                                .cookie = "",
                                .callback_result = [&](query::ID id, const query::Result& result) {}};

            db.query(query1);
            db.query(query2);

            tmgr.advance(1_time);
            db.expire();
            CHECK_EQ(t.t, 1_time);
            CHECK_EQ(t2.t, 1_time);

            tmgr.advance(5_time);
            db.expire();
            CHECK_EQ(t.t, 5_time);
            CHECK_EQ(t2.t, 1_time);

            tmgr.advance(7_time);
            db.expire();
            CHECK_EQ(t.t, 5_time);
            CHECK_EQ(t2.t, 7_time);

            tmgr.advance(100_time);
            db.expire();
            CHECK_EQ(t.t, 100_time);
            CHECK_EQ(t2.t, 100_time);
        }
    }

    TEST_CASE("polling") {
        class Polling : public TestTable {
        public:
            void poll() override { ++cnt; }
            int cnt = 0;
        };

        Polling t;
        Configuration cfg;
        Scheduler tmgr;
        Database db(&cfg, &tmgr);
        db.addTable(&t);
        db.poll();
        db.poll();
        db.poll();
        CHECK_EQ(t.cnt, 3);
    }

    TEST_CASE("query") {
        TestTable t;
        Configuration cfg;
        Scheduler tmgr;
        Database db(&cfg, &tmgr);
        db.addTable(&t);

        SUBCASE("single-shot") {
            Result<std::optional<query::ID>> query_id;
            int num_callback_executions = 0;
            int num_done_executions = 0;

            auto callback_result = [&](query::ID id, const query::Result& result) {
                ++num_callback_executions;
                CHECK_EQ(id, *query_id);

                CHECK_EQ(result.columns.size(), 1);
                CHECK_EQ(result.columns[0].name, "x");

                CHECK_EQ(result.rows.size(), 3);
                CHECK(! result.rows[0].type.has_value());
                CHECK_EQ(std::get<int64_t>(result.rows[0].values[0]), num_callback_executions);
                CHECK(! result.rows[1].type.has_value());
                CHECK_EQ(std::get<int64_t>(result.rows[1].values[0]), num_callback_executions + 1);
                CHECK(! result.rows[2].type.has_value());
                CHECK_EQ(std::get<int64_t>(result.rows[2].values[0]), num_callback_executions + 2);

                CHECK_EQ(result.cookie, "Leibniz");
            };

            auto callback_done = [&](query::ID id, bool cancelled) {
                CHECK(! cancelled);
                ++num_done_executions;
            };

            auto query = Query{.sql_stmt = "SELECT * from test_table",
                               .subscription = {},
                               .schedule = 2s, // this should be ignored
                               .requires_tables = {"test_table"},
                               .cookie = "Leibniz",
                               .callback_result = std::move(callback_result),
                               .callback_done = std::move(callback_done)};

            query_id = db.query(query);
            REQUIRE(query_id);
            CHECK_EQ(db.numberQueries(), 1);

            CHECK_EQ(num_callback_executions, 0);
            tmgr.advance(1_time);
            CHECK_EQ(num_callback_executions, 1);
            tmgr.advance(3_time);
            CHECK_EQ(num_callback_executions, 1);

            db.expire();
            CHECK_EQ(db.numberQueries(), 0);
            CHECK_EQ(num_done_executions, 1);
        }

        SUBCASE("subscription - snapshots") {
            Result<std::optional<query::ID>> query_id;
            int num_callback_executions = 0;
            int num_done_executions = 0;

            auto callback_result = [&](query::ID id, const query::Result& result) {
                ++num_callback_executions;
                CHECK_EQ(id, *query_id);

                CHECK_EQ(result.columns.size(), 1);
                CHECK_EQ(result.columns[0].name, "x");

                CHECK_EQ(result.rows.size(), 3);
                CHECK(! result.rows[0].type.has_value());
                CHECK_EQ(std::get<int64_t>(result.rows[0].values[0]), num_callback_executions);
                CHECK(! result.rows[1].type.has_value());
                CHECK_EQ(std::get<int64_t>(result.rows[1].values[0]), num_callback_executions + 1);
                CHECK(! result.rows[2].type.has_value());
                CHECK_EQ(std::get<int64_t>(result.rows[2].values[0]), num_callback_executions + 2);

                CHECK_EQ(result.cookie, "Leibniz");
            };

            auto callback_done = [&](query::ID id, bool cancelled) {
                CHECK(cancelled);
                ++num_done_executions;
            };

            auto query = Query{.sql_stmt = "SELECT * from test_table",
                               .subscription = query::SubscriptionType::Snapshots,
                               .schedule = 2s,
                               .cookie = "Leibniz",
                               .callback_result = std::move(callback_result),
                               .callback_done = std::move(callback_done)};

            query_id = db.query(query);
            REQUIRE(query_id);

            CHECK_EQ(num_callback_executions, 0);
            tmgr.advance(1_time);
            CHECK_EQ(num_callback_executions, 1);
            tmgr.advance(3_time);
            CHECK_EQ(num_callback_executions, 2);

            db.cancel(**query_id);
            tmgr.advance(5_time);
            db.expire();
            CHECK_EQ(num_callback_executions, 2);
            CHECK_EQ(num_done_executions, 1);
        }

        SUBCASE("subscription - differences") {
            Result<std::optional<query::ID>> query_id;
            int num_callback_executions = 0;

            auto callback = [&](query::ID id, const query::Result& result) {
                ++num_callback_executions;

                switch ( num_callback_executions ) {
                    case 1: // first result is snapshot
                        CHECK_EQ(result.rows.size(), 3);
                        CHECK(! result.rows[0].type.has_value());
                        CHECK_EQ(std::get<int64_t>(result.rows[0].values[0]), 1);
                        CHECK(! result.rows[1].type.has_value());
                        CHECK_EQ(std::get<int64_t>(result.rows[1].values[0]), 2);
                        CHECK(! result.rows[2].type.has_value());
                        CHECK_EQ(std::get<int64_t>(result.rows[2].values[0]), 3);
                        break;

                    case 2: // 2nd result is diff
                        CHECK_EQ(result.rows.size(), 2);
                        CHECK_EQ(result.rows[0].type, query::result::ChangeType::Delete);
                        CHECK_EQ(std::get<int64_t>(result.rows[0].values[0]), 1);
                        CHECK_EQ(result.rows[1].type, query::result::ChangeType::Add);
                        CHECK_EQ(std::get<int64_t>(result.rows[1].values[0]), 4);
                        break;

                    case 3: // 3rd result is diff
                        CHECK_EQ(result.rows.size(), 2);
                        CHECK_EQ(result.rows[0].type, query::result::ChangeType::Delete);
                        CHECK_EQ(std::get<int64_t>(result.rows[0].values[0]), 2);
                        CHECK_EQ(result.rows[1].type, query::result::ChangeType::Add);
                        CHECK_EQ(std::get<int64_t>(result.rows[1].values[0]), 5);
                        break;

                    default: CHECK(! false);
                }

                CHECK_EQ(id, *query_id);
            };

            auto query = Query{.sql_stmt = "SELECT * from test_table",
                               .subscription = query::SubscriptionType::Differences,
                               .schedule = 2s,
                               .cookie = "Leibniz",
                               .callback_result = std::move(callback)};

            query_id = db.query(query);
            REQUIRE(query_id);

            CHECK_EQ(num_callback_executions, 0);
            tmgr.advance(1_time);
            CHECK_EQ(num_callback_executions, 1);
            tmgr.advance(3_time);
            CHECK_EQ(num_callback_executions, 2);
        }

        SUBCASE("query - subscription - events") {
            Result<std::optional<query::ID>> query_id;
            int num_callback_executions = 0;

            auto callback = [&](query::ID id, const query::Result& result) {
                ++num_callback_executions;

                switch ( num_callback_executions ) {
                    case 1: // first result is snapshot
                        CHECK_EQ(result.rows.size(), 3);
                        CHECK(! result.rows[0].type.has_value());
                        CHECK_EQ(std::get<int64_t>(result.rows[0].values[0]), 1);
                        CHECK(! result.rows[1].type.has_value());
                        CHECK_EQ(std::get<int64_t>(result.rows[1].values[0]), 2);
                        CHECK(! result.rows[2].type.has_value());
                        CHECK_EQ(std::get<int64_t>(result.rows[2].values[0]), 3);
                        break;

                    case 2: // 2nd result is new events
                        CHECK_EQ(result.rows.size(), 1);
                        CHECK_EQ(result.rows[0].type, query::result::ChangeType::Add);
                        CHECK_EQ(std::get<int64_t>(result.rows[0].values[0]), 4);
                        break;

                    case 3: // 3rd result is new events
                        CHECK_EQ(result.rows.size(), 1);
                        CHECK_EQ(result.rows[0].type, query::result::ChangeType::Add);
                        CHECK_EQ(std::get<int64_t>(result.rows[0].values[0]), 5);
                        break;

                    default: CHECK(! false);
                }

                CHECK_EQ(id, *query_id);
            };

            auto query = Query{.sql_stmt = "SELECT * from test_table",
                               .subscription = query::SubscriptionType::Events,
                               .schedule = 2s,
                               .cookie = "Leibniz",
                               .callback_result = std::move(callback)};

            query_id = db.query(query);
            REQUIRE(query_id);

            CHECK_EQ(num_callback_executions, 0);
            tmgr.advance(1_time);
            CHECK_EQ(num_callback_executions, 1);
            tmgr.advance(3_time);
            CHECK_EQ(num_callback_executions, 2);
        }

        SUBCASE("query with required table missing") {
            int num_callback_executions = 0;
            int num_done_executions = 0;

            auto callback_result = [&](query::ID id, const query::Result& result) { ++num_callback_executions; };

            auto callback_done = [&](query::ID id, bool cancelled) { ++num_done_executions; };

            auto query = Query{.sql_stmt = "SELECT * from test_table",
                               .requires_tables = {"DOES_NOT_EXIST"},
                               .callback_result = std::move(callback_result),
                               .callback_done = std::move(callback_done)};

            auto query_id = db.query(query);
            REQUIRE(query_id);
            CHECK(! *query_id);

            query = Query{.sql_stmt = "SELECT * from test_table",
                          .if_missing_tables = {"test_table"},
                          .callback_result = std::move(callback_result),
                          .callback_done = std::move(callback_done)};

            query_id = db.query(query);
            REQUIRE(query_id);
            CHECK(! *query_id);

            CHECK_EQ(num_callback_executions, 0);
            tmgr.advance(1_time);
            CHECK_EQ(num_callback_executions, 0);

            db.expire();
            CHECK_EQ(num_done_executions, 0);
        }
    }

    TEST_CASE("virtual methods with mock data") {
        // Check that some of our virtual methods aren't called when using mock data.
        class MockedTestTable : public TestTable {
            bool init() override {
                CHECK(false);
                cannot_be_reached();
            }
            void activate() override { CHECK(false); }
            void deactivate() override { CHECK(false); }
            void poll() override { CHECK(false); }
            void expire(Time t) override { CHECK(false); }
        };

        MockedTestTable t;
        t.enableMockData();
        Configuration cfg;
        Scheduler tmgr;
        Database db(&cfg, &tmgr);
        db.addTable(&t);

        auto callback = [&](query::ID id, const query::Result& result) { CHECK_EQ(result.columns.size(), 1); };

        auto query = Query{.sql_stmt = "SELECT * from test_table",
                           .subscription = {},
                           .schedule = 0s,
                           .cookie = "",
                           .callback_result = std::move(callback)};

        auto query_id = db.query(query);
        REQUIRE(query_id);

        tmgr.advance(1000_time);
    }

    TEST_CASE("JSON schema") {
        auto schema = nlohmann::json::parse(Database::documentRegisteredTables());
        auto zeek_agent = schema["tables"]["zeek_agent"];

        // Just a basic check that we it looks right.
        CHECK_EQ(zeek_agent["columns"].size(), 13);
    }
}
