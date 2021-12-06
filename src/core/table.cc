// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "table.h"

#include "database.h"
#include "logger.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/testing.h"

#include <algorithm>

using namespace zeek::agent;

std::string zeek::agent::table::to_string(table::Operator op) {
    switch ( op ) {
        case table::Operator::Equal: return "==";
        case table::Operator::Unequal: return "!=";
        case table::Operator::LowerThan: return "<";
        case table::Operator::GreaterEqual: return ">=";
        case table::Operator::Glob: return "GLOB";
    }
    cannot_be_reached(); // thanks GCC
}

std::string zeek::agent::to_string(value::Type type) {
    switch ( type ) {
        case value::Type::Real: return "real";
        case value::Type::Text: return "text";
        case value::Type::Blob: return "blob";
        case value::Type::Integer: return "int";
        case value::Type::Null: return "null";
    };
    cannot_be_reached(); // thanks GCC
}

std::string zeek::agent::to_string(const Value& value) {
    struct Visitor {
        std::string operator()(int64_t x) { return format("{}", x); }
        std::string operator()(double x) { return format("{}", x); }
        std::string operator()(const std::string& x) { return x; }
        std::string operator()(std::monostate) { return "(null)"; }
    };

    return std::visit(Visitor(), value);
}

std::string zeek::agent::to_string(const std::vector<Value>& values) {
    return join(transform(values, [](const auto& x) { return to_string(x); }), " ");
}

std::string table::Where::str() const {
    return format("{} {} {}", column, to_string(op), zeek::agent::to_string(expression));
}

std::string schema::Column::str() const { return format("{}: {}", name, type); }

std::string zeek::agent::to_string(const std::vector<schema::Column>& values) {
    return join(transform(values, [](const auto& x) { return zeek::agent::to_string(x); }), ", ");
}

Table::~Table() {
    if ( _current_connections != 0 )
        logger()->warn(
            "unbalanced connects/disconnects for table"); // note: cannot throw, and cannot call name() from dtor
}

bool Table::isActive() const { return _current_connections > 0; }

const Options& Table::options() const {
    if ( ! _db )
        throw InternalError("table attempted to access options before initialization");

    return _db->configuration().options();
}

Time Table::currentTime() const {
    if ( ! _db )
        throw InternalError("no database/scheduler available in table");

    return _db->currentTime();
}

std::vector<Value> Table::generateMockRow(int i) {
    std::vector<Value> row;

    for ( auto j = 0u; j < schema().columns.size(); j++ ) {
        Value v;
        switch ( schema().columns[j].type ) {
            case value::Type::Blob: v = format("blob_{:c}_{:c}", ('a' + i % 65), ('a' + j % 65)); break;
            case value::Type::Integer: v = static_cast<int64_t>(100 * (i + 1) + j); break;
            case value::Type::Null: /* leave unset */ break;
            case value::Type::Real: v = format("{:.1f}", (i + 1) * 10 + ((j + 1) / 10.0)); break;
            case value::Type::Text: v = format("text_{:c}_{:c}", ('a' + i % 65), ('a' + j % 65)); break;
        }

        row.push_back(std::move(v));
    }

    return row;
}

void Table::sqliteTrackStatement() {
    if ( ++_current_connections == 1 ) {
        ZEEK_AGENT_DEBUG("table", "activating table {}", name());
        activate();
    }
}

void Table::sqliteUntrackStatement() {
    assert(_current_connections > 0);
    if ( --_current_connections == 0 ) {
        ZEEK_AGENT_DEBUG("table", "deactivating table {}", name());
        deactivate();
    }
}

std::vector<std::vector<Value>> SnapshotTable::rows(Time t, const std::vector<table::Where>& wheres) {
    // We ignore the given time in this method because snapshot() will always
    // be reflecting *now*, and *now* is must be older or equal to *now*, and
    // *now* is always larger or equal any valid t.

    if ( usesMockData() ) {
        std::vector<std::vector<Value>> result;

        for ( int i = 0; i < 5; i++ )
            result.push_back(generateMockRow(i));

        return result;
    }
    else
        return snapshot(wheres);
}

void EventTable::newEvent(std::vector<Value> row) {
    _events.emplace_back(Event{.time = currentTime(), .row = std::move(row)});
}

void EventTable::newEvent(Time t, std::vector<Value> row) {
    if ( ! _events.empty() && t < _events.back().time )
        throw InternalError("outdated timestamp in EventTable::newEvent()");

    _events.emplace_back(Event{.time = t, .row = std::move(row)});
}

std::vector<std::vector<Value>> EventTable::rows(Time t, const std::vector<table::Where>& wheres) {
    // We ignore the WHERE constraints in this implementation.
    std::vector<std::vector<Value>> result;

    if ( usesMockData() ) {
        for ( int i = 0; i < 2; i++ )
            result.push_back(generateMockRow(_mock_seed++));

        for ( int i = 0; i < 1; i++ )
            result.push_back(generateMockRow(_mock_seed));
    }
    else {
        auto begin = std::lower_bound(_events.begin(), _events.end(), Event{.time = t, .row = {}});
        for ( auto i = begin; i != _events.end(); i++ )
            result.push_back(i->row);
    }

    return result;
}

void EventTable::expire(Time t) {
    auto end = std::lower_bound(_events.begin(), _events.end(), Event{.time = t, .row = {}});
    _events.erase(_events.begin(), end);
}

TEST_SUITE("Table") {
    class TestBaseTable : public Table {
    public:
        TestBaseTable(std::string name) : name(name) {}
        Schema schema() const override {
            return {.name = name, .columns = {schema::Column{.name = "x", .type = value::Type::Integer}}};
        }

        std::vector<std::vector<Value>> rows(Time t, const std::vector<table::Where>& wheres) override { return {}; }

        std::string name;
    };

    TEST_CASE("activation") {
        TestBaseTable t("T");
        t.sqliteTrackStatement();
        CHECK(t.isActive());
        t.sqliteTrackStatement();
        CHECK(t.isActive());
        t.sqliteUntrackStatement();
        CHECK(t.isActive());
        t.sqliteUntrackStatement();
        CHECK(! t.isActive());
    }

    TEST_CASE("SnapshotTable") {
        class TestTable : public SnapshotTable {
        public:
            Schema schema() const override {
                return {.name = "test_table", .columns = {schema::Column{.name = "x", .type = value::Type::Integer}}};
            }

            std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override {
                CHECK_EQ(wheres.size(), 1);
                CHECK_EQ(wheres[0].column, "x");
                return {{10l}, {20l}, {30l}, {40l}, {50l}};
            }

            using SnapshotTable::enableMockData;
        };

        TestTable t;

        SUBCASE("real data") {
            auto rows = t.rows(0_time, {table::Where{.column = "x", .op = table::Operator::Equal, .expression = {}}});
            REQUIRE_EQ(rows.size(), 5);
            CHECK_EQ(std::get<int64_t>(rows[0][0]), 10);
            CHECK_EQ(std::get<int64_t>(rows[1][0]), 20);
            CHECK_EQ(std::get<int64_t>(rows[2][0]), 30);
            CHECK_EQ(std::get<int64_t>(rows[3][0]), 40);
            CHECK_EQ(std::get<int64_t>(rows[4][0]), 50);
        }

        SUBCASE("mock data") {
            t.enableMockData();

            for ( int i = 0; i < 3; i++ ) {
                auto rows = t.rows(0_time, {});
                REQUIRE_EQ(rows.size(), 5);
                CHECK_EQ(std::get<int64_t>(rows[0][0]), 100);
                CHECK_EQ(std::get<int64_t>(rows[1][0]), 200);
                CHECK_EQ(std::get<int64_t>(rows[2][0]), 300);
                CHECK_EQ(std::get<int64_t>(rows[3][0]), 400);
                CHECK_EQ(std::get<int64_t>(rows[4][0]), 500);
            }
        }
    }

    TEST_CASE("EventTable") {
        class TestTable : public EventTable {
        public:
            Schema schema() const override {
                return {.name = "test_table", .columns = {schema::Column{.name = "x", .type = value::Type::Integer}}};
            }

            using EventTable::enableMockData;
            using EventTable::newEvent;
        };

        TestTable t;

        t.newEvent(1_time, {10l});
        t.newEvent(2_time, {20l});
        t.newEvent(2_time, {21l});
        t.newEvent(3_time, {30l});
        t.newEvent(4_time, {40l});
        t.newEvent(5_time, {50l});

        SUBCASE("real data") {
            auto rows = t.rows(0_time, {});
            REQUIRE_EQ(rows.size(), 6);
            CHECK_EQ(std::get<int64_t>(rows[0][0]), 10);
            CHECK_EQ(std::get<int64_t>(rows[1][0]), 20);
            CHECK_EQ(std::get<int64_t>(rows[2][0]), 21);
            CHECK_EQ(std::get<int64_t>(rows[3][0]), 30);
            CHECK_EQ(std::get<int64_t>(rows[4][0]), 40);
            CHECK_EQ(std::get<int64_t>(rows[5][0]), 50);

            rows = t.rows(2_time, {});
            CHECK_EQ(rows.size(), 5);

            rows = t.rows(5_time, {});
            CHECK_EQ(rows.size(), 1);

            rows = t.rows(7_time, {});
            CHECK_EQ(rows.size(), 0);

            t.expire(2_time);
            rows = t.rows(0_time, {});
            CHECK_EQ(rows.size(), 5);

            t.expire(5_time);
            rows = t.rows(0_time, {});
            CHECK_EQ(rows.size(), 1);
        }

        SUBCASE("mock data") {
            t.enableMockData();
            auto rows = t.rows(0_time, {});
            REQUIRE_EQ(rows.size(), 3);
            CHECK_EQ(std::get<int64_t>(rows[0][0]), 100);
            CHECK_EQ(std::get<int64_t>(rows[1][0]), 200);
            CHECK_EQ(std::get<int64_t>(rows[2][0]), 300);

            rows = t.rows(0_time, {}); // time does not matter for mock data
            CHECK_EQ(std::get<int64_t>(rows[0][0]), 300);
            CHECK_EQ(std::get<int64_t>(rows[1][0]), 400);
            CHECK_EQ(std::get<int64_t>(rows[2][0]), 500);
        }
    }
}
