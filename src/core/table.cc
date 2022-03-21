
#include "table.h"

#include "database.h"
#include "logger.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/testing.h"

#include <algorithm>
#include <iostream>
#include <set>
#include <utility>
#include <variant>

#include <nlohmann/json.hpp>

using namespace zeek::agent;

std::string zeek::agent::value::to_string(const value::Type& type) {
    switch ( type ) {
        case value::Type::Address: return "address";
        case value::Type::Blob: return "blob";
        case value::Type::Bool: return "bool";
        case value::Type::Count: return "count";
        case value::Type::Double: return "real";
        case value::Type::Integer: return "int";
        case value::Type::Interval: return "interval";
        case value::Type::Null: return "null";
        case value::Type::Text: return "text";
        case value::Type::Time: return "time";
        case value::Type::Port: return "port";
        case value::Type::Record: return "record";
        case value::Type::Set: return "set";
        case value::Type::Vector: return "vector";
    };
    cannot_be_reached(); // thanks GCC
}

Result<value::Type> zeek::agent::type::from_string(const std::string& type) {
    if ( type == "address" )
        return value::Type::Address;
    if ( type == "blob" )
        return value::Type::Blob;
    if ( type == "bool" )
        return value::Type::Bool;
    if ( type == "count" )
        return value::Type::Count;
    if ( type == "real" )
        return value::Type::Double;
    if ( type == "int" )
        return value::Type::Integer;
    if ( type == "interval" )
        return value::Type::Interval;
    if ( type == "null" )
        return value::Type::Null;
    if ( type == "text" )
        return value::Type::Text;
    if ( type == "time" )
        return value::Type::Time;
    if ( type == "port" )
        return value::Type::Port;
    if ( type == "record" )
        return value::Type::Record;
    if ( type == "set" )
        return value::Type::Set;
    if ( type == "vector" )
        return value::Type::Vector;

    return result::Error(format("unknown type value '{}'", type));
}

std::string zeek::agent::to_string(const Value& value) {
    struct Visitor {
        std::string operator()(Interval x) { return format("{}", to_string(x)); }
        std::string operator()(Time x) { return format("{}", to_string(x)); }
        std::string operator()(bool x) { return format("{}", (x ? "true" : "false")); }
        std::string operator()(const Record& v) { return to_string(v); }
        std::string operator()(const Port& v) { return to_string(v); }
        std::string operator()(const Set& v) { return to_string(v); }
        std::string operator()(const Vector& v) { return to_string(v); }
        std::string operator()(const std::string& x) { return x; }
        std::string operator()(double x) { return format("{}", x); }
        std::string operator()(int64_t x) { return format("{}", x); }
        std::string operator()(std::monostate) { return "(null)"; }
    };

    return std::visit(Visitor(), static_cast<const Value::Base&>(value));
}

static nlohmann::json to_json(const Value& v, const value::Type& t);
static Value from_json(const nlohmann::json& value, const value::Type& type);

static nlohmann::json to_json(const Port& v) {
    auto elements = nlohmann::json::object({{"port", v.port}, {"proto", static_cast<int>(v.protocol)}});
    std::cerr << elements.dump() << std::endl;
    return elements;
}

static Value from_json_port(const nlohmann::json& v) {
    return Port(v["port"], static_cast<port::Protocol>(v["proto"]));
}

static nlohmann::json to_json(const Record& v) {
    std::vector<nlohmann::json> elements;

    for ( const auto& i : v ) {
        auto elem = nlohmann::json::object({{"type", to_string(i.second)}, {"value", to_json(i.first, i.second)}});
        elements.emplace_back(std::move(elem));
    }

    return elements;
}

static Value from_json_record(const nlohmann::json& v) {
    Record elements;

    for ( const auto& i : v ) {
        auto type = type::from_string(i["type"]);
        assert(type);
        elements.emplace_back(from_json(i["value"], *type), *type);
    }

    return {elements};
}

static nlohmann::json to_json(const Set& v) {
    std::vector<nlohmann::json> elements;

    for ( const auto& i : v )
        elements.emplace_back(to_json(i, v.type));

    return nlohmann::json::object({{"elem", to_string(v.type)}, {"value", elements}});
}

static Value from_json_set(const nlohmann::json& v) {
    auto type = type::from_string(v["elem"]);
    const auto& values = v["value"];
    assert(type);

    Set elements(*type);

    for ( const auto& i : values )
        elements.insert(from_json(i, *type));

    return elements;
}

static nlohmann::json to_json(const Vector& v) {
    std::vector<nlohmann::json> elements;

    for ( const auto& i : v )
        elements.emplace_back(to_json(i, v.type));

    return nlohmann::json::object({{"elem", to_string(v.type)}, {"value", elements}});
}

static Value from_json_vector(const nlohmann::json& v) {
    auto type = type::from_string(v["elem"]);
    const auto& values = v["value"];
    assert(type);

    Vector elements(*type);

    for ( const auto& i : values )
        elements.emplace_back(from_json(i, *type));

    return elements;
}

static nlohmann::json to_json(const Value& v, const value::Type& t) {
    struct Visitor {
        nlohmann::json operator()(int64_t x) { return x; }
        nlohmann::json operator()(double x) { return x; }
        nlohmann::json operator()(Time x) { return x.time_since_epoch().count(); }
        nlohmann::json operator()(Interval x) { return x.count(); }
        nlohmann::json operator()(bool x) { return x; }
        nlohmann::json operator()(const std::string& x) { return x; }
        nlohmann::json operator()(const Port& x) { return to_json(x); }
        nlohmann::json operator()(const Record& x) { return to_json(x); }
        nlohmann::json operator()(const Set& x) { return to_json(x); }
        nlohmann::json operator()(const Vector& x) { return to_json(x); }
        nlohmann::json operator()(std::monostate) { return {}; }
    };

    auto x = std::visit(Visitor(), static_cast<const Value::Base&>(v));
    std::cerr << x.dump() << std::endl;
    return x;
}

static Value from_json(const nlohmann::json& value, const value::Type& type) {
    if ( value.is_null() )
        return {std::monostate()};

    switch ( type ) {
        case value::Type::Bool: return value.get<bool>() != 0;
        case value::Type::Double: return value.get<double>();
        case value::Type::Interval: return Interval(value.get<int64_t>());
        case value::Type::Null: return {};
        case value::Type::Port: return from_json_port(value);
        case value::Type::Record: return from_json_record(value);
        case value::Type::Set: return from_json_set(value);
        case value::Type::Time: return Time(Interval(value.get<int64_t>()));
        case value::Type::Vector: return from_json_vector(value);

        case value::Type::Count:
        case value::Type::Integer: return value.get<int64_t>();

        case value::Type::Address:
        case value::Type::Blob:
        case value::Type::Text: return value.get<std::string>();
    };

    cannot_be_reached(); // thanks GCC
}

std::string zeek::agent::to_json_string(const Value& value, value::Type type) { return to_json(value, type).dump(); }

Value zeek::agent::from_json_string(const std::string_view& data, value::Type type) {
    try {
        auto json = nlohmann::json::parse(data);
        return from_json(json, type);
    } catch ( nlohmann::json::parse_error& e ) {
        // This should never happen, we only parse our own JSON.
        throw InternalError(format("JSON parse error: {}", e.what()));
    }
}

std::string zeek::agent::to_string(const std::vector<Value>& values) {
    return join(transform(values, [](const auto& x) { return to_string(x); }), " ");
}

std::string zeek::agent::to_string(const Port& v) {
    std::string_view proto;
    switch ( v.protocol ) {
        case port::Protocol::ICMP: proto = "icmp"; break;
        case port::Protocol::TCP: proto = "tcp"; break;
        case port::Protocol::UDP: proto = "udp"; break;
        case port::Protocol::Unknown: proto = "unknown"; break;
    };

    return format("{}/{}", v.port, proto);
}

std::string zeek::agent::to_string(const Record& v) {
    const std::vector<std::pair<Value, value::Type>>& base = v;
    return std::string("[") + join(transform(base, [](const auto& x) { return to_string(x.first); }), ", ") + "]";
}

std::string zeek::agent::to_string(const Set& v) {
    const std::set<Value>& base = v;
    return std::string("{") + join(transform(base, [](const auto& x) { return to_string(x); }), ", ") + "}";
}

std::string zeek::agent::to_string(const Vector& v) {
    const std::vector<Value>& base = v;
    return std::string("[") + join(transform(base, [](const auto& x) { return to_string(x); }), ", ") + "]";
}

std::optional<schema::Column> Schema::column(const std::string_view& name) {
    for ( const auto& c : columns ) {
        if ( name == c.name )
            return c;
    }

    return {};
}

std::string schema::Column::str() const { return format("{}: {}", name, type); }

std::string zeek::agent::to_string(const std::vector<schema::Column>& values) {
    return join(transform(values, [](const auto& x) { return zeek::agent::to_string(x); }), ", ");
}

std::string zeek::agent::table::to_string(const Argument& arg) {
    return format("{}={}", arg.column, ::zeek::agent::to_string(arg.expression));
}

std::vector<schema::Column> zeek::agent::Schema::parameters() const {
    std::vector<schema::Column> result;
    for ( auto c : columns ) {
        if ( c.is_parameter )
            result.push_back(std::move(c));
    }

    return result;
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

    for ( auto j = 0U; j < schema().columns.size(); j++ ) {
        Value v;
        switch ( schema().columns[j].type ) {
            case value::Type::Integer:
            case value::Type::Count: v = static_cast<int64_t>(100 * (i + 1) + j); break;
            case value::Type::Interval: v = to_interval(10 * (i + 1) + j); break;
            case value::Type::Blob: v = format("blob_{:c}_{:c}", ('a' + i % 65), ('a' + j % 65)); break;
            case value::Type::Bool: v = static_cast<bool>(i % 2); break;
            case value::Type::Double: v = static_cast<double>((i + 1) * 10 + ((j + 1) / 10.0)); break;
            case value::Type::Null: /* leave unset */ break;
            case value::Type::Text: v = format("text_{:c}_{:c}", ('a' + i % 65), ('a' + j % 65)); break;
            case value::Type::Time: v = to_time(1646252056 + 100 * (i + 1) + j); break;
            case value::Type::Address: v = format("192.168.1.{}", i % 255 + 1 + j); break;
            case value::Type::Port: v = Port(10000 * (i + 1) + j, static_cast<port::Protocol>(j % 4)); break;
            case value::Type::Record:
                v = Record({{static_cast<int64_t>(1000 * (i + 1) + j), value::Type::Count},
                            {static_cast<bool>(i % 2), value::Type::Bool},
                            {format("text_{:c}_{:c}", ('a' + i % 65), ('A' + j % 65)), value::Type::Text}});
            case value::Type::Set:
                v = Set(value::Type::Text, {format("elem_{:c}_{:c}", ('a' + i % 65), ('A' + j % 65)),
                                            format("elem_{:c}_{:c}", ('a' + i % 65), ('A' + j % 65)),
                                            format("lem_{:c}_{:c}", ('a' + i % 65), ('A' + j % 65))});
            case value::Type::Vector:
                v = Vector(value::Type::Text, {format("elem_{:c}_{:c}", ('a' + i % 65), ('M' + j % 65)),
                                               format("elem_{:c}_{:c}", ('a' + i % 65), ('N' + j % 65)),
                                               format("elem_{:c}_{:c}", ('a' + i % 65), ('R' + j % 65))});
        }

        row.push_back(std::move(v));
    }

    return row;
}

void Table::sqliteTrackStatement() {
    if ( ++_current_connections == 1 ) {
        ZEEK_AGENT_DEBUG("table", "activating table {}", name());

        if ( ! _use_mock_data )
            activate();
    }
}

void Table::sqliteUntrackStatement() {
    assert(_current_connections > 0);
    if ( --_current_connections == 0 ) {
        ZEEK_AGENT_DEBUG("table", "deactivating table {}", name());

        if ( ! _use_mock_data )
            deactivate();
    }
}

std::vector<std::vector<Value>> SnapshotTable::rows(Time t, const std::vector<table::Argument>& args) {
    // We ignore the given time in this method because snapshot() will always
    // be reflecting *now*, and *now* is must be older or equal to *now*, and
    // *now* is always larger or equal any valid t.

    if ( usesMockData() && name() != "zeek_agent" ) {
        std::vector<std::vector<Value>> result;

        result.reserve(5);
        for ( int i = 0; i < 5; i++ )
            result.push_back(generateMockRow(i));

        return result;
    }
    else
        return snapshot(args);
}

void EventTable::newEvent(std::vector<Value> row) {
    _events.emplace_back(Event{.time = currentTime(), .row = std::move(row)});
}

void EventTable::newEvent(Time t, std::vector<Value> row) {
    if ( ! _events.empty() && t < _events.back().time )
        throw InternalError("outdated timestamp in EventTable::newEvent()");

    _events.emplace_back(Event{.time = t, .row = std::move(row)});
}

std::vector<std::vector<Value>> EventTable::rows(Time t, const std::vector<table::Argument>& args) {
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
        TestBaseTable(std::string name) : name(std::move(std::move(name))) {}
        Schema schema() const override {
            return {.name = name, .columns = {schema::Column{.name = "x", .type = value::Type::Integer}}};
        }

        std::vector<std::vector<Value>> rows(Time t, const std::vector<table::Argument>& args) override { return {}; }

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

            std::vector<std::vector<Value>> snapshot(const std::vector<table::Argument>& args) override {
                return {{10L}, {20L}, {30L}, {40L}, {50L}};
            }

            using SnapshotTable::enableMockData;
        };

        TestTable t;

        SUBCASE("real data") {
            auto rows = t.rows(0_time, {});
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

        t.newEvent(1_time, {10L});
        t.newEvent(2_time, {20L});
        t.newEvent(2_time, {21L});
        t.newEvent(3_time, {30L});
        t.newEvent(4_time, {40L});
        t.newEvent(5_time, {50L});

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

    TEST_CASE("Record serialization") {
        Record v = {
            {"1.2.3.4", value::Type::Address},
            {"BLOB", value::Type::Blob},
            {true, value::Type::Bool},
            {42L, value::Type::Count},
            {3.14, value::Type::Double},
            {-42L, value::Type::Integer},
            {10s, value::Type::Interval},
            {Port(43L, port::Protocol::TCP), value::Type::Port},
            {{}, value::Type::Null},
            {"TEXT", value::Type::Text},
            {10_time, value::Type::Time},
            {Record{{1L, value::Type::Count}, {false, value::Type::Bool}}, value::Type::Record},
            {Set{value::Type::Count, {1L, 2L, 4L, 5L}}, value::Type::Set},
            {Vector{value::Type::Bool, {true, false, true}}, value::Type::Vector},
        };

        auto x = to_json_string(Value{v}, value::Type::Record);
        auto y = from_json_string(x, value::Type::Record);
        CHECK_EQ(y, Value(v));
        CHECK_EQ(to_string(y),
                 "[1.2.3.4, BLOB, true, 42, 3.14, -42, 10s, 43/tcp, (null), TEXT, 1970-01-01-00-00-10, [1, false], {1, "
                 "2, 4, 5}, [true, false, true]]");
    }
}
