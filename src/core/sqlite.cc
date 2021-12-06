// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "core/sqlite.h"

#include "logger.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/testing.h"

#include <algorithm>
#include <list>
#include <map>
#include <utility>

#include <sqlite3.h>

using namespace zeek::agent;

namespace {
extern const ::sqlite3_module OurSqliteModule; // forward declaration; defind below
}

// Cookie data passed into the various SQLite callbacks.
struct Cookie {
    SQLite::Implementation* sqlite = nullptr;
    Table* table = nullptr;
};

// Our representation of the LHS of an SQLite WHERE constraint.
struct Constraint {
    std::string column; // column name
    table::Operator op; // operation
    int argv_index;     // index specifying how to access the corresponding value in the SQLite filter vector
};

// Captures one of our virtual tables.
struct VTab {
    struct ::sqlite3_vtab vtab;          // SQLite data structure for virtual table; must be 1st field
    struct Cookie cookie;                // Cookie for access by  SQLite callbacks
    std::vector<Constraint> constraints; // Set of WHERE constraints relevant during processing
};

// Captures the current position in a result set.
struct Cursor {
    struct ::sqlite3_vtab_cursor cursor;  // SQLite data structure for current cursor; must be first field
    struct Cookie cookie;                 // Cookie for access by SQLite callbacks
    struct VTab* vtab;                    // Links to virtual table cursor applies to
    Schema schema;                        // copy of the virtual tables schema (duplicated here for faster access)
    std::vector<std::vector<Value>> rows; // set of rows cursor iterates over
    size_t current = 0;                   // current cursor position in `rows`
};

template<>
struct Pimpl<SQLite>::Implementation {
    // Initializes SQLite backend.
    void open();

    // Shutsdown SQLIte backend.
    void close();

    // Registers table with the backend; does not take ownership
    Result<Nothing> addTable(Table* table);

    // Looks up a registered table by name.
    Table* table(const std::string& name);

    // Pre-compiles a statement.
    Result<std::unique_ptr<sqlite::PreparedStatement>> prepareStatement(std::string stmt);

    // Executes a statement.
    Result<sqlite::Result> runStatement(const std::string& stmt, Time t = 0_time);

    // Executes a precompiled statement.
    Result<sqlite::Result> runStatement(const sqlite::PreparedStatement& stmt, Time t = 0_time);

    ::sqlite3* _sqlite_db = nullptr;      // SQLite database handle
    std::list<Cookie> _cookies;           // list containing one cookie per registered table
    std::set<Table*> _stmt_tables;        // set of tables statement refers to; set during statement compilation
    std::optional<Time> _stmt_t = 0_time; // earliest time of interest during statement execution
    std::map<std::string, Table*> _tables_by_name; // map of registered tables indexed by their names

    mutable std::mutex _stmt_mutex; // lock acquired during statement execution to prevent concurrent processing
};

// Records error message in virtual table. Returns SQLITE_ERROR for convinient caller usage.
static int sqliteError(VTab* vtab, std::string msg) {
    if ( vtab->vtab.zErrMsg )
        ::sqlite3_free(vtab->vtab.zErrMsg);

    vtab->vtab.zErrMsg = ::sqlite3_mprintf("%s", msg.c_str());
    return SQLITE_ERROR;
}

// Converts a SQLite value into a corresponding table value.
static Result<Value> sqliteConvertValue(const std::string& name, ::sqlite3_value* v) {
    switch ( auto t = ::sqlite3_value_type(v) ) {
        case SQLITE_FLOAT: return {::sqlite3_value_double(v)};
        case SQLITE_INTEGER: return {static_cast<int64_t>(::sqlite3_value_int64(v))};
        case SQLITE_NULL: return {std::monostate{}};

        case SQLITE_BLOB: {
            auto data = reinterpret_cast<const char*>(::sqlite3_value_blob(v));
            auto size = ::sqlite3_value_bytes(v);
            return Value(std::string(data, size));
        }

        case SQLITE_TEXT: {
            auto data = reinterpret_cast<const char*>(::sqlite3_value_text(v));
            auto size = ::sqlite3_value_bytes(v);
            return Value(std::string(data, size));
        }

        default: return result::Error(format("invalid value type in statement response ({})", t));
    }
}

// Converts a SQLite type into a corresponding table value type.
static Result<value::Type> sqliteConvertType(const std::string& name, int type) {
    switch ( type ) {
        case SQLITE_BLOB: return value::Type::Blob;
        case SQLITE_FLOAT: return value::Type::Real;
        case SQLITE_INTEGER: return value::Type::Integer;
        case SQLITE_NULL: return value::Type::Null;
        case SQLITE_TEXT: return value::Type::Text;
        default: return result::Error(format("invalid value type in statement response ({})", type));
    }
}

// SQLite callback that leverages the "authorizer" APIto track which tables a
// statement accesses.
static int sqliteAuthorizer(void* user, int action, const char* arg3, const char* arg4, const char* arg5,
                            const char* arg6) {
    auto* impl = reinterpret_cast<Pimpl<SQLite>::Implementation*>(user);

    // actions and arguments: https://www.sqlite.org/c3ref/c_alter_table.html
    if ( action != SQLITE_READ )
        return SQLITE_OK;

    if ( auto t = impl->_tables_by_name.find(arg3); t != impl->_tables_by_name.end() ) {
        ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] authorizer: read for column {}", t->second->name(), arg4);
        impl->_stmt_tables.insert(t->second);
    }

    return SQLITE_OK;
}

// SQLite "connect" callback.
static int onTableConnect(::sqlite3* db, void* paux, int argc, const char* const* argv, ::sqlite3_vtab** ppvtab,
                          char** pzerr) {
    const auto* cookie = reinterpret_cast<const Cookie*>(paux);
    auto table_name = cookie->table->name();
    auto stmt = format("CREATE TABLE {} ({})", table_name,
                       join(transform(cookie->table->schema().columns,
                                      [&table_name](const auto& c) {
                                          std::string name = c.name + " ";

                                          switch ( c.type ) {
                                              case value::Type::Blob: return name + "INTEGER";
                                              case value::Type::Integer: return name + "INTEGER";
                                              case value::Type::Real: return name + "REAL";
                                              case value::Type::Text: return name + "TEXT";
                                              case value::Type::Null:
                                                  logger()->error(format("table {} uses NULL in schema", table_name));
                                                  return name + "NULL";
                                          }
                                          cannot_be_reached(); // thanks GCC
                                      }),
                            ", "));

    ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] connect: \"{}\"", cookie->table->name(), stmt);

    auto rc = ::sqlite3_declare_vtab(db, stmt.c_str());
    if ( rc != SQLITE_OK ) {
        logger()->error(format("creating table {} failed: {}", table_name, ::sqlite3_errmsg(db)));
        return rc;
    }

    auto vtab = new VTab;
    vtab->cookie = *cookie;
    *ppvtab = &vtab->vtab;

    return SQLITE_OK;
}

// SQLite "disconnect" callback.
static int onTableDisconnect(::sqlite3_vtab* pvtab) {
    auto vtab = reinterpret_cast<VTab*>(pvtab);
    auto cookie = &vtab->cookie;

    ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] disconnect", cookie->table->name());

    delete vtab;

    return SQLITE_OK;
}

// SQLite "bests index" callback.
static int onxBestIndexCallback(::sqlite3_vtab* pvtab, ::sqlite3_index_info* info) {
    auto vtab = reinterpret_cast<VTab*>(pvtab);
    auto cookie = &vtab->cookie;

    ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] best-index", cookie->table->name());

    // Track all constraints that the statement must provide.
    std::set<std::string> required_constraints;
    for ( const auto& c : cookie->table->schema().columns ) {
        if ( c.mandatory_constraint )
            required_constraints.insert(c.name);
    }

    if ( info->nConstraint > 0 ) {
        std::vector<Constraint> constraints;
        constraints.reserve(info->nConstraint);

        for ( auto i = 0; i < info->nConstraint; i++ ) {
            const auto& c = info->aConstraint[i];
            if ( ! c.usable )
                continue;

            if ( c.iColumn < 0 )
                // -1 for ROWID
                continue;

            auto column = cookie->table->schema().columns[c.iColumn];
            if ( ! column.mandatory_constraint ) {
                // Let SQLite handle this constraint.
                info->aConstraintUsage[i].argvIndex = 0;
                continue;
            }

            Constraint constraint;
            constraint.column = column.name;
            constraint.argv_index = constraints.size() + 1;

            info->aConstraintUsage[i].argvIndex =
                constraint.argv_index;             // pass expression value for this constraint to filter()
            info->aConstraintUsage[i].omit = true; // the table is in charge of filtering, not SQLite

            switch ( c.op ) {
                case SQLITE_INDEX_CONSTRAINT_EQ: constraint.op = table::Operator::Equal; break;
                case SQLITE_INDEX_CONSTRAINT_NE: constraint.op = table::Operator::Unequal; break;
                case SQLITE_INDEX_CONSTRAINT_GE: constraint.op = table::Operator::GreaterEqual; break;
                case SQLITE_INDEX_CONSTRAINT_LT: constraint.op = table::Operator::LowerThan; break;
                case SQLITE_INDEX_CONSTRAINT_GLOB: constraint.op = table::Operator::Glob; break;
                default: return sqliteError(vtab, format("unsupported WHERE operator ({})", c.op));
            }

            ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] - providing constraint: {} {} EXPR", cookie->table->name(),
                             constraint.column, to_string(constraint.op));

            required_constraints.erase(constraint.column);
            constraints.push_back(std::move(constraint));
        }

        vtab->constraints = std::move(constraints);
    }

    if ( required_constraints.size() )
        return sqliteError(vtab, format("missing WHERE constraint: {}", join(required_constraints, ", ")));

    return SQLITE_OK;
}

// SQLite "open" callback.
static int onTableOpen(::sqlite3_vtab* pvtab, ::sqlite3_vtab_cursor** ppcursor) {
    auto vtab = reinterpret_cast<VTab*>(pvtab);
    auto cookie = &vtab->cookie;

    ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] open", cookie->table->name());

    auto cursor = new Cursor;
    cursor->cookie = *cookie;
    cursor->vtab = vtab;
    cursor->schema = cookie->table->schema();
    *ppcursor = &cursor->cursor;

    return SQLITE_OK;
}

// SQLite "close" callback.
static int onTableClose(::sqlite3_vtab_cursor* pcursor) {
    const auto cursor = reinterpret_cast<Cursor*>(pcursor);
    auto cookie = &cursor->cookie;

    ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] close", cookie->table->name());

    delete cursor;

    return SQLITE_OK;
}

// SQLite "filter" callback.
static int onTableFilter(::sqlite3_vtab_cursor* pcursor, int idxnum, const char* idxstr, int argc,
                         ::sqlite3_value** argv) {
    const auto cursor = reinterpret_cast<Cursor*>(pcursor);
    auto cookie = &cursor->cookie;

    ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] filter", cookie->table->name());

    std::vector<table::Where> wheres;
    for ( const auto& c : cursor->vtab->constraints ) {
        auto expr = sqliteConvertValue(c.column, argv[c.argv_index - 1]);
        if ( ! expr )
            return sqliteError(cursor->vtab, "unsupported WHERE constraint");

        auto where = table::Where{.column = c.column, .op = c.op, .expression = std::move(*expr)};
        ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] - with constraint: {}", cookie->table->name(), to_string(where));
        wheres.push_back(std::move(where));
    }

    auto t = cookie->sqlite->_stmt_t;
    assert(t);
    cursor->rows = cookie->table->rows(*t, wheres);
    cursor->current = 0;

    // Double check that the returned rows match our schema.
    for ( const auto& row : cursor->rows ) {
        if ( row.size() != cursor->schema.columns.size() )
            return sqliteError(cursor->vtab, format("wrong row size returned by table {}", cookie->table->name()));

        for ( size_t i = 0; i < row.size(); i++ ) {
            auto is_correct = [](auto type, const auto& value) {
                if ( std::holds_alternative<std::monostate>(value) )
                    // Always ok to remain unset.
                    return true;

                switch ( type ) {
                    case value::Type::Integer: return std::holds_alternative<int64_t>(value);
                    case value::Type::Text: return std::holds_alternative<std::string>(value);
                    case value::Type::Blob: return std::holds_alternative<std::string>(value);
                    case value::Type::Real: return std::holds_alternative<double>(value);
                    case value::Type::Null: return std::holds_alternative<std::monostate>(value);
                }
                cannot_be_reached(); // thanks GCC
            }(cursor->schema.columns[i].type, row[i]);

            if ( ! is_correct )
                return sqliteError(cursor->vtab, format("unexpected value type at index {} in row returned by table {}",
                                                        i, cookie->table->name()));
        }
    }

    return SQLITE_OK;
}

// SQLite "next" callback.
static int onNext(::sqlite3_vtab_cursor* pcursor) {
    const auto cursor = reinterpret_cast<Cursor*>(pcursor);
    auto cookie = &cursor->cookie;

    ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] next", cookie->table->name());

    ++cursor->current;

    return SQLITE_OK;
}

// SQLite "eof" callback.
static int onEof(::sqlite3_vtab_cursor* pcursor) {
    const auto cursor = reinterpret_cast<Cursor*>(pcursor);
    auto cookie = &cursor->cookie;

    ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] eof?", cookie->table->name());

    return cursor->current < cursor->rows.size() ? 0 : 1;
}

// SQLite "column" callback.
static int onColumn(::sqlite3_vtab_cursor* pcursor, ::sqlite3_context* context, int i) {
    const auto cursor = reinterpret_cast<Cursor*>(pcursor);
    auto cookie = &cursor->cookie;

    ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] get-column {}", cookie->table->name(), i);

    assert(cursor->current < cursor->rows.size());
    assert(i >= 0 && i < static_cast<int>(cursor->rows[cursor->current].size()));

    auto type = cursor->schema.columns[i].type;
    const auto& value = cursor->rows[cursor->current][i];

    if ( std::holds_alternative<std::monostate>(value) ) {
        ::sqlite3_result_null(context);
        return SQLITE_OK;
    }

    switch ( type ) {
        case value::Type::Real: ::sqlite3_result_double(context, std::get<double>(value)); break;
        case value::Type::Integer: ::sqlite3_result_int64(context, std::get<int64_t>(value)); break;
        case value::Type::Null: ::sqlite3_result_null(context); break;

        case value::Type::Blob: {
            const auto& v = std::get<std::string>(value);
            ::sqlite3_result_blob(context, v.data(), v.size(), SQLITE_STATIC);
            break;
        }

        case value::Type::Text: {
            const auto& v = std::get<std::string>(value);
            ::sqlite3_result_text(context, v.data(), v.size(), SQLITE_STATIC);
            break;
        }
    }

    return SQLITE_OK;
}

// SQLite "rowid" callback.
static int onRowid(::sqlite3_vtab_cursor* pcursor, ::sqlite3_int64* prowid) {
    const auto cursor = reinterpret_cast<Cursor*>(pcursor);
    auto cookie = &cursor->cookie;

    ZEEK_AGENT_DEBUG("sqlite", "[{}] [callback] get-rowid", cookie->table->name());

    *prowid = static_cast<int64_t>(cursor->current) + 1;

    return SQLITE_OK;
}

namespace {

// Define a SQLite module defining our virtual tables, with all its
// callbacks.
const ::sqlite3_module OurSqliteModule = {3, // Version

                                          // Mandatory callbacks; enough to get read-only tables.
                                          &onTableConnect, &onTableConnect, &onxBestIndexCallback, &onTableDisconnect,
                                          &onTableDisconnect, &onTableOpen, &onTableClose, &onTableFilter, &onNext,
                                          &onEof, &onColumn, &onRowid,

                                          // Unused callbacks
                                          nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                          nullptr, nullptr, nullptr};

} // namespace


sqlite::PreparedStatement::PreparedStatement(::sqlite3_stmt* stmt, std::set<Table*> tables)
    : _statement(stmt), _tables(std::move(tables)) {
    assert(stmt);

    for ( const auto& t : _tables )
        t->sqliteTrackStatement();
}

::sqlite::PreparedStatement::~PreparedStatement() {
    ZEEK_AGENT_DEBUG("sqlite", "deleting compiled statement: \"{}\"", ::sqlite3_sql(_statement));
    ::sqlite3_finalize(_statement);

    for ( const auto& t : _tables )
        t->sqliteUntrackStatement();
};

void SQLite::Implementation::open() {
    if ( ::sqlite3_open(":memory:", &_sqlite_db) != SQLITE_OK )
        throw FatalError("failed to create the SQLite database");

    if ( ::sqlite3_set_authorizer(_sqlite_db, sqliteAuthorizer, this) != SQLITE_OK )
        throw FatalError("failed to set authorizer for the SQLite database");
}

void SQLite::Implementation::close() { ::sqlite3_close(_sqlite_db); }

Table* SQLite::Implementation::table(const std::string& name) {
    for ( auto i : _tables_by_name ) {
        if ( i.second->name() == name )
            return i.second;
    };

    return nullptr;
}

Result<Nothing> SQLite::Implementation::addTable(Table* table) {
    assert(_sqlite_db);

    _cookies.push_back(Cookie{.sqlite = this, .table = table});
    _tables_by_name[table->name()] = table;

    auto rc =
        ::sqlite3_create_module_v2(_sqlite_db, table->name().c_str(), &OurSqliteModule, &_cookies.back(), nullptr);
    if ( rc != SQLITE_OK )
        return result::Error(format("failed to create SQLite module for virtual table {}", table->name()));

    // Technically, we wouldn't even need to create the virtual table
    // explicitly because all our tables are "eponymous" (see
    // https://www.sqlite.org/vtab.html#eponymous_virtual_tables). However, we
    // do create them so that one can introspect them through "sqlite_schema".

    if ( this->table(table->name()) ) {
        auto result = runStatement(format("DROP TABLE {}", table->name()));
        if ( ! result )
            return result.error();
    }

    auto result = runStatement(format("CREATE VIRTUAL TABLE {} USING {}", table->name(), table->name()));
    if ( ! result )
        return result.error();

    return Nothing();
}

Result<std::unique_ptr<sqlite::PreparedStatement>> SQLite::Implementation::prepareStatement(std::string stmt) {
    ::sqlite3_stmt* prepared_stmt = nullptr;
    _stmt_tables.clear();
    auto rc = ::sqlite3_prepare_v2(_sqlite_db, stmt.data(), stmt.size(), &prepared_stmt, nullptr);
    if ( rc != SQLITE_OK )
        return result::Error(format("failed to compile SQL statement: {} ({})", stmt, ::sqlite3_errmsg(_sqlite_db)));

    ZEEK_AGENT_DEBUG("sqlite", "statement result will have {} columns", ::sqlite3_column_count(prepared_stmt));

    return std::unique_ptr<sqlite::PreparedStatement>(
        new sqlite::PreparedStatement(prepared_stmt, std::move(_stmt_tables)));
}

Result<sqlite::Result> SQLite::Implementation::runStatement(const sqlite::PreparedStatement& stmt, Time t) {
    // We take a lock here so that we know that no other statement can interleave
    // while we're processing the current one. That way, we can ensure that the
    // virtual table can ask us for the 't' time (there isn't any more direct
    // way to get that over unfortunately).
    std::scoped_lock<std::mutex> lock(_stmt_mutex);

    ScopeGuard reset_time([this]() { _stmt_t.reset(); });
    _stmt_t = t;

    sqlite::Result result;
    auto num_columns = ::sqlite3_column_count(stmt.statement());

    int rc;
    bool first_row = true;
    while ( (rc = ::sqlite3_step(stmt.statement())) == SQLITE_ROW ) {
        // Note: we can't precompute the columns, the types won't be valid before
        // we actually execute.
        for ( auto i = 0; i < num_columns; i++ ) {
            auto name = ::sqlite3_column_name(stmt.statement(), i);
            auto type = sqliteConvertType(name, ::sqlite3_column_type(stmt.statement(), i));
            if ( ! type )
                return type.error();

            if ( first_row )
                result.columns.push_back({.name = name, .type = *type});
            else {
                // The SQLite docs say: "For a given column, this value may
                // change from one result row to the next." That would be
                // deadly for us, let's see if it actually happens ...
                if ( result.columns[i].type != *type && result.columns[i].type != value::Type::Null &&
                     *type != value::Type::Null )
                    return result::Error("cell type unexpectedly changing between result rows");
            }
        }

        first_row = false;

        std::vector<Value> row;

        for ( auto i = 0; i < num_columns; i++ ) {
            auto v = sqliteConvertValue(::sqlite3_column_name(stmt.statement(), i),
                                        ::sqlite3_column_value(stmt.statement(), i));
            if ( ! v )
                return v.error();

            row.push_back(std::move(*v));
        }

        ZEEK_AGENT_DEBUG("sqlite", "statement result [{}]: {}", result.rows.size() + 1, to_string(row));
        result.rows.push_back(std::move(row));
    }

    switch ( rc ) {
        case SQLITE_DONE:
            ZEEK_AGENT_DEBUG("sqlite", "statement result has {} rows", result.rows.size());
            std::sort(result.rows.begin(), result.rows.end());
            return result;

        case SQLITE_ERROR: return result::Error(format("SQL statement failed, {}", ::sqlite3_errmsg(_sqlite_db)));
        case SQLITE_MISUSE: return result::Error("SQL statement returned misuse");
        default:
            return result::Error(format("SQL statement returned unexpected result, {}", ::sqlite3_errmsg(_sqlite_db)));
    }
}

Result<sqlite::Result> SQLite::Implementation::runStatement(const std::string& stmt, Time t) {
    auto prepared = prepareStatement(stmt);
    if ( ! prepared )
        return prepared.error();

    return runStatement(**prepared, t);
}

SQLite::SQLite() {
    ZEEK_AGENT_DEBUG("sqlite", "creating instance");
    pimpl()->open();
}

SQLite::~SQLite() {
    ZEEK_AGENT_DEBUG("sqlite", "destroying instance");
    pimpl()->close();
}

Result<std::unique_ptr<sqlite::PreparedStatement>> SQLite::prepareStatement(std::string stmt) {
    ZEEK_AGENT_DEBUG("sqlite", "preparing statement: \"{}\"", stmt);
    Synchronize _(this);
    return pimpl()->prepareStatement(stmt);
}

Result<sqlite::Result> SQLite::runStatement(const sqlite::PreparedStatement& stmt, Time t) {
    ZEEK_AGENT_DEBUG("sqlite", "executing compiled statement: \"{}\"", ::sqlite3_sql(stmt.statement()));
    assert(stmt.statement());

    Synchronize _(this);
    return pimpl()->runStatement(stmt, t);
}

Result<sqlite::Result> SQLite::runStatement(const std::string& stmt, Time t) {
    Synchronize _(this);
    ZEEK_AGENT_DEBUG("sqlite", "executing statement: \"{}\"", stmt);
    return pimpl()->runStatement(stmt, t);
}

Result<Nothing> SQLite::addTable(Table* table) {
    ZEEK_AGENT_DEBUG("sqlite", "{} table {}", (pimpl()->table(table->name()) ? "replacing" : "adding"), table->name());
    Synchronize _(this);
    return pimpl()->addTable(table);
}

TEST_SUITE("SQLite") {
    template<typename T>
    inline std::string str(const T& t) {
        using namespace table;
        return to_string(t);
    }

    TEST_CASE("statement with no tables") {
        SQLite sql;
        auto result = sql.runStatement("SELECT * FROM sqlite_schema");
        REQUIRE(result);
        CHECK_EQ(result->rows.size(), 0);
    }

    TEST_CASE("statement snapshot tables") {
        class TestTable1 : public SnapshotTable {
        public:
            Schema schema() const override {
                return {.name = "test_table1",
                        .columns = {{.name = "i1", .type = value::Type::Integer},
                                    {.name = "t1", .type = value::Type::Text}}};
            }

            virtual ~TestTable1() {}

            virtual void activate() override { active += 1; }
            virtual void deactivate() override { active -= 1; }

            std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override {
                int64_t counter = 0;
                std::vector<std::vector<Value>> x;
                x.push_back({{++counter}, {"foo"}});
                x.push_back({{++counter}, {"bar"}});
                x.push_back({{++counter}, {"foobar"}});

                if ( extend )
                    x.push_back({++counter, "extended"});

                return x;
            }

            bool extend = false;
            int active = 0;
        };

        class TestTable2 : public SnapshotTable {
        public:
            Schema schema() const override {
                return {.name = "test_table2",
                        .columns = {{.name = "i2", .type = value::Type::Integer},
                                    {.name = "t2", .type = value::Type::Text},
                                    {.name = "r2", .type = value::Type::Real},
                                    {.name = "b2", .type = value::Type::Blob}}};
            }

            virtual ~TestTable2() {}

            std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override {
                int64_t counter = 0;
                std::vector<std::vector<Value>> x;
                x.push_back({{++counter}, {"foo1"}, {3.14}, {"blobA"}});
                x.push_back({{++counter}, {"foo2"}, {4.14}, {"blobB"}});
                x.push_back({{++counter}, {"foo3"}, {5.14}, {"blobC"}});
                x.push_back({{++counter}, {"foo4"}, {6.14}, {"blobD"}});
                return x;
            }
        };

        TestTable1 t1;
        TestTable2 t2;
        SQLite sql;
        sql.addTable(&t1);
        sql.addTable(&t2);

        SUBCASE("table registration") {
            auto result = sql.runStatement("SELECT * FROM sqlite_schema");
            REQUIRE(result);
            for ( const auto& x : result->rows )
                logger()->info(to_string(x));
            CHECK_EQ(result->rows.size(), 2);
        }

        SUBCASE("broken statement") {
            auto rows = sql.runStatement("SELECT * FOO sqlite_schema");
            REQUIRE(! rows);
        }

        SUBCASE("statement all rows") {
            auto result = sql.runStatement("SELECT * FROM test_table1");
            REQUIRE(result);

            auto columns = result->columns;
            CHECK_EQ(columns.size(), 2);
            auto c = columns.begin();
            CHECK_EQ(c->name, "i1");
            CHECK_EQ(c->type, value::Type::Integer);
            ++c;
            CHECK_EQ(c->name, "t1");
            CHECK_EQ(c->type, value::Type::Text);

            CHECK_EQ(result->rows.size(), 3);
            CHECK_EQ(str(result->rows.at(0)), "1 foo");
            CHECK_EQ(str(result->rows.at(1)), "2 bar");
            CHECK_EQ(str(result->rows.at(2)), "3 foobar");
        }

        SUBCASE("statement selected rows") {
            auto result = sql.runStatement("SELECT * FROM test_table1 WHERE t1 LIKE 'foo%'");
            REQUIRE(result);
            CHECK_EQ(result->rows.size(), 2);
            CHECK_EQ(str(result->rows.at(0)), "1 foo");
            CHECK_EQ(str(result->rows.at(1)), "3 foobar");
        }

        SUBCASE("statement without matches") {
            auto result = sql.runStatement("SELECT * FROM test_table1 WHERE t1 LIKE 'XXXX'");
            REQUIRE(result);
            CHECK_EQ(result->rows.size(), 0);
        }

        SUBCASE("statement selected column") {
            auto result = sql.runStatement("SELECT t1 FROM test_table1 WHERE i1 == 1");
            REQUIRE(result);
            CHECK_EQ(result->rows.size(), 1);
            CHECK_EQ(str(result->rows.at(0)), "foo");
        }

        SUBCASE("statement with time") {
            // Time should just be ignored because snapshot tables always provide the state as of "now".
            auto result = sql.runStatement("SELECT * FROM test_table1", 10000000000000_time);
            REQUIRE(result);
            CHECK_EQ(result->rows.size(), 3);
        }

        SUBCASE("all data types") {
            auto result = sql.runStatement("SELECT * FROM test_table2 WHERE i2 == 1");
            REQUIRE(result);
            CHECK_EQ(result->rows.size(), 1);

            const auto& v = result->rows.at(0);
            CHECK_EQ(std::get<int64_t>(v[0]), 1);
            CHECK_EQ(std::get<std::string>(v[1]), "foo1");
            CHECK_EQ(std::get<double>(v[2]), 3.14);
            CHECK_EQ(std::get<std::string>(v[3]), "blobA");
        }

        SUBCASE("statement with join") {
            CHECK_EQ(t1.active, 0);
            auto statement = sql.prepareStatement(
                "SELECT t1, b2 FROM test_table1 JOIN test_table2 ON test_table1.i1 = test_table2.i2");
            REQUIRE(statement);
            CHECK_EQ((*statement)->tables().size(), 2);

            // order is undefined
            std::set<std::string> names;
            names.insert((*(*statement)->tables().begin())->name());
            names.insert((*++(*statement)->tables().begin())->name());

            CHECK(names.find("test_table1") != names.end());
            CHECK(names.find("test_table2") != names.end());

            auto result = sql.runStatement(**statement);
            REQUIRE(result);
            CHECK_EQ(result->rows.size(), 3);
            CHECK_EQ(str(result->rows.at(0)), "bar blobB");
        }

        SUBCASE("statement reuse") {
            auto statement = sql.prepareStatement("SELECT * from test_table1 WHERE i1 >= 3");
            REQUIRE(statement);
            CHECK_EQ((*statement)->tables().size(), 1);
            CHECK_EQ((*(*statement)->tables().begin())->name(), "test_table1");

            auto result = sql.runStatement(**statement);
            CHECK_EQ(result->rows.size(), 1);
            CHECK_EQ(str(result->rows.at(0)), "3 foobar");

            t1.extend = true;
            result = sql.runStatement(**statement);
            CHECK_EQ(result->rows.size(), 2);
            CHECK_EQ(str(result->rows.at(0)), "3 foobar");
            CHECK_EQ(str(result->rows.at(1)), "4 extended");
        }

        SUBCASE("activation") {
            CHECK_EQ(t1.active, 0);
            auto statement1 = sql.prepareStatement("SELECT * from test_table1");
            REQUIRE(statement1);
            CHECK_EQ((*statement1)->tables().size(), 1);
            CHECK_EQ((*(*statement1)->tables().begin())->name(), "test_table1");
            CHECK_EQ(t1.active, 1);

            auto statement2 = sql.prepareStatement("SELECT * from test_table1");
            REQUIRE(statement2);
            CHECK_EQ((*statement2)->tables().size(), 1);
            CHECK_EQ((*(*statement2)->tables().begin())->name(), "test_table1");
            CHECK_EQ(t1.active, 1);

            statement1 = {};
            CHECK_EQ(t1.active, 1);
            statement2 = {};
            CHECK_EQ(t1.active, 0);
        }
    }

    TEST_CASE("statement event tables") {
        class TestTable : public EventTable {
        public:
            virtual ~TestTable() {}

            Schema schema() const override {
                return {.name = "test_events",
                        .columns = {{.name = "time", .type = value::Type::Integer},
                                    {.name = "tag", .type = value::Type::Text}}};
            }

            using EventTable::newEvent; // make protected version accessible
        };

        TestTable table;
        SQLite sql;
        sql.addTable(&table);

        table.newEvent(10_time, {{10l}, {"foo_10"}});
        table.newEvent(20_time, {{20l}, {"foo_20"}});
        table.newEvent(30_time, {{30l}, {"foo_30"}});
        table.newEvent(40_time, {{40l}, {"foo_40"}});
        table.newEvent(50_time, {{50l}, {"foo_50"}});

        SUBCASE("table registration") {
            auto result = sql.runStatement("SELECT * FROM sqlite_schema");
            REQUIRE(result);
            CHECK_EQ(result->rows.size(), 1);
        }

        SUBCASE("statement all events") {
            auto result = sql.runStatement("SELECT * FROM test_events");
            REQUIRE(result);
            CHECK_EQ(result->rows.size(), 5);
            CHECK_EQ(str(result->rows.at(0)), "10 foo_10");
            CHECK_EQ(str(result->rows.at(1)), "20 foo_20");
            CHECK_EQ(str(result->rows.at(2)), "30 foo_30");
            CHECK_EQ(str(result->rows.at(3)), "40 foo_40");
            CHECK_EQ(str(result->rows.at(4)), "50 foo_50");
        }

        SUBCASE("statement events t T") {
            auto result = sql.runStatement("SELECT * FROM test_events", 30_time);
            REQUIRE(result);
            CHECK_EQ(result->rows.size(), 3);
            CHECK_EQ(str(result->rows.at(0)), "30 foo_30");
            CHECK_EQ(str(result->rows.at(1)), "40 foo_40");
            CHECK_EQ(str(result->rows.at(2)), "50 foo_50");
        }
    }

    TEST_CASE("statement with where constraints") {
        class TestTable : public SnapshotTable {
        public:
            Schema schema() const override {
                return {.name = "test_table",
                        .columns = {{.name = "i", .type = value::Type::Integer},
                                    {.name = "c", .type = value::Type::Text, .mandatory_constraint = true}}};
            }

            virtual ~TestTable() {}

            std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override {
                REQUIRE_EQ(wheres.size(), 1);

                auto where = wheres[0];
                CHECK_EQ(where.column, "c");

                auto val = std::get<std::string>(where.expression);
                std::vector<std::vector<Value>> x;
                x.push_back({{1l}, val});
                x.push_back({{2l}, val});
                x.push_back({{3l}, val});
                return x;
            }
        };

        TestTable t;
        SQLite sql;
        sql.addTable(&t);

        SUBCASE("prefilter with WHERE") {
            auto statement = sql.prepareStatement("SELECT * from test_table WHERE c == 'X'");
            REQUIRE(statement);

            auto result = sql.runStatement(**statement);
            REQUIRE(result);
            CHECK_EQ(result->rows.size(), 3);
            CHECK_EQ(str(result->rows.at(0)), "1 X");
            CHECK_EQ(str(result->rows.at(1)), "2 X");
            CHECK_EQ(str(result->rows.at(2)), "3 X");
        }

        SUBCASE("missing WHERE") {
            auto statement = sql.prepareStatement("SELECT * from test_table");
            REQUIRE(! statement);
        }
    }

    TEST_CASE("broken table implementation") {
        class BrokenTable : public SnapshotTable {
        public:
            BrokenTable(int error_type) : error_type(error_type) {}
            Schema schema() const override {
                return {.name = "broken_table",
                        .columns = {{.name = "i", .type = value::Type::Integer},
                                    {.name = "c", .type = value::Type::Text}}};
            }

            virtual ~BrokenTable() {}

            std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override {
                std::vector<std::vector<Value>> x;

                if ( error_type == 1 )
                    x.push_back({1l}); // missing column

                if ( error_type == 2 )
                    x.push_back({{1l}, {3.14}}); // wrong column type

                return x;
            }

            int error_type;
        };

        SUBCASE("wrong column number") {
            BrokenTable t(1);
            SQLite sql;
            sql.addTable(&t);
            auto result = sql.runStatement("SELECT * from broken_table");
            CHECK(! result);
            CHECK_EQ(result.error().description(),
                     "SQL statement failed, wrong row size returned by table broken_table");
        }

        SUBCASE("wrong column type") {
            BrokenTable t(2);
            SQLite sql;
            sql.addTable(&t);
            auto result = sql.runStatement("SELECT * from broken_table");
            CHECK(! result);
            CHECK_EQ(result.error().description(),
                     "SQL statement failed, unexpected value type at index 1 in row returned by table broken_table");
        }
    }
}
