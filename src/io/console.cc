// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "console.h"

#include "core/database.h"
#include "core/logger.h"
#include "core/signal.h"
#include "util/ascii-table.h"
#include "util/color.h"
#include "util/fmt.h"
#include "util/helpers.h"

#include <algorithm>
#include <condition_variable>
#include <csignal>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <replxx.hxx>

using namespace zeek::agent;

template<>
struct Pimpl<Console>::Implementation {
    // One time initialization from main thread.
    void init();

    // Main interactive loop running inside thread.
    void repl();

    // Executes a command or query.
    void execute(const std::string& cmd, bool terminate = false);

    // Performance a query against the database.
    void query(const std::string& stmt, std::optional<query::SubscriptionType> subscription, bool terminate = false);

    // Prints a message to the console.
    void message(const std::string& msg);

    // Prints an error to the console.
    void error(const std::string& msg);

    // Prints a query result to the console.
    void printResult(const query::Result& result, bool include_type);

    // Prints a liste of all tables.
    void printTables();

    // Prints the schema for a table.
    Result<Nothing> printSchema(const std::string& table);

    // Prints a help test to the console.
    void help();

    // Prints an initial welcome message to the console.
    void welcome();

    Database* _db = nullptr;              // as passed into constructor
    Scheduler* _scheduler = nullptr;      // as passed into constructor
    SignalManager* _signal_mgr = nullptr; // as passed into constructor

    std::string _scheduled_statement; // pre-scheduled statement

    std::map<std::string, Schema> _tables; // copy of table schema for thread-safety

    std::unique_ptr<std::thread> _thread;    // console's thread
    std::optional<query::ID> _current_query; // while a query is running, its ID
    std::mutex _query_done_mutex;            // mutex to flag when a query has been fully processed
    std::condition_variable _query_done_cv;  // condition variable to flag when a query has been fully processed
    replxx::Replxx _rx;                      // instance of the REPL
};

void Console::Implementation::init() {
    for ( auto t : _db->tables() )
        // Create a copy of the table schema while we are in the main thread.
        _tables.emplace(t->name(), t->schema());
}

void Console::Implementation::execute(const std::string& cmd, bool terminate) {
    ZEEK_AGENT_DEBUG("console", "executing: {}", cmd);

    auto check_terminate = [&]() {
        if ( terminate )
            _scheduler->terminate();
    };

    if ( cmd == ".tables" ) {
        printTables();
        check_terminate();
    }

    else if ( cmd == ".quit" || cmd == ".exit" )
        _scheduler->terminate();

    else if ( cmd == ".help" ) {
        help();
        check_terminate();
    }

    else if ( cmd.substr(0, 7) == ".diffs " )
        query(cmd.substr(7), query::SubscriptionType::Differences);

    else if ( cmd.substr(0, 21) == ".snapshot-plus-diffs " )
        query(cmd.substr(21), query::SubscriptionType::SnapshotPlusDifferences);

    else if ( cmd.substr(0, 8) == ".events " )
        query(cmd.substr(8), query::SubscriptionType::Events);

    else if ( cmd.substr(0, 8) == ".schema " ) {
        if ( auto m = split(trim(cmd.substr(8))); m.size() == 1 && ! m[0].empty() ) {
            if ( auto rc = printSchema(m[0]); ! rc )
                error(rc.error());
        }
        else
            error("cannot parse table name");

        check_terminate();
    }

    else if ( cmd.substr(0, 11) == ".snapshots " )
        query(cmd.substr(11), query::SubscriptionType::Snapshots);

    else if ( cmd[0] == '.' ) {
        error("unknown command");
        check_terminate();
    }

    else
        query(cmd, {}, terminate);
}

void Console::Implementation::repl() {
    // Runs in its own thread.
    auto history_path = platform::dataDirectory() / "history";
    _rx.history_load(history_path.string());

    welcome();

    while ( ! _scheduler->terminating() ) {
        auto raw_input = _rx.input(color::yellow("> "));
        if ( ! raw_input ) {
            if ( errno == EAGAIN )
                continue;

            // EOF -> exit
            raw_input = ".quit";
        }

        auto input = trim(raw_input);

        if ( input.empty() )
            continue;

        _rx.history_add(input);
        _rx.history_sync(history_path.string());

        execute(input, false);
    }
}

void Console::Implementation::printResult(const query::Result& result, bool include_type) {
    if ( result.columns.empty() )
        return;

    const bool include_header = result.initial_result;

    AsciiTable table;

    auto columns = transform(result.columns, [](const auto& c) { return c.name; });

    if ( include_type )
        columns.insert(columns.begin(), 1, "   ");

    table.addHeader(std::move(columns));

    for ( const auto& row : result.rows ) {
        auto values = transform(row.values, [](const auto& v) { return to_string(v); });

        if ( include_type ) {
            std::string prefix = "  ";
            if ( row.type ) {
                switch ( *row.type ) {
                    case query::result::ChangeType::Add: prefix = color::green(" + "); break;
                    case query::result::ChangeType::Delete: prefix = color::red(" - "); break;
                }
            }

            values.insert(values.begin(), 1, prefix);
        }

        table.addRow(std::move(values));
    }

    table.print(std::cout, include_header);
}

void Console::Implementation::printTables() {
    AsciiTable out;
    out.addHeader({"Name", "Description"});

    for ( const auto& [name, schema] : _tables )
        out.addRow({name, schema.summary});

    out.print(std::cout);
}

Result<Nothing> Console::Implementation::printSchema(const std::string& table) {
    auto t = _tables.find(table);
    if ( t == _tables.end() )
        return result::Error("no such table");

    AsciiTable out;
    out.addHeader({"Column", "Type", "Description"});

    bool has_parameters = false;
    for ( const auto& c : t->second.columns ) {
        if ( ! c.is_parameter )
            out.addRow({c.name, to_string(c.type), c.summary});
        else
            has_parameters = true;
    }

    std::cout << std::endl;
    out.print(std::cout);
    std::cout << std::endl;

    if ( has_parameters ) {
        AsciiTable out;
        out.addHeader({"Table Parameter", "Type", "Description"});

        for ( const auto& c : t->second.columns ) {
            if ( c.is_parameter )
                out.addRow({ltrim(c.name, "_"), to_string(c.type), c.summary});
        }

        out.print(std::cout);
        std::cout << std::endl;
    }

    return Nothing();
}

void Console::Implementation::query(const std::string& stmt, std::optional<query::SubscriptionType> subscription,
                                    bool terminate) {
    Query query = {.sql_stmt = stmt,
                   .subscription = subscription,
                   .schedule = 2s,
                   .terminate = terminate,
                   .cookie = "",
                   .callback_result =
                       [&](query::ID id, const query::Result& result) {
                           printResult(result, subscription && *subscription != query::SubscriptionType::Snapshots);

                           if ( subscription && *subscription == query::SubscriptionType::Snapshots )
                               std::cout << std::endl;
                       },
                   .callback_done =
                       [&](query::ID id, bool regular_shutdown) {
                           std::unique_lock<std::mutex> lock(_query_done_mutex);
                           _query_done_cv.notify_all();
                       }};

    std::unique_ptr<signal::Handler> sigint_handler;
    if ( ! terminate )
        // Temporarily install our our SIGINT handler while the query is running.
        sigint_handler = std::make_unique<signal::Handler>(_signal_mgr, SIGINT, [this]() {
            std::unique_lock<std::mutex> lock(_query_done_mutex);
            _query_done_cv.notify_all();
        });

    {
        std::unique_lock<std::mutex> lock(_query_done_mutex);

        _current_query.reset();

        _scheduler->schedule([this, query]() {
            std::unique_lock<std::mutex> lock(_query_done_mutex);

            if ( auto id = _db->query(query) )
                _current_query = *id;
            else {
                error(id.error());
                _query_done_cv.notify_all();
            }
        });

        _query_done_cv.wait(lock);

        if ( _current_query ) {
            // Move cancelling of query into main thread.
            auto id = *_current_query;
            _scheduler->schedule([this, id]() { _db->cancel(id); });
            _current_query.reset();
        }
    }

    std::cout << std::endl;
}

void Console::Implementation::message(const std::string& msg) { _rx.print("%s\n", msg.c_str()); }

void Console::Implementation::error(const std::string& msg) { _rx.print("error: %s\n", msg.c_str()); }

void Console::Implementation::welcome() {
    _rx.print(R"(
Welcome to Zeek Agent v2.

Enter query or command to execute. Type `.help` for help, and `.quit` for exit.

)");
}

void Console::Implementation::help() {
    _rx.print(R"(
Query

    Example: SELECT * FROM processes WHERE uid = 100

Commands

    .help                         display this help
    .quit                         terminate agent
    .diffs <query>                continously reschedule query, showing added or removed entries each time
    .snapshot-plus-diffs <query>  show initial snapshot, then continously reschedule query, showing added or removed entries each time
    .events <query>               continously reschedule query, showing new entries each time
    .schema <table>               display the schema for the given table
    .snapshots <query>            continously reschedule query, showing all entries each time
    .tables                       list available tables

)");
}

Console::Console(Database* db, Scheduler* scheduler, SignalManager* signal_mgr) {
    ZEEK_AGENT_DEBUG("console", "creating instance");
    pimpl()->_db = db;
    pimpl()->_scheduler = scheduler;
    pimpl()->_signal_mgr = signal_mgr;
}

Console::~Console() {
    ZEEK_AGENT_DEBUG("console", "destroying instance");
    stop();
}

void Console::scheduleStatementWithTermination(std::string stmt) { pimpl()->_scheduled_statement = std::move(stmt); }

void Console::start() {
    ZEEK_AGENT_DEBUG("console", "starting");

#ifdef HAVE_WINDOWS
    static const HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD flags;
    GetConsoleMode(handle, &flags);
    flags |= ENABLE_PROCESSED_OUTPUT;
    flags |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(handle, flags);
#endif

    pimpl()->init();

    pimpl()->_thread = std::make_unique<std::thread>([this]() {
        if ( pimpl()->_scheduled_statement.size() )
            pimpl()->execute(pimpl()->_scheduled_statement, true);
        else
            pimpl()->repl();
    });
}

void Console::stop() {
    if ( pimpl()->_thread ) {
        ZEEK_AGENT_DEBUG("console", "stopping");
        pimpl()->_query_done_cv.notify_all();
        pimpl()->_thread->join();
    }
}
