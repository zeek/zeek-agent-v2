// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#include "console.h"

#include "core/database.h"
#include "core/logger.h"
#include "core/signal.h"
#include "util/ascii-table.h"
#include "util/color.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/socket.h"
#include "util/testing.h"

#include <algorithm>
#include <condition_variable>
#include <csignal>
#include <list>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <replxx.hxx>

using namespace zeek::agent;

static const auto ProtocolVersion = "1";
static const auto MessageTerminator = "<<<>>>";

// Helpers sending output back to client.
static void sendEndOfMessage(socket::Remote& remote);
static void sendError(socket::Remote& remote, const std::string& msg);
static void sendHelp(socket::Remote& remote);
static void sendResult(socket::Remote& remote, const query::Result& result, bool include_type);
static void sendSchema(socket::Remote& remote, const Schema& schema);
static void sendTables(socket::Remote& remote, const std::map<std::string, Schema>& tables);
static void sendWelcome(socket::Remote& remote);

// State of worker thread serving an ongoing query.
struct PendingQuery {
    socket::Remote remote;                // remote console to send output to
    std::unique_ptr<std::thread> thread;  // worker thread serving query
    std::optional<query::ID> query_id;    // while a query is running, its ID
    std::mutex done_mutex;                // mutex to flag when a query has been fully processed
    std::condition_variable done_cv;      // condition variable to flag when a query has been fully processed
    std::atomic<bool> needs_join = false; // flag to server thread to clean up thread
};

template<>
struct Pimpl<ConsoleServer>::Implementation {
    // One time initialization from main thread.
    void init();

    // Clean up any state before destruction.
    void done();

    // Main loop for the console server running inside its own thread; will
    // block until terminated.
    void poll();

    // Executes a command/query entered on the console.
    void execute(socket::Remote remote, const std::string& cmd, bool terminate = false);

    // Performs a query against the database. This returns immediately after
    // spawning a worker thread performing the query.
    void query(const socket::Remote& remote, const std::string& stmt,
               std::optional<query::SubscriptionType> subscription, bool terminate = false);

    filesystem::path _socket_path;   // as passed into constructor
    Database* _db = nullptr;         // as passed into constructor
    Scheduler* _scheduler = nullptr; // as passed into constructor

    Socket _socket;                                            // IPC socket for communicating with console clients
    std::map<std::string, Schema> _tables;                     // copy of table schema for thread-safety
    std::unique_ptr<std::thread> _thread;                      // console's thread
    std::list<std::unique_ptr<PendingQuery>> _pending_queries; // queries waiting for results
};

void ConsoleServer::Implementation::init() {
    for ( auto t : _db->tables() )
        // Create a copy of the table schema while we are in the main thread.
        _tables.emplace(t->name(), t->schema());

    if ( auto rc = _socket.bind(_socket_path) )
        ZEEK_AGENT_DEBUG("console-server", "opened socket {}", _socket_path);
    else
        logger()->warn("console server: {}", rc.error());
}

void ConsoleServer::Implementation::done() {
    filesystem::remove(_socket_path);

    for ( auto& p : _pending_queries ) {
        p->done_cv.notify_all();
        p->thread->join();
    }

    _thread->join();
}

void ConsoleServer::Implementation::poll() {
    if ( ! _socket )
        return;

    ZEEK_AGENT_DEBUG("console-server", "reading from socket {}", _socket_path);

    while ( ! _scheduler->terminating() ) {
        auto result = _socket.read();
        if ( ! result ) {
            logger()->warn("console server: receive failed: {}", result.error());
            continue;
        }

        if ( ! result->has_value() )
            continue;

        auto msg = trim((*result)->first);
        auto remote = (*result)->second;

        if ( msg == MessageTerminator )
            break;

        ZEEK_AGENT_DEBUG("console-server", "received command: {}", msg);
        execute(remote, msg, false);

        // Clean up worker threads.
        auto i = _pending_queries.begin();
        while ( i != _pending_queries.end() ) {
            auto cur = i++;
            if ( (*cur)->needs_join ) {
                ZEEK_AGENT_DEBUG("console-server", "joining query worker thread");
                (*cur)->thread->join();
                _pending_queries.erase(cur);
            }
        }
    }

    ZEEK_AGENT_DEBUG("console-server", "done reading from socket {}", _socket_path);
}

void ConsoleServer::Implementation::execute(socket::Remote remote, const std::string& cmd, bool terminate) {
    // We perform anything that's quick synchronously inside the main console
    // server thread. For queries, we spawn a worker thread to serve them.
    if ( cmd == ".version" ) {
        remote << ProtocolVersion << std::endl;
        sendEndOfMessage(remote);
    }

    else if ( cmd == ".welcome" )
        sendWelcome(remote);

    else if ( cmd == ".tables" )
        sendTables(remote, _tables);

    else if ( cmd == ".help" )
        sendHelp(remote);

    else if ( cmd == ".terminate" )
        _scheduler->terminate();

    else if ( cmd.substr(0, 7) == ".diffs " )
        query(remote, cmd.substr(7), query::SubscriptionType::Differences);

    else if ( cmd.substr(0, 21) == ".snapshot-plus-diffs " )
        query(remote, cmd.substr(21), query::SubscriptionType::SnapshotPlusDifferences);

    else if ( cmd.substr(0, 8) == ".events " )
        query(remote, cmd.substr(8), query::SubscriptionType::Events);

    else if ( cmd.substr(0, 8) == ".schema " ) {
        if ( auto m = split(trim(cmd.substr(8))); m.size() == 1 && ! m[0].empty() ) {
            auto t = _tables.find(m[0]);
            if ( t != _tables.end() )
                sendSchema(remote, t->second);
            else
                sendError(remote, "no such table");
        }
        else
            sendError(remote, "cannot parse table name");
    }

    else if ( cmd.substr(0, 11) == ".snapshots " )
        query(remote, cmd.substr(11), query::SubscriptionType::Snapshots);

    else if ( cmd == ".ctrlc" ) {
        for ( auto& p : _pending_queries ) {
            if ( p->remote == remote )
                p->done_cv.notify_all();
        }
    }

    else if ( cmd[0] == '.' )
        sendError(remote, frmt("unknown command: {}", split(cmd).front()));

    else
        query(remote, cmd, {}, terminate);

    if ( auto err = remote.error() )
        logger()->warn("console send failed: {}", *err);
}

void ConsoleServer::Implementation::query(const socket::Remote& remote, const std::string& stmt,
                                          std::optional<query::SubscriptionType> subscription, bool terminate) {
    // We spawn a worker thread here to serve the query, and then return back to caller immediately.
    _pending_queries.emplace_back(std::make_unique<PendingQuery>());
    auto pending = _pending_queries.back().get();

    Query query = {.sql_stmt = stmt,
                   .subscription = subscription,
                   .schedule = 2s,
                   .terminate = terminate,
                   .cookie = "",

                   .callback_result =
                       [pending, subscription](query::ID id, const query::Result& result) {
                           sendResult(pending->remote, result,
                                      subscription && *subscription != query::SubscriptionType::Snapshots);

                           if ( subscription && *subscription == query::SubscriptionType::Snapshots )
                               pending->remote << std::endl;

                           if ( ! pending->remote )
                               // Cancel query on error.
                               pending->done_cv.notify_all();
                       },

                   .callback_done =
                       [pending](query::ID id, bool regular_shutdown) {
                           std::unique_lock<std::mutex> lock(pending->done_mutex);
                           pending->remote << std::endl;
                           sendEndOfMessage(pending->remote);
                           pending->done_cv.notify_all();
                       }};


    pending->remote = remote;
    pending->thread =
        std::make_unique<std::thread>([this, pending, query = std::move(query), scheduler = _scheduler]() {
            ZEEK_AGENT_DEBUG("console-server", "starting query worker thread");

            std::unique_lock<std::mutex> lock(pending->done_mutex);

            scheduler->schedule([this, pending, &query]() {
                std::unique_lock<std::mutex> lock(pending->done_mutex);

                if ( auto id = _db->query(query) )
                    pending->query_id = *id;

                else {
                    sendError(pending->remote, id.error());
                    pending->done_cv.notify_all();
                }
            });

            pending->done_cv.wait(lock);

            if ( auto err = pending->remote.error() )
                logger()->warn("console send failed: {}", *err);

            if ( pending->query_id ) {
                // Move canceling of query into main thread.
                auto id = *pending->query_id;
                scheduler->schedule([this, id]() { _db->cancel(id); });
                pending->query_id.reset();
            }

            pending->needs_join = true;
        });
}

ConsoleServer::ConsoleServer(const filesystem::path& socket_path, Database* db, Scheduler* scheduler) {
    ZEEK_AGENT_DEBUG("console-server", "creating instance");
    pimpl()->_socket_path = socket_path;
    pimpl()->_db = db;
    pimpl()->_scheduler = scheduler;
}

ConsoleServer::~ConsoleServer() {
    ZEEK_AGENT_DEBUG("console-server", "destroying instance");
    stop();
}

void ConsoleServer::start() {
    ZEEK_AGENT_DEBUG("console-server", "starting");

#ifdef HAVE_WINDOWS
    static const HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD flags;
    GetConsoleMode(handle, &flags);
    flags |= ENABLE_PROCESSED_OUTPUT;
    flags |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(handle, flags);
#endif

    pimpl()->init();
    pimpl()->_thread = std::make_unique<std::thread>([this]() { pimpl()->poll(); });
}

void ConsoleServer::stop() {
    if ( pimpl()->_thread ) {
        ZEEK_AGENT_DEBUG("console-server", "stopping");
        pimpl()->done();
    }
}

static void sendEndOfMessage(socket::Remote& remote) { remote << MessageTerminator << std::endl << std::flush; }

static void sendError(socket::Remote& remote, const std::string& msg) {
    remote << frmt("error: {}", msg) << std::endl;
    sendEndOfMessage(remote);
}

static void sendHelp(socket::Remote& remote) {
    remote << R"(
Query

    Example: SELECT * FROM processes WHERE uid = 100

Commands

    .help                         display this help
    .diffs <query>                continuously reschedule query, showing added or removed entries each time
    .snapshot-plus-diffs <query>  show initial snapshot, then continuously reschedule query, showing added or removed entries each time
    .events <query>               continuously reschedule query, showing new entries each time
    .schema <table>               display the schema for the given table
    .snapshots <query>            continuously reschedule query, showing all entries each time
    .tables                       list available tables
    .terminate                    terminate agent and quit console
    .exit                         quit console, but leave agent running
)" << std::endl;

    sendEndOfMessage(remote);
}

static void sendResult(socket::Remote& remote, const query::Result& result, bool include_type) {
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

    table.print(remote, include_header);
}

static void sendSchema(socket::Remote& remote, const Schema& schema) {
    AsciiTable out;
    out.addHeader({"Column", "Type", "Description"});

    bool has_parameters = false;
    for ( const auto& c : schema.columns ) {
        if ( ! c.is_parameter )
            out.addRow({c.name, to_string(c.type), c.summary});
        else
            has_parameters = true;
    }

    remote << std::endl;
    out.print(remote);
    remote << std::endl;

    if ( has_parameters ) {
        AsciiTable out;
        out.addHeader({"Table Parameter", "Type", "Description"});

        for ( const auto& c : schema.columns ) {
            if ( c.is_parameter )
                out.addRow({ltrim(c.name, "_"), to_string(c.type), c.summary});
        }

        out.print(remote);
        remote << std::endl;
    }

    sendEndOfMessage(remote);
}

static void sendTables(socket::Remote& remote, const std::map<std::string, Schema>& tables) {
    AsciiTable out;
    out.addHeader({"Name", "Description"});

    for ( const auto& [name, schema] : tables )
        out.addRow({name, schema.summary});

    out.print(remote);

    sendEndOfMessage(remote);
}

static void sendWelcome(socket::Remote& remote) {
    remote << R"(
Welcome to Zeek Agent v2.

Enter query or command to execute. Type `.help` for help, and `.quit` for exit.
)" << std::endl;

    sendEndOfMessage(remote);
}


/////////////////////////////////

template<>
struct Pimpl<ConsoleClient>::Implementation {
    // One time initialization from main thread.
    void init();

    // Clean up any state before destruction.
    void done();

    // Main interactive loop running inside thread; won't return until termination
    void repl();

    // Executes a command or query, returns output
    std::optional<std::string> execute(const std::string& cmd, bool echo = true);

    filesystem::path _socket_path;        // as passed into constructor
    Scheduler* _scheduler = nullptr;      // as passed into constructor
    SignalManager* _signal_mgr = nullptr; // as passed into constructor

    std::pair<std::string, bool>
        _scheduled_statement;                     // pre-scheduled statement; bool indicates if output is to be echoed
    std::optional<std::string> _scheduled_result; // output of pre-scheduled statement

    Socket _socket;                           // IPC socket for communicating with console server
    socket::Remote _remote;                   // remote console server for sending commands to
    std::unique_ptr<signal::Handler> _sigint; // custom CTRL-C handler while client is running
    std::unique_ptr<std::thread> _thread;     // console's thread
    replxx::Replxx _rx;                       // instance of the REPL
    std::atomic<int> _ctrlc = 0;              // number of times CTRL-C has been pressed during command execution
};

void ConsoleClient::Implementation::init() {
    filesystem::path client_socket = frmt("{}.client", _socket_path);
    if ( auto rc = _socket.bind(client_socket); ! rc ) {
        logger()->error("console client: {}", rc.error());
        return;
    }

    ZEEK_AGENT_DEBUG("console-client", "opened socket {}", client_socket);

    _remote = socket::Remote(&_socket, _socket_path);
    ZEEK_AGENT_DEBUG("console-client", "connected to remote socket {}", _socket_path);

    if ( _signal_mgr )
        _sigint = std::make_unique<signal::Handler>(_signal_mgr, SIGINT, [this]() {
            ++_ctrlc;
            _socket.write(".ctrlc\n", _remote);
        });
}

void ConsoleClient::Implementation::done() { _sigint.reset(); }

void ConsoleClient::Implementation::repl() {
    // Runs in its own thread.

    filesystem::path history_path;
    if ( auto dir = platform::dataDirectory() ) {
        history_path = *dir / "history";
        _rx.history_load(history_path.string());
    }

    ZEEK_AGENT_DEBUG("console-client", "reading from socket {}", _socket_path);

    execute(".version", false); // No version check for now, we only have one version.
    execute(".welcome");

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

        if ( ! history_path.empty() )
            _rx.history_sync(history_path.string());

        if ( trim(input) == ".quit" || trim(input) == ".exit" )
            return;

        execute(input);
    }

    ZEEK_AGENT_DEBUG("console-client", "done reading from socket {}", _socket_path);
}

std::optional<std::string> ConsoleClient::Implementation::execute(const std::string& cmd, bool echo) {
    ZEEK_AGENT_DEBUG("console-client", "sending command: {}", cmd);

    std::optional<std::string> output;

    _remote << cmd << std::endl;
    if ( auto err = _remote.error() )
        throw FatalError(frmt("failed to send command to server: {}", *err));

    _ctrlc = 0;
    while ( _ctrlc < 2 && ! _scheduler->terminating() ) {
        auto result = _socket.read();
        if ( ! result )
            throw FatalError(frmt("receive failed: {}", result.error()));

        if ( ! result->has_value() )
            continue;

        auto msg = trim((*result)->first);
        ZEEK_AGENT_DEBUG("console-client", "received output: {}", msg);

        if ( msg == MessageTerminator )
            break;

        if ( echo )
            _rx.print("%s", (*result)->first.c_str());

        if ( ! output )
            output = msg;
        else
            output->append(msg);
    }

    return output;
}

ConsoleClient::ConsoleClient(const filesystem::path& socket, Scheduler* scheduler, SignalManager* signal_mgr) {
    ZEEK_AGENT_DEBUG("console-client", "creating instance");
    pimpl()->_socket_path = socket;
    pimpl()->_scheduler = scheduler;
    pimpl()->_signal_mgr = signal_mgr;
}

ConsoleClient::~ConsoleClient() {
    ZEEK_AGENT_DEBUG("console-client", "destroying instance");
    stop();
}

void ConsoleClient::scheduleStatementWithTermination(std::string stmt, bool echo) {
    pimpl()->_scheduled_statement = {std::move(stmt), echo};
}

void ConsoleClient::start(bool run_repl) {
    ZEEK_AGENT_DEBUG("console-client", "starting");

#ifdef HAVE_WINDOWS
    static const HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD flags;
    GetConsoleMode(handle, &flags);
    flags |= ENABLE_PROCESSED_OUTPUT;
    flags |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(handle, flags);
#endif

    pimpl()->init();
    pimpl()->_thread = std::make_unique<std::thread>([this, run_repl]() {
        try {
            if ( pimpl()->_scheduled_statement.first.size() )
                pimpl()->_scheduled_result =
                    pimpl()->execute(pimpl()->_scheduled_statement.first, pimpl()->_scheduled_statement.second);
            else if ( run_repl )
                pimpl()->repl();
            else {
                ZEEK_AGENT_DEBUG("console-client", "not starting REPL - waiting until terminated");
                while ( ! pimpl()->_scheduler->terminating() )
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        } catch ( const FatalError& e ) {
            logger()->error("{}", e.what());
        } catch ( const InternalError& e ) {
            logger()->error("internal error: {}", e.what());
        }

        pimpl()->_scheduler->terminate();
    });
}

void ConsoleClient::stop() {
    if ( pimpl()->_thread ) {
        ZEEK_AGENT_DEBUG("console-client", "stopping");
        pimpl()->_thread->join();
    }

    pimpl()->done();
}

TEST_SUITE("console") {
    Configuration cfg;
    auto socket = filesystem::path(frmt("/tmp/zeek-agent-test-socket.{}", getpid()));

    TEST_CASE("client/server") {
        Scheduler scheduler;
        Database db(&cfg, &scheduler);

        ConsoleServer server(socket, &db, &scheduler);
        server.start();

        ConsoleClient client(socket, &scheduler, nullptr);
        client.start(false);

        CHECK_EQ(client.pimpl()->execute(".version", false), ProtocolVersion);
        scheduler.terminate();
    }

    TEST_CASE("pre-scheduled statement") {
        Scheduler scheduler;
        Database db(&cfg, &scheduler);

        ConsoleServer server(socket, &db, &scheduler);
        server.start();

        ConsoleClient client(socket, &scheduler, nullptr);
        client.scheduleStatementWithTermination(".version", false);
        client.start();

        while ( scheduler.loop() )
            std::this_thread::sleep_for(std::chrono::microseconds(100));

        REQUIRE(client.pimpl()->_scheduled_result);
        CHECK_EQ(*client.pimpl()->_scheduled_result, ProtocolVersion);
    }
}
