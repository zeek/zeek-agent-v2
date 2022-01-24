// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "zeek.h"

#include "autogen/config.h"
#include "core/configuration.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/scheduler.h"
#include "core/table.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/platform.h"
#include "util/testing.h"

#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

#include "broker/fwd.hh"
#include <broker/endpoint.hh>
#include <broker/topic.hh>
#include <broker/zeek.hh>

// Helpers for debugging logging that include additional state.
#define ZEEK_INSTANCE_DEBUG(instance, ...)                                                                             \
    ZEEK_AGENT_DEBUG("zeek", format("[{}/{}] {}", endpoint(), instance, __VA_ARGS__))
#define ZEEK_CONN_DEBUG(...) ZEEK_AGENT_DEBUG("zeek", format("[{}] {}", endpoint(), __VA_ARGS__))
#define ZEEK_IO_DEBUG(...) ZEEK_AGENT_DEBUG("zeek", __VA_ARGS__)

using namespace zeek::agent;

// A query received from Zeek.
struct ZeekQuery {
    std::optional<std::string> zeek_instance; // ID of sending Zeek instances
    std::string zeek_id;                      // Zeek-side query ID
    std::string event_name;                   // Name of event to turn results into
    std::optional<std::string> zeek_cookie;   // Zeek-side cookie string to return with answers
    Query query;                              // database-side query
    std::optional<query::ID> query_id;        // database-side query ID once scheduled
};

// Manages the connection to one external Broker endpoint. Usually that's a
// Zeek, but it can an also be another process acting as a relay to Zeek
// instances not directly connected to the agent. Note that in the latter case,
// more than one Zeek instance may be visible on this connection. The class
// handles that correctly by tracking which Zeek instances it has seen (through
// their instance IDs that the Zeek-side agent framework creates)
class BrokerConnection : SynchronizedBase {
public:
    BrokerConnection(Database* db, Scheduler* scheduler) : _db(db), _scheduler(scheduler) {}
    ~BrokerConnection() { disconnect(); } // NOLINT(bugprone-exception-escape)

    // Establishes a Broker connection to `<host>[:<port>]`. Only reports fatal
    // errors, *not* including when the connection can't be established (it
    // will be continiously retried).
    Result<Nothing> connect(const std::string& destination);

    // Shutsdown current connection to Broker.
    void disconnect();

    // Performs periodic operations. Must be called reguarly from external.
    void poll();

private:
    void installQuery(ZeekQuery zquery);
    void cancelQuery(const std::string& zeek_id);
    void cancelAllQueries();
    const ZeekQuery* lookupQuery(const std::string& zeek_id);

    void removeZeekInstance(const std::string& zeek_instance);

    void processEvent(const broker::data_message& msg);
    void processError(const broker::error& err);
    void processStatus(const broker::status& status);

    void transmitResult(const std::string& zeek_id, const query::Result& result);
    void transmitError(const std::string& zeek_instance, const std::string& msg,
                       const std::optional<std::string>& zeek_id, const std::optional<std::string>& cookie);
    void transmitEvent(std::string event_name, broker::vector args,
                       const std::optional<std::string>& zeek_instance = {},
                       const std::optional<std::string>& zeek_id = {}, const std::optional<std::string>& cookie = {},
                       const std::optional<query::result::ChangeType>& change = {});

    void unexpectedEventArguments(const std::string& zeek_agent, broker::zeek::Event& ev);

    std::string endpoint() const {
        if ( _destination )
            return format("{}:{}", _destination->address, _destination->port);
        else
            return "<no dest>";
    }

    const auto& options() const { return _db->configuration().options(); }


    Database* _db = nullptr;                          // as passed into constructor
    Scheduler* _scheduler = nullptr;                  // as passed into constructor
    std::optional<broker::network_info> _destination; // parsed destination as passed into constructor

    // Broker state
    broker::endpoint _endpoint;
    std::optional<broker::subscriber> _subscriber;
    std::optional<broker::status_subscriber> _status_subscriber;

    std::map<std::string, ZeekQuery> _zeek_queries; // currently active queries
    std::map<std::string, Time> _zeek_instances;    // currently active Zeek instances, w/ last seen
};

Result<Nothing> BrokerConnection::connect(const std::string& destination) {
    Synchronize _(this);

    // Parse "host[:port]".
    std::string address;
    unsigned long port = 9999;

    try {
        auto m = split(trim(destination), ":");
        if ( m.empty() || m.size() > 2 )
            throw std::runtime_error("");

        address = trim(m[0]);
        if ( address.empty() )
            throw std::runtime_error("");

        if ( m.size() == 2 ) {
            port = std::stoul(m[1]);
            if ( port >= 65536 )
                throw std::out_of_range(""); // msg is ignored below
        }
    } catch ( ... ) {
        return result::Error(format("invalid Zeek address ({})", address));
    }

    std::vector<broker::topic> topics = {
        format("/zeek-agent/query/host/{}", options().agent_id),
        std::string(broker::topic::errors_str),   // internal topic to receive error messages
        std::string(broker::topic::statuses_str), // internal topic to receive status messages
    };

    auto groups = options().zeek_groups;
    groups.emplace_back("all");
    groups.push_back(tolower(platform::name()));

    for ( const auto& group : groups ) {
        topics.emplace_back(format("/zeek-agent/query/group/{}", group)); // group broadcast
        topics.emplace_back(
            format("/zeek-agent/query/group/{}/{}", options().agent_id, group)); // group msg to individual host
    }

    _endpoint.subscribe(
        topics, [](caf::unit_t&) { /* nop */ },
        [this](caf::unit_t&, const broker::data_message& msg) {
            if ( broker::get_topic(msg) == broker::topic::statuses_str ) {
                Synchronize _(this);
                auto x = broker::to<broker::status>(broker::get_data(msg));
                assert(x); // NOLINT(bugprone-lambda-function-name)
                processStatus(*x);
            }
            else if ( broker::get_topic(msg) == broker::topic::errors_str ) {
                Synchronize _(this);
                auto x = broker::to<broker::error>(broker::get_data(msg));
                assert(x); // NOLINT(bugprone-lambda-function-name)
                processError(*x);
            }
            else {
                Synchronize _(this);
                processEvent(msg);
            }
        },                                                  //
        [](caf::unit_t&, const caf::error&) { /* nop */ }); //

    _subscriber = _endpoint.make_subscriber(topics);
    _status_subscriber = _endpoint.make_status_subscriber(true);
    _destination =
        broker::network_info(address, port,
                             std::chrono::duration_cast<broker::timeout::seconds>(options().zeek_reconnect_interval));

    ZEEK_CONN_DEBUG("beginning to peer");
    for ( const auto& t : topics )
        ZEEK_CONN_DEBUG(format("  subscribing to: {}", t.string()));

    // Broker's peer_nosync() has not version taking netinfo directly
    _endpoint.peer_nosync(_destination->address, _destination->port, _destination->retry);
    return Nothing();
}

void BrokerConnection::disconnect() {
    Synchronize _(this);

    if ( ! _destination )
        return;

    cancelAllQueries();
    _zeek_instances.clear();
    _subscriber.reset();
    _status_subscriber.reset();

    ZEEK_CONN_DEBUG("unpeering");

    // Send out shutdown message. This is best effort, the event might not make
    // it out anymore. But the Zeek instances will eventually time out their
    // state if they don't hear from us anymore.
    transmitEvent("ZeekAgentAPI::agent_shutdown_v1", {});

    if ( ! _endpoint.unpeer(_destination->address, _destination->port) )
        logger()->warn(format("failed disconnect from {}", endpoint()));
}

void BrokerConnection::poll() {
    Synchronize _(this);

    // Expire any state from Zeek instances we haven't seen in a while.
    std::vector<std::string> to_remove;
    for ( const auto& z : _zeek_instances ) {
        if ( z.second + options().zeek_timeout < _scheduler->currentTime() )
            to_remove.emplace_back(z.first);
    }

    for ( const auto& id : to_remove ) {
        ZEEK_INSTANCE_DEBUG(id, "expiring Zeek instance");
        removeZeekInstance(id);
    }
}

void BrokerConnection::installQuery(ZeekQuery zquery) {
    auto zeek_id = zquery.zeek_id;
    if ( lookupQuery(zeek_id) )
        // Already installed.
        return;

    zquery.query.callback_result = [this, zeek_id](query::ID /* query_id */, const query::Result& result) {
        Synchronize _(this);
        transmitResult(zeek_id, result);
    };

    zquery.query.callback_done = [this, zeek_id](query::ID /* query_id */, bool /* cancelled */) {
        Synchronize _(this);
        ZEEK_CONN_DEBUG(format("database done with query {}, removing", zeek_id));
        _zeek_queries.erase(zeek_id);
    };

    if ( auto rc = _db->query(zquery.query) ) {
        zquery.query_id = *rc;
        _zeek_queries.emplace(zeek_id, std::move(zquery));
    }
    else if ( zquery.zeek_instance )
        // We don't log this as an error locally, but send it back to Zeek.
        transmitError(*zquery.zeek_instance, format("could not compile query ({})", rc.error()), zquery.zeek_id,
                      zquery.zeek_cookie);
}

void BrokerConnection::cancelQuery(const std::string& zeek_id) {
    auto i = _zeek_queries.find(zeek_id);
    if ( i == _zeek_queries.end() )
        // already gone
        return;

    assert(i->second.query_id);
    _db->cancel(*i->second.query_id);
    _zeek_queries.erase(i);
}

void BrokerConnection::removeZeekInstance(const std::string& zeek_instance) {
    auto z = _zeek_instances.find(zeek_instance);
    if ( z == _zeek_instances.end() )
        return;

    std::vector<std::string> to_delete;
    for ( const auto& q : _zeek_queries ) {
        if ( q.second.zeek_instance == zeek_instance )
            to_delete.emplace_back(q.first);
    }

    for ( const auto& id : to_delete )
        cancelQuery(id);

    _zeek_instances.erase(z);
}

void BrokerConnection::cancelAllQueries() {
    // Need to be careful with the iteration here because canceling a query
    // will trigger a callback that removes it from _zeek_queries.
    std::vector<query::ID> query_ids;

    for ( auto i : _zeek_queries ) {
        if ( i.second.query_id )
            query_ids.emplace_back(*i.second.query_id);
    }

    for ( auto i : query_ids )
        _db->cancel(i);

    _zeek_queries.clear();
}

void BrokerConnection::unexpectedEventArguments(const std::string& zeek_agent, broker::zeek::Event& ev) {
    ZEEK_INSTANCE_DEBUG(zeek_agent, format("ignoring event with unexpected argument types: {}{}", ev.name(),
                                           broker::to_string(ev.args())));
}

void BrokerConnection::processEvent(const broker::data_message& msg) {
    broker::zeek::Event event(std::get<1>(msg.data()));
    auto args = event.args();

    std::string zeek_instance;

    try {
        if ( args.empty() )
            throw std::runtime_error("argument error");

        zeek_instance = broker::get<std::string>(args[0]);

        if ( auto z = _zeek_instances.find(zeek_instance); z == _zeek_instances.end() ) {
            ZEEK_INSTANCE_DEBUG(zeek_instance, "new Zeek instance");
            _zeek_instances[zeek_instance] = _scheduler->currentTime();
        }
        else
            z->second = _scheduler->currentTime();

    } catch ( const std::exception& e ) {
        unexpectedEventArguments(zeek_instance, event);
        return;
    }

    ZEEK_INSTANCE_DEBUG(zeek_instance, format("got event: {}{}", event.name(), broker::to_string(event.args())));

    if ( event.name() == "ZeekAgentAPI::zeek_hello_v1" ) {
        // nothing to do
    }

    else if ( event.name() == "ZeekAgentAPI::zeek_shutdown_v1" ) {
        removeZeekInstance(zeek_instance);
    }

    else if ( event.name() == "ZeekAgentAPI::install_query_v1" ) {
        ZeekQuery zquery;

        try {
            if ( args.size() != 3 )
                throw std::runtime_error("argument error");

            auto zeek_id = broker::get<std::string>(args[1]);
            if ( lookupQuery(zeek_id) ) {
                ZEEK_INSTANCE_DEBUG(zeek_instance, format("ignoring already known query {}", zquery.zeek_id));
                return;
            }

            auto query_record = broker::get<broker::vector>(args[2]);
            if ( query_record.size() != 5 )
                throw std::runtime_error("argument error");

            auto sql_stmt = broker::get<std::string>(query_record[0]);

            Interval schedule_ = 0s;

            if ( query_record[1] != broker::data() )
                schedule_ = std::chrono::duration_cast<Interval>(broker::get<broker::timespan>(query_record[1]));

            std::optional<query::SubscriptionType> subscription;
            if ( query_record[2] != broker::data() ) {
                auto enum_ = broker::get<broker::enum_value>(query_record[2]);
                if ( enum_.name == "ZeekAgent::Snapshots" )
                    subscription = query::SubscriptionType::Snapshots;
                else if ( enum_.name == "ZeekAgent::Events" )
                    subscription = query::SubscriptionType::Events;
                else if ( enum_.name == "ZeekAgent::Differences" )
                    subscription = query::SubscriptionType::Differences;
                else
                    ZEEK_INSTANCE_DEBUG(zeek_instance,
                                        format("ignoring event with unknown subscription type: {}", enum_.name));
            }

            auto event_name = broker::get<std::string>(broker::get<broker::vector>(query_record[3])[0]);

            std::optional<std::string> cookie;

            if ( query_record[4] != broker::data() )
                cookie = broker::get<std::string>(query_record[4]);

            zquery = ZeekQuery{.zeek_instance = std::move(zeek_instance),
                               .zeek_id = zeek_id,
                               .event_name = std::move(event_name),
                               .zeek_cookie = cookie,
                               .query = Query{
                                   .sql_stmt = std::move(sql_stmt),
                                   .subscription = subscription,
                                   .schedule = schedule_,
                                   .terminate = false,
                                   .cookie = *cookie,
                               }};
        } catch ( const std::exception& e ) {
            unexpectedEventArguments(zeek_instance, event);
            return;
        }

        installQuery(std::move(zquery));
    }

    else if ( event.name() == "ZeekAgentAPI::cancel_query_v1" ) {
        std::string zeek_id;
        try {
            if ( args.size() != 2 )
                throw std::runtime_error("argument error");

            zeek_id = broker::get<std::string>(args[1]);
        } catch ( const std::exception& e ) {
            unexpectedEventArguments(zeek_instance, event);
            return;
        }

        if ( auto zquery = lookupQuery(zeek_id); zquery && zquery->query_id )
            _db->cancel(*zquery->query_id);
    }
}

void BrokerConnection::processError(const broker::error& err) {
#if 0
    std::string msg = "<no error message>";
    if ( err.message() )
        msg = *err.message();
#else
    const auto& msg = err.context().get_as<std::string>(1);
#endif

    logger()->warn("[{}] {}", endpoint(), msg);
}

void BrokerConnection::processStatus(const broker::status& status) {
    auto msg = (status.message() ? *status.message() : std::string("<no status description from broker>"));
    logger()->info(format("[{}] {}", endpoint(), msg));

    switch ( status.code() ) {
        case broker::sc::peer_added: {
            // Schedule repeated query sending agent hello.
            ZeekQuery hello = {.zeek_id = "agent_hello_" + randomUUID(), // unique ID for each query
                               .event_name = "ZeekAgentAPI::agent_hello_v1",
                               .query = Query{.sql_stmt = "SELECT * from zeek_agent",
                                              .subscription = query::SubscriptionType::Snapshots,
                                              .schedule = options().zeek_hello_interval}};

            installQuery(std::move(hello));
            break;
        }

        case broker::sc::peer_lost:
        case broker::sc::peer_removed:
            cancelAllQueries();
            _zeek_instances.clear();

            if ( options().terminate_on_disconnect )
                _scheduler->terminate();

            break;

        default: break; // ignore
    }
}

void BrokerConnection::transmitResult(const std::string& zeek_id, const query::Result& result) {
    if ( _endpoint.is_shutdown() || _endpoint.peers().empty() )
        // Nothing connected.
        return;

    auto zquery = lookupQuery(zeek_id);
    if ( ! zquery )
        // Cancelled in the meantime.
        return;

    for ( const auto& row : result.rows ) {
        std::vector<broker::data> columns;

        for ( auto i = 0U; i < result.columns.size(); i++ ) {
            broker::data value;
            switch ( result.columns[i].type ) {
                case value::Type::Blob:
                case value::Type::Text: value = std::get<std::string>(row.values[i]); break;
                case value::Type::Integer: value = std::get<int64_t>(row.values[i]); break;
                case value::Type::Null: value = broker::data(); break;
                case value::Type::Real: value = std::get<double>(row.values[i]); break;
            }

            columns.push_back(std::move(value));
        }

        transmitEvent(zquery->event_name, {{std::move(columns)}}, zquery->zeek_instance, zquery->zeek_id,
                      zquery->zeek_cookie, row.type);
    }
}

void BrokerConnection::transmitError(const std::string& zeek_instance, const std::string& msg,
                                     const std::optional<std::string>& zeek_id,
                                     const std::optional<std::string>& cookie) {
    ZEEK_INSTANCE_DEBUG(zeek_instance, format("error: {}", msg));
    transmitEvent("ZeekAgentAPI::agent_error_v1", {msg}, zeek_instance, zeek_id, cookie);
}

void BrokerConnection::transmitEvent(std::string event_name, broker::vector args,
                                     const std::optional<std::string>& zeek_instance,
                                     const std::optional<std::string>& zeek_id,
                                     const std::optional<std::string>& cookie,
                                     const std::optional<query::result::ChangeType>& change) {
    assert(! zeek_instance.has_value() || ! zeek_instance->empty());
    assert(! cookie.has_value() || ! cookie->empty());

    broker::data change_data;
    if ( change ) {
        switch ( *change ) {
            case query::result::ChangeType::Add: change_data = broker::enum_value("ZeekAgent::Add"); break;
            case query::result::ChangeType::Delete: change_data = broker::enum_value("ZeekAgent::Delete"); break;
        }
    }

    std::vector<broker::data> context;
    context.emplace_back(options().agent_id);
    context.emplace_back(static_cast<broker::timestamp>(std::chrono::system_clock::now()));
    context.emplace_back(zeek_id ? broker::data(*zeek_id) : broker::data());
    context.emplace_back(std::move(change_data));
    context.emplace_back(cookie ? broker::data(*cookie) : broker::data());

    args.insert(args.begin(), 1, std::move(context));
    broker::zeek::Event event(std::move(event_name), std::move(args));

    if ( zeek_instance ) {
        ZEEK_INSTANCE_DEBUG(*zeek_instance, format("sending event: {}{}", event.name(), to_string(event.args())));
        _endpoint.publish(format("/zeek-agent/response/{}/{}", *zeek_instance, options().agent_id), std::move(event));
    }
    else {
        ZEEK_INSTANCE_DEBUG("all", format("sending event: {}{}", event.name(), to_string(event.args())));
        _endpoint.publish(format("/zeek-agent/response/all/{}", options().agent_id), std::move(event));
    }
}

const ZeekQuery* BrokerConnection::lookupQuery(const std::string& zeek_id) {
    if ( auto i = _zeek_queries.find(zeek_id); i != _zeek_queries.end() )
        return &i->second;
    else
        return nullptr;
}

template<>
struct Pimpl<Zeek>::Implementation {
    // Starts communication with external Zeek instances.
    void start(const std::vector<std::string>& zeeks);

    // Terminates all Zeek communication.
    void stop();

    // Performs periodic operations. Must be called reguarly from external.
    void poll();

    Database* _db = nullptr;         // as passed into constructor
    Scheduler* _scheduler = nullptr; // as passed into constructor

    std::vector<std::unique_ptr<BrokerConnection>>
        _connections;      // one connection per desintation passed into constructor
    bool _stopped = false; // true once stop() can been executed
};

void Zeek::Implementation::start(const std::vector<std::string>& zeeks) {
    for ( const auto& z : zeeks ) {
        auto conn = std::make_unique<BrokerConnection>(_db, _scheduler);
        if ( auto rc = conn->connect(z) )
            _connections.push_back(std::move(conn));
        else
            logger()->error(rc.error());
    }
}

void Zeek::Implementation::stop() { _connections.clear(); }

void Zeek::Implementation::poll() {
    for ( const auto& c : _connections )
        c->poll();
}

Zeek::Zeek(Database* db, Scheduler* scheduler) {
    ZEEK_IO_DEBUG("creating instance");
    pimpl()->_db = db;
    pimpl()->_scheduler = scheduler;
}

Zeek::~Zeek() {
    ZEEK_IO_DEBUG("destroying instance");
    stop();
}

void Zeek::start(const std::vector<std::string>& zeeks) {
    ZEEK_IO_DEBUG("starting");
    Synchronize _(this);
    pimpl()->start(zeeks);
}

void Zeek::stop() {
    ZEEK_IO_DEBUG("stopping");
    Synchronize _(this);
    pimpl()->stop();
}

void Zeek::poll() {
    ZEEK_IO_DEBUG("polling");
    Synchronize _(this);
    pimpl()->poll();
}

TEST_SUITE("Zeek") {
    class TestTable : public SnapshotTable {
    public:
        TestTable() {}
        Schema schema() const override {
            return {.name = "test_table",
                    .columns = {{.name = "i", .type = value::Type::Integer},
                                {.name = "t", .type = value::Type::Text},
                                {.name = "r", .type = value::Type::Real},
                                {.name = "b", .type = value::Type::Blob}}};
        }

        ~TestTable() override {}

        std::vector<std::vector<Value>> snapshot(const std::vector<table::Where>& wheres) override {
            int64_t counter = 0;
            std::vector<std::vector<Value>> x;
            x.push_back({{++counter}, {"foo1"}, {3.14}, {"blobA"}});
            x.push_back({{++counter}, {"foo2"}, {4.14}, {"blobB"}});
            x.push_back({{++counter}, {"foo3"}, {5.14}, {"blobC"}});
            return x;
        }

        int64_t counter = 0;
    };

    TEST_CASE("connect/hello/disconnect/reconnect") {
        TestTable t;
        Configuration cfg;
        Scheduler tmgr;
        Database db(&cfg, &tmgr);
        auto agent_table = Database::findRegisteredTable("zeek_agent");
        db.addTable(agent_table);
        Zeek zeek(&db, &tmgr);

        // Shorten reconnect interval.
        std::stringstream options{"zeek_reconnect_interval = 1"};
        cfg.read(options, "-");

        broker::endpoint receiver;
        auto subscriber = receiver.make_subscriber({"/zeek-agent/response/"});
        auto status_subscriber = receiver.make_status_subscriber(true);
        auto port = receiver.listen("localhost");

        // Initiate connection.
        zeek.start({format("localhost:{}", port)});

        auto wait_for_connect_and_hello = [&]() {
            // Wait for agent connecting.
            auto x = status_subscriber.get();
            auto status = broker::get_if<broker::status>(x);
            CHECK_EQ(status->code(), broker::sc::peer_added);

            broker::zeek::Event hello{{}};
            do {
                // Wait for agent hello to arrive.
                auto time_ = 0_time;
                while ( ! subscriber.available() ) {
                    time_ += 10s;
                    tmgr.advance(time_);
                    std::this_thread::sleep_for(0.1s);
                }

                auto msg = subscriber.get();
                CHECK_EQ(get_topic(msg), broker::topic(format("/zeek-agent/response/all/{}", cfg.options().agent_id)));

                hello = broker::zeek::Event(broker::move_data(msg));
            } while ( hello.name() == "ZeekAgentAPI::agent_shutdown_v1" ); // ignore shutdown event

            CHECK_EQ(hello.name(), "ZeekAgentAPI::agent_hello_v1");
            CHECK_EQ(hello.args().size(), 2);                                  // context plus columns record
            CHECK_EQ(broker::get<broker::vector>(hello.args()[1]).size(), 13); // zeek_agent table has 12 columns

            return hello;
        };

        auto wait_for_disconnect = [&]() {
            // Wait for disconnect.
            auto x = status_subscriber.get();
            auto status = broker::get_if<broker::status>(x);

            bool is_disconnect =
                (status->code() == broker::sc::peer_lost) || (status->code() == broker::sc::peer_removed);
            CHECK(is_disconnect);
        };

        auto hello = wait_for_connect_and_hello();

        // Kill connection.
        for ( auto p : receiver.peers() ) {
            // GCC may report "p.peer.network->port" as potentially
            // uninitialized. Not under our control so ignore. Note that this
            // needs to work with clang-tidy too even when compiler is GCC.

#if ! defined(__has_warning) // Clang always has this
#define __suppress_warning
#elif __has_warning("-Wmaybe-uninitialized")
#define __suppress_warning
#endif

#ifdef __suppress_warning
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
            receiver.unpeer(p.peer.network->address, p.peer.network->port);
#ifdef __suppress_warning
#pragma GCC diagnostic pop
#undef __suppress_warning
#endif
        }

        wait_for_disconnect();

        auto hello2 = wait_for_connect_and_hello();
        CHECK_NE(broker::get<broker::vector>(hello.args()[0]).at(2),
                 broker::get<broker::vector>(hello2.args()[0]).at(2)); // must have different query ID

        // Tear connection down.
        zeek.stop();
        wait_for_disconnect();
    }
}
