// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "zeek.h"

#include "autogen/config.h"
#include "core/configuration.h"
#include "core/database.h"
#include "core/logger.h"
#include "core/scheduler.h"
#include "core/table.h"
#include "platform/platform.h"
#include "util/fmt.h"
#include "util/helpers.h"
#include "util/testing.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#ifndef HAVE_WINDOWS
#include <unistd.h>
#endif

#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXSocketTLSOptions.h>
#include <ixwebsocket/IXUserAgent.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketSendData.h>
#include <nlohmann/json.hpp>

#include <broker/address.hh>
#include <broker/configuration.hh>
#include <broker/data.hh>
#include <broker/endpoint.hh>
#include <broker/enum_value.hh>
#include <broker/fwd.hh>
#include <broker/none.hh>
#include <broker/topic.hh>
#include <broker/zeek.hh>

// Minimum version of the Zeek-side package that we require. If we see an agent
// with an older version, we'll stop communicating with it.
static const int64_t MininumZeekPackageVersion = 200020008;

// Helpers for debugging logging that include additional state.
#define ZEEK_INSTANCE_DEBUG(instance, ...)                                                                             \
    ZEEK_AGENT_DEBUG("zeek", "{}", frmt("[{}/{}] ", endpoint(), instance) + frmt(__VA_ARGS__))
#define ZEEK_CONN_DEBUG(...) ZEEK_AGENT_DEBUG("zeek", "{}", frmt("[{}] ", endpoint()) + frmt(__VA_ARGS__))
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

class ZeekConnection;

// Abstract base class encapsulating event exchange wity a Zeek endpoint,
// implementing connection setup/tear down and message encoding/decoding.
class TransportProtocol {
public:
    virtual ~TransportProtocol() {}

    // Establishes a connection to `<host>[:<port>]`. Only reports fatal
    // errors, *not* including when the connection can't be established (it
    // will be continiously retried).
    virtual void connect(const std::string& host, unsigned int port, const std::vector<std::string>& topics) = 0;

    // Shutsdown current connection.
    virtual void disconnect() = 0;

    // Sends an event to endpint.
    virtual void transmitEvent(const std::string& topic, const std::string& name, Record args) = 0;

    // Will be called regularly to perform periodic operations.
    virtual void poll(){};

    // Returns true if connection is currently down.
    virtual bool isShutdown() = 0;

    // Returns the default remote port to connect to if not specified otherwise.
    virtual unsigned int defaultPort() = 0;

    // Returns a name for the transport prototoc suitable for debug messages.
    virtual const char* name() const = 0;

    // Returns the connection associated with this transport protocol.
    auto connection() { return _connection; }

    // Returns the endpoint associated with this transport protocol.
    std::string endpoint() const;

    // Sets the connection associated with this transport protocol. To be used
    // by the connection itself to register itself with the transport.
    void setConnection(ZeekConnection* conn) { _connection = conn; }

private:
    ZeekConnection* _connection; // connection associated with this transport protocol
};

// Represents a change in connectivity with a Zeek endpoint.
enum class ConnectivityChange {
    Added,   // new connection setup
    Removed, // connection deliberately shut down
    Lost,    // connection unexpectedly terminated
    Other    // a change no further classified
};

// Manages the connection to one external Zeek endpoint. Usually that's
// actually a Zeek insteance, but it can an also be another process acting as a
// relay to Zeek instances not directly connected to the agent themselves. Note
// that in the latter case, more than one Zeek instance may be visible on this
// connection. The class handles that correctly by tracking which Zeek
// instances it has seen (through their instance IDs that the Zeek-side agent
// framework creates)
class ZeekConnection {
public:
    ZeekConnection(Database* db, Scheduler* scheduler) : _db(db), _scheduler(scheduler) {}

    ~ZeekConnection() {} // NOLINT(bugprone-exception-escape)

    void addTransport(std::unique_ptr<TransportProtocol> transport) {
        _transports.emplace_back(std::move(transport));
        _transports.back()->setConnection(this);
    }

    // Establishes a connection to `<host>[:<port>]`. Only reports fatal
    // errors, *not* including when the connection can't be established (it
    // will be continiously retried).
    Result<Nothing> connect(const std::string& destination);

    // Shutsdown current connection.
    void disconnect();

    // Performs periodic operations. Must be called reguarly from external.
    void poll();

protected:
    friend class TransportProtocol;
    friend class NativeBrokerTransport;
    friend class WebSocketTransport;

    // Callblack to signal that a transport was successful in establishign a
    // connection to an enpoint.
    void connectionEstablished(const TransportProtocol* transport, const std::string& address, unsigned int port);

    // Callback to signal that a connection attempt has failed.
    void connectionAttemptFailed(const TransportProtocol* transport, const std::string& reason = "");

    // Inject event from transport protocol.
    void processEvent(const std::string& name, const std::vector<Value>& args);

    // Report error from transport protocol.
    void processError(const std::string& msg);

    // Report connectivity change from transport protocol.
    void processConnectivityChange(const ConnectivityChange& status, const std::string& msg);

    // Returns human-readable representation of the current endpoint for log
    // messages.
    std::string endpoint() const {
        if ( _destination )
            return *_destination;
        else
            return "<no dest>";
    }

    const auto& configuration() const { return _db->configuration(); }
    const auto& options() const { return _db->configuration().options(); }
    const auto& scheduler() const { return _scheduler; }

private:
    void installQuery(ZeekQuery zquery);
    void cancelQuery(const std::string& zeek_id);
    void cancelAllQueries();
    const ZeekQuery* lookupQuery(const std::string& zeek_id);

    void removeZeekInstance(const std::string& zeek_instance);

    void transmitResult(const std::string& zeek_id, const query::Result& result);
    void transmitError(const std::string& zeek_instance, const std::string& msg,
                       const std::optional<std::string>& zeek_id, const std::optional<std::string>& cookie);
    void transmitEvent(const std::string& event_name, Record args, const std::optional<std::string>& zeek_instance = {},
                       const std::optional<std::string>& zeek_id = {}, const std::optional<std::string>& cookie = {},
                       const std::optional<query::result::ChangeType>& change = {});

    void unexpectedEventArguments(const std::string& zeek_agent, const std::string& name,
                                  const std::vector<Value>& args);


    std::vector<std::unique_ptr<TransportProtocol>> _transports; // as added through `addTranspor()`.
    std::set<const void*> _transports_failed;       // tracks which transports have reported failed attempts
    Database* _db = nullptr;                        // as passed into constructor
    Scheduler* _scheduler = nullptr;                // as passed into constructor
    std::map<std::string, ZeekQuery> _zeek_queries; // currently active queries

    // Zeek instance state
    struct ZeekInstance {
        Time last_seen = 0_time;               // last time we saw an event from this instance
        std::string version_string;            // Zeek version string, from instance's hello
        uint64_t version_number = 0;           // Zeek version number, from instance's hello
        std::string package_version = "<n/a>"; // Zeek agent package version, from instance's hello
        bool disabled = false;                 // If true, we won't send/process any activity to/from this agent

        bool operator==(const ZeekInstance& other) const {
            // Ignore last seen, we're interested only in semantic changes.
            return version_string == other.version_string && version_number == other.version_number &&
                   package_version == other.package_version;
        }

        bool operator!=(const ZeekInstance& other) const { return ! (*this == other); }
    };

    bool _transport_established = false; // set once we have at least once successful connection
    std::optional<std::string> _destination;
    std::map<std::string, ZeekInstance> _zeek_instances; // currently active Zeek instances
};

///// Native Broker transport.

// Transport implementation using the Broker library for communication.
class NativeBrokerTransport : public TransportProtocol {
public:
    NativeBrokerTransport(const zeek::agent::Configuration& config) : _config(config) {}
    ~NativeBrokerTransport() override {}

    void connect(const std::string& host, unsigned int port, const std::vector<std::string>& topics) override;
    void disconnect() override;
    bool isShutdown() override { return ! _endpoint || _endpoint->is_shutdown(); }
    unsigned int defaultPort() override { return 9998; /* default port used by the zeek-agent package  */ }
    void transmitEvent(const std::string& topic, const std::string& name, Record args) override;
    const char* name() const override { return "Broker"; }

private:
    // Helper to prepare Broker config object
    broker::configuration brokerConfig();

    void processEvent(const broker::data_message& msg);
    void processError(const broker::error& err);
    void processConnectivityChange(const broker::status& status);

    const zeek::agent::Configuration& _config;        // as passed into constructor
    std::unique_ptr<broker::endpoint> _endpoint;      // Broker state
    std::optional<broker::network_info> _destination; // parsed destination
};

static broker::data to_broker(const Value& v, const value::Type& t) {
    broker::data value;
    if ( std::get_if<std::monostate>(&v) == nullptr ) {
        switch ( t ) {
            case value::Type::Count: value = static_cast<uint64_t>(std::get<int64_t>(v)); break;
            case value::Type::Integer: value = std::get<int64_t>(v); break;
            case value::Type::Blob:
            case value::Type::Text: value = std::get<std::string>(v); break;
            case value::Type::Bool: value = (std::get<bool>(v) != 0); break;
            case value::Type::Double: value = std::get<double>(v); break;
            case value::Type::Enum: value = broker::enum_value(std::get<std::string>(v)); break;

            case value::Type::Interval:
                value = std::chrono::duration_cast<broker::timespan>(std::get<Interval>(v));
                break;

            case value::Type::Null: value = broker::data(); break;
            case value::Type::Time: value = broker::timestamp(std::get<Time>(v).time_since_epoch()); break;

            case value::Type::Address: {
                broker::address addr;
                if ( addr.convert_from(std::get<std::string>(v)) )
                    value = addr;
                break;
            }

            case value::Type::Port: {
                const auto& p = std::get<Port>(v);
                broker::port::protocol proto;
                switch ( p.protocol ) {
                    case port::Protocol::ICMP: proto = broker::port::protocol::icmp; break;
                    case port::Protocol::TCP: proto = broker::port::protocol::tcp; break;
                    case port::Protocol::UDP: proto = broker::port::protocol::udp; break;
                    case port::Protocol::Unknown: proto = broker::port::protocol::unknown; break;
                }

                value = broker::port(p.port, proto);
                break;
            }

            case value::Type::Record: {
                broker::vector br;
                for ( const auto& [x, t] : std::get<Record>(v) )
                    br.emplace_back(to_broker(x, t));

                value = std::move(br);
                break;
            }

            case value::Type::Set: {
                const auto& set = std::get<Set>(v);
                broker::set bs;
                for ( const auto& x : set )
                    bs.insert(to_broker(x, set.type));

                value = std::move(bs);
                break;
            }

            case value::Type::Vector: {
                const auto& vec = std::get<Vector>(v);
                broker::vector bv;
                for ( const auto& x : vec )
                    bv.emplace_back(to_broker(x, vec.type));

                value = std::move(bv);
                break;
            }
        }
    }

    return value;
}

// Best effort type guessing.
static std::pair<Value, value::Type> from_broker(const broker::data& v) {
    if ( auto x = broker::get_if<broker::none>(&v) )
        return {{}, value::Type::Null};

    if ( auto x = broker::get_if<broker::boolean>(&v) )
        return {*x, value::Type::Bool};

    if ( auto x = broker::get_if<broker::count>(&v) )
        return {static_cast<int64_t>(*x), value::Type::Count};

    if ( auto x = broker::get_if<broker::integer>(&v) )
        return {static_cast<int64_t>(*x), value::Type::Integer};

    if ( auto x = broker::get_if<broker::real>(&v) )
        return {*x, value::Type::Double};

    if ( auto x = broker::get_if<std::string>(&v) )
        return {*x, value::Type::Text};

    if ( auto x = broker::get_if<broker::enum_value>(&v) )
        return {x->name, value::Type::Enum};

    if ( auto x = broker::get_if<broker::set>(&v) ) {
        auto type = value::Type::Null;
        if ( ! x->empty() )
            type = from_broker(*x->begin()).second;

        Set y(type);
        for ( const auto& i : *x )
            y.insert(from_broker(i).first);

        return {y, value::Type::Set};
    }

    if ( auto x = broker::get_if<broker::vector>(&v) ) {
        // We can't distinguish vectors from records, but we only need the
        // latter right now ...
        Record y;
        for ( const auto& i : *x )
            y.emplace_back(from_broker(i));

        return {y, value::Type::Record};
    }

    if ( auto x = broker::get_if<broker::timespan>(&v) )
        return {std::chrono::duration_cast<Interval>(*x), value::Type::Interval};

    /* Not supported, don't need these.
     *
     * if ( auto x = broker::get_if<broker::address>(&v) )
     * else if ( auto x = broker::get_if<broker::subnet>(&v) )
     * else if ( auto x = broker::get_if<broker::port>(&v) )
     * else if ( auto x = broker::get_if<broker::table>(&v) )
     * else if ( auto x = broker::get_if<broker::timestamp>(&v) )
     */

    throw InternalError(frmt("unsupported Broker data type received ({})", broker::to_string(v)));
}

broker::configuration NativeBrokerTransport::brokerConfig() {
    const auto& options = _config.options();
    // Configure Broker/CAF for lower resource consumption.
    broker::broker_options broker_options;
    broker_options.forward = false;
    broker_options.ignore_broker_conf = true;
    broker_options.disable_ssl = options.zeek_ssl_disable;

    broker::configuration broker_config(broker_options);
    broker_config.openssl_cafile(options.zeek_ssl_cafile);
    broker_config.openssl_capath(options.zeek_ssl_capath);
    broker_config.openssl_certificate(options.zeek_ssl_certificate);
    broker_config.openssl_key(options.zeek_ssl_keyfile);
    broker_config.openssl_passphrase(options.zeek_ssl_passphrase);

#if 1
    broker_config.set("caf.scheduler.policy", "sharing");
    broker_config.set("caf.scheduler.max-threads", 1);
    broker_config.set("caf.middleman.workers", 0);
#else
    // Use Zeek's stealing configuration.
    broker_config.set("caf.work-stealing.moderate-sleep-duration", broker::timespan{16'000});
    broker_config.set("caf.work-stealing.relaxed-sleep-duration", broker::timespan{64'000});
    broker_config.set("caf.work-stealing.aggressive-poll-attempts", 5);
    broker_config.set("caf.work-stealing.moderate-poll-attempts", 5);
    broker_config.set("caf.work-stealing.aggressive-steal-interval", 4);
    broker_config.set("caf.work-stealing.moderate-steal-interval", 2);
    broker_config.set("caf.work-stealing.relaxed-steal-interval", 1);
#endif

    return broker_config;
}

void NativeBrokerTransport::connect(const std::string& host, unsigned int port,
                                    const std::vector<std::string>& topics) {
    auto broker_topics = transform(topics, [](const auto& t) { return broker::topic(t); });
    broker_topics.emplace_back(std::string(broker::topic::errors_str));
    broker_topics.emplace_back(std::string(broker::topic::statuses_str));

    _endpoint = std::make_unique<broker::endpoint>(brokerConfig());
    _endpoint->subscribe_nosync(
        std::move(broker_topics), []() { /* nop */ },
        [this](const broker::data_message& msg) {
            connection()->scheduler()->schedule([this, msg]() { // process message on the main thread
                if ( broker::get_topic(msg) == broker::topic::statuses_str ) {
                    auto x = broker::to<broker::status>(broker::get_data(msg));
                    assert(x); // NOLINT(bugprone-lambda-function-name)
                    processConnectivityChange(*x);
                }
                else if ( broker::get_topic(msg) == broker::topic::errors_str ) {
                    auto x = broker::to<broker::error>(broker::get_data(msg));
                    assert(x); // NOLINT(bugprone-lambda-function-name)
                    processError(*x);
                }
                else
                    processEvent(msg);
            });
        },
        [](const broker::error&) { /* nop */ });

    _destination = broker::network_info(host, port,
                                        std::chrono::duration_cast<broker::timeout::seconds>(
                                            _config.options().zeek_reconnect_interval));

    // Broker's peer_nosync() has not version taking netinfo directly
    _endpoint->peer_nosync(_destination->address, _destination->port, _destination->retry);
}

void NativeBrokerTransport::disconnect() {
    if ( ! _endpoint )
        return;

    if ( ! _endpoint->unpeer(_destination->address, _destination->port) )
        logger()->warn("failed disconnect from {}", connection()->endpoint());

    _endpoint->shutdown();
    _endpoint = nullptr;
}

void NativeBrokerTransport::transmitEvent(const std::string& topic, const std::string& event_name, Record args) {
    if ( ! _endpoint )
        return;

    broker::zeek::Event event(event_name, broker::get<broker::vector>(to_broker(std::move(args), value::Type::Record)));
    _endpoint->publish(topic, std::move(event));
}

void NativeBrokerTransport::processEvent(const broker::data_message& msg) {
    broker::zeek::Event event(std::get<1>(msg.data()));

    std::vector<Value> args;
    for ( const auto& a : event.args() )
        args.push_back(from_broker(a).first);

    connection()->processEvent(event.name(), args);
}

void NativeBrokerTransport::processError(const broker::error& err) {
    std::string msg = "<no error message>";
    if ( err.message() )
        msg = *err.message();

    switch ( static_cast<broker::ec>(err.code()) ) {
        // Prettyify some common errors.
        case broker::ec::peer_invalid:
        case broker::ec::peer_unavailable:
            logger()->debug("cannot connect to Zeek endpoint via Broker at {}", connection()->endpoint());
            connection()->connectionAttemptFailed(this, msg);
            break;

        default: connection()->processError(frmt("{} for {}", msg, connection()->endpoint()));
    }
}

void NativeBrokerTransport::processConnectivityChange(const broker::status& status) {
    ConnectivityChange change = ConnectivityChange::Other;
    auto msg = (status.message() ? *status.message() : std::string("<no status description from broker>"));

    switch ( static_cast<broker::sc>(status.code()) ) {
        // Prettyify some common messages.
        case broker::sc::peer_added:
            connection()->connectionEstablished(this, _destination.value().address, _destination.value().port);
            change = ConnectivityChange::Added;
            msg = frmt("connected to Zeek endpoint at {}", connection()->endpoint());
            break;
        case broker::sc::peer_lost:
            change = ConnectivityChange::Lost;
            msg = frmt("lost connection to Zeek endpoint at {}", connection()->endpoint());
            break;
        case broker::sc::peer_removed:
            change = ConnectivityChange::Removed;
            msg = frmt("disconnected from Zeek endpoint at {}", connection()->endpoint());
            break;
        default: break;
    }

    connection()->processConnectivityChange(change, msg);
}

///// WebSocket transport.

// Transport implementation using the Broker library for communication.
class WebSocketTransport : public TransportProtocol {
public:
    WebSocketTransport(const zeek::agent::Configuration& config) : _config(config) {}
    ~WebSocketTransport() override {}

    void connect(const std::string& host, unsigned int port, const std::vector<std::string>& topics) override;
    void disconnect() override;
    bool isShutdown() override { return ! (_connected && _socket.getReadyState() == ix::ReadyState::Open); }
    unsigned int defaultPort() override { return 9997; /* Zeek's default WebSocket port */ }
    void transmitEvent(const std::string& topic, const std::string& name, Record args) override;
    void poll() override;
    const char* name() const override { return "WebSocket"; }

private:
    void tryReconnect(); // backend for both connect() and reconnection logic

    const zeek::agent::Configuration& _config; // as passed into constructor
    std::string _host;                         // address trying to connect to
    unsigned int _port;                        // port trying to connect to

    ix::WebSocket _socket;
    bool _connected = false;
    std::optional<Time> _last_connect_attempt;
};

static nlohmann::json to_json(const Value& v, const value::Type& t) {
    nlohmann::json value;
    std::string type;

    if ( std::get_if<std::monostate>(&v) == nullptr ) {
        switch ( t ) {
            case value::Type::Count:
                type = "count";
                value = std::get<int64_t>(v);
                break;

            case value::Type::Integer:
                type = "integer";
                value = std::get<int64_t>(v);
                break;

            case value::Type::Blob:
            case value::Type::Text:
                type = "string";
                value = std::get<std::string>(v);
                break;

            case value::Type::Bool:
                type = "boolean";
                value = (std::get<bool>(v) != 0);
                break;

            case value::Type::Double:
                type = "real";
                value = std::get<double>(v);
                break;

            case value::Type::Enum:
                type = "enum-value";
                value = std::get<std::string>(v);
                break;

            case value::Type::Interval:
                type = "timespan";
                value = to_string(std::get<Interval>(v));
                break;

            case value::Type::Null:
                type = "none";
                value = nlohmann::json::object();
                break;

            case value::Type::Time: {
                type = "timestamp";
                auto s = to_string_iso(std::get<Time>(v));
                if ( auto x = s.find('+'); x != std::string::npos ) // TODO: Broker doesn't like timezones added
                    s = s.substr(0, x);
                value = s + ".000"; // TODO: Broker requires postfix
                break;
            }

            case value::Type::Address: {
                type = "address";
                value = std::get<std::string>(v);
                break;
            }

            case value::Type::Port: {
                const auto& p = std::get<Port>(v);
                broker::port::protocol proto;
                switch ( p.protocol ) {
                    case port::Protocol::ICMP: proto = broker::port::protocol::icmp; break;
                    case port::Protocol::TCP: proto = broker::port::protocol::tcp; break;
                    case port::Protocol::UDP: proto = broker::port::protocol::udp; break;
                    case port::Protocol::Unknown: proto = broker::port::protocol::unknown; break;
                }

                type = "port";
                value = frmt("{}/{}", p.port, proto);
                break;
            }

            case value::Type::Record: {
                std::vector<nlohmann::json> j;
                for ( const auto& [x, t] : std::get<Record>(v) )
                    j.emplace_back(to_json(x, t));

                type = "vector";
                value = std::move(j);
                break;
            }

            case value::Type::Set: {
                std::vector<nlohmann::json> j;
                for ( const auto& x : std::get<Set>(v) )
                    j.emplace_back(to_json(x, std::get<Set>(v).type));

                type = "set";
                value = std::move(j);
                break;
            }

            case value::Type::Vector: {
                std::vector<nlohmann::json> j;
                for ( const auto& x : std::get<Vector>(v) )
                    j.emplace_back(to_json(x, std::get<Vector>(v).type));

                type = "vector";
                value = std::move(j);
                break;
            }
        }
    }
    else {
        type = "none";
        value = nlohmann::json::object();
    }

    nlohmann::json json;
    json["@data-type"] = type;
    json["data"] = value;
    return json;
}

// Best effort type guessing.
static std::pair<Value, value::Type> from_json(const nlohmann::json& json) {
    const auto& type = json["@data-type"];
    const auto& value = json["data"];

    if ( type == "integer" )
        return {value.get<int64_t>(), value::Type::Integer};

    if ( type == "count" )
        return {value.get<int64_t>(), value::Type::Count};

    if ( type == "bool" )
        return {value.get<bool>(), value::Type::Bool};

    if ( type == "real" )
        return {value.get<double>(), value::Type::Double};

    if ( type == "string" )
        return {value.get<std::string>(), value::Type::Text};

    if ( type == "enum-value" )
        return {value.get<std::string>(), value::Type::Enum};

    if ( type == "none" )
        return {{}, value::Type::Null};

    if ( type == "set" ) {
        auto type = value::Type::Null;

        std::set<Value> x;
        for ( const auto& i : value ) {
            auto m = from_json(i);
            x.insert(m.first);
            type = m.second;
        }

        return {Set(type, std::move(x)), value::Type::Set};
    }

    if ( type == "vector" ) {
        // We can't distinguish vectors from records, but we only need the
        // latter right now ...
        Record y;
        for ( const auto& i : value )
            y.emplace_back(from_json(i));

        return {y, value::Type::Record};
    }

    if ( type == "timespan" )
        return {to_interval_from_secs(std::stoi(value.get<std::string>())), value::Type::Interval};

    if ( type == "timestamp" ) {
        std::tm tm = {};
        std::istringstream ss(value.get<std::string>());
        ss >> std::get_time(&tm, "%FT%T");
        auto tp = std::chrono::system_clock::from_time_t(std::mktime(&tm));
        return {tp, value::Type::Time};
    }

    /* Not supported, don't need these.
     *
     * if ( auto x = broker::get_if<broker::address>(&v) )
     * else if ( auto x = broker::get_if<broker::subnet>(&v) )
     * else if ( auto x = broker::get_if<broker::port>(&v) )
     * else if ( auto x = broker::get_if<broker::table>(&v) )
     * else if ( auto x = broker::get_if<broker::timestamp>(&v) )
     */

    throw InternalError(frmt("unsupported data type received over WebSocket ({})", type));
}

void WebSocketTransport::connect(const std::string& host, unsigned int port, const std::vector<std::string>& topics) {
    const auto& options = connection()->options();

    auto url = frmt("{}://{}:{}/v1/messages/json", (options.zeek_ssl_disable ? "ws" : "wss"), host, port);

    _socket.setUrl(url);
    _socket.setPingInterval(30);
    _socket.enablePong();
    _socket.enablePerMessageDeflate();
    _host = host;
    _port = port;

    if ( ! connection()->options().zeek_ssl_disable ) {
        ix::SocketTLSOptions tls_options;
        tls_options.tls = true;
        tls_options.disable_hostname_validation = true; // with Zeek, we generally don't validate hostnames

        const auto auth_disabled = (options.zeek_ssl_certificate.empty() && options.zeek_ssl_keyfile.empty() &&
                                    options.zeek_ssl_cafile.empty() && options.zeek_ssl_capath.empty());

        if ( ! auth_disabled ) {
            if ( ! options.zeek_ssl_certificate.empty() )
                tls_options.certFile = options.zeek_ssl_certificate;

            if ( ! options.zeek_ssl_keyfile.empty() )
                tls_options.keyFile = options.zeek_ssl_keyfile;

            if ( ! options.zeek_ssl_cafile.empty() )
                tls_options.caFile = options.zeek_ssl_cafile;
            else
                tls_options.caFile = "SYSTEM";

            if ( ! options.zeek_ssl_capath.empty() )
                logger()->warn("option zeek.ssl_cpath not supported for WebSocket connections, ignoring");
        }

        else {
            // Enable encryption, but don't require authentication (and not even certificates).
            tls_options.caFile = "NONE";
            // Use a cipher that don't need a certificate; this list is
            // borrowed from Broker, including ciphers that works with
            // different OpenSSL versions
            tls_options.ciphers = "AECDH-AES256-SHA@SECLEVEL=0:AECDH-AES256-SHA:P-384";
        }

        _socket.setTLSOptions(tls_options);
    }

    // We implement our own auto-connect, too difficult to control otherwise.
    _socket.disableAutomaticReconnection();

    _socket.setOnMessageCallback([this, topics](const ix::WebSocketMessagePtr& msg) {
        auto msg_type = msg->type;
        auto msg_str = msg->str;
        auto msg_error_reason = msg->errorInfo.reason;

        connection()->scheduler()->schedule([this, topics, msg_type, msg_str,
                                             msg_error_reason]() { // process message on the main thread
            switch ( msg_type ) {
                case ix::WebSocketMessageType::Open: {
                    connection()->connectionEstablished(this, _host, _port);
                    connection()->processConnectivityChange(ConnectivityChange::Added,
                                                            frmt("connected to WebSocket endpoint at {}",
                                                                 connection()->endpoint()));

                    _socket.send(nlohmann::json(topics).dump());
                    _connected = true;
                    break;
                }

                case ix::WebSocketMessageType::Close: {
                    if ( _connected )
                        connection()->processConnectivityChange(ConnectivityChange::Removed,
                                                                frmt("disconnected from WebSocket endpoint at {}",
                                                                     connection()->endpoint()));
                    _connected = false;
                    break;
                }

                case ix::WebSocketMessageType::Error: {
                    if ( _connected )
                        connection()->processConnectivityChange(ConnectivityChange::Lost,
                                                                frmt("lost connection to WebSocket endpoint at {} ({})",
                                                                     connection()->endpoint(), msg_error_reason));
                    else {
                        std::string reason = trim(msg_error_reason);

                        if ( reason.find("Connect error:") != std::string::npos ||
                             reason.find("Cancelled") != std::string::npos )
                            // We get "error: Connect error: Bad file
                            // descriptor" or "error: Cancelled" if noone is
                            // listening at the destination port.
                            reason = "";

                        logger()->debug("cannot connect to Zeek endpoint via WebSocket at {}{}",
                                        connection()->endpoint(), (reason.empty() ? "" : frmt(" ({})", reason)));
                        connection()->connectionAttemptFailed(this, reason);
                    }

                    _connected = false;
                    break;
                }

                case ix::WebSocketMessageType::Message:
                    try {
                        auto json = nlohmann::json::parse(msg_str);

                        if ( json["type"] == "ack" ) {
                            auto endpoint_ = json["endpoint"].get<std::string>();
                            auto broker_version = json["version"].get<std::string>();
                            ZEEK_CONN_DEBUG("received acknowledgment (endpoint={} broker={})", endpoint_,
                                            broker_version);
                        }

                        else if ( json["type"] == "data-message" ) {
                            auto [data_, type] = from_json(json);
                            const auto& data = std::get<Record>(data_);

                            if ( std::get<int64_t>(data[0].first) != 1 || std::get<int64_t>(data[1].first) != 1 ) {
                                ZEEK_CONN_DEBUG("unexpected content enums for data-message: {}", to_string(data));
                                return;
                            }

                            auto event = std::get<Record>(data[2].first);
                            const auto& event_name = std::get<std::string>(event[0].first);
                            const std::vector<std::pair<Value, value::Type>>& event_args =
                                std::get<Record>(event[1].first);

                            connection()->processEvent(event_name,
                                                       transform(event_args, [](auto i) { return i.first; }));
                        }

                        else if ( json["type"] == "error" ) {
                            auto code = json["code"].get<std::string>();
                            auto context = json["context"].get<std::string>();
                            connection()->processError(
                                frmt("WebSocket error for {}: {} ({})", connection()->endpoint(), code, context));
                        }

                        else {
                            ZEEK_CONN_DEBUG("unexpected message type {}", json["@type"]);
                            return;
                        }
                    }

                    catch ( const std::exception& e ) {
                        ZEEK_CONN_DEBUG("cannot parse WebSocket message: {} ({})", e.what(), msg_str);
                    }

                    break;

                case ix::WebSocketMessageType::Ping:
                case ix::WebSocketMessageType::Pong:
                case ix::WebSocketMessageType::Fragment: break;
            }
        });
    });

    ZEEK_CONN_DEBUG("WebSocket endpoint: {}", url);
    tryReconnect();
}

void WebSocketTransport::tryReconnect() {
    if ( _socket.getReadyState() != ix::ReadyState::Closed )
        // Still/already doing something on the connection.
        return;

    if ( _last_connect_attempt &&
         (std::chrono::system_clock::now() - *_last_connect_attempt) < _config.options().zeek_reconnect_interval )
        return;

    _socket.stop();
    _socket.start();
    _last_connect_attempt = std::chrono::system_clock::now();
}

void WebSocketTransport::disconnect() {
    _socket.stop();
    _last_connect_attempt.reset();
    _connected = false;
}

void WebSocketTransport::poll() {
    if ( _last_connect_attempt && ! _connected )
        tryReconnect();
}

void WebSocketTransport::transmitEvent(const std::string& topic, const std::string& event_name, Record args) {
    broker::zeek::Event ev(event_name, broker::get<broker::vector>(to_broker(args, value::Type::Record)));
    auto event = Record({{Value(1L), value::Type::Count},
                         {Value(1L), value::Type::Count},
                         {Record{{
                              {Value(event_name), value::Type::Text},
                              {std::move(args), value::Type::Record},
                          }},
                          value::Type::Record}});

    nlohmann::json msg = to_json(event, value::Type::Record);
    msg["type"] = "data-message";
    msg["topic"] = topic;
    _socket.send(msg.dump());
}

///// Transport-indenpendent Zeek communication code.

std::string TransportProtocol::endpoint() const { return _connection->endpoint(); }

Result<Nothing> ZeekConnection::connect(const std::string& destination) {
    // Parse "host[:port]".
    std::string address;
    unsigned int port = 0;

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
        return result::Error(frmt("invalid Zeek address ({})", address));
    }

    if ( port > 0 )
        _destination = frmt("{}:{}", address, port);
    else
        _destination = address;

    std::vector<std::string> topics = {
        frmt("/zeek-agent/query/host/{}", options().agent_id),
    };

    auto groups = options().zeek_groups;
    groups.emplace_back("all");
    groups.push_back(tolower(platform::name()));

    for ( const auto& group : groups ) {
        topics.emplace_back(frmt("/zeek-agent/query/group/{}", group)); // group broadcast
        topics.emplace_back(
            frmt("/zeek-agent/query/group/{}/{}", options().agent_id, group)); // group msg to individual host
    }

    ZEEK_CONN_DEBUG("connecting");
    for ( const auto& t : topics )
        ZEEK_CONN_DEBUG("  subscribing to: {}", t);

    for ( const auto& transport : _transports )
        transport->connect(address, port ? port : transport->defaultPort(), topics);

    return Nothing();
}

void ZeekConnection::disconnect() {
    if ( ! _destination )
        return;

    cancelAllQueries();
    _zeek_instances.clear();

    ZEEK_CONN_DEBUG("disconnecting");

    // Send out shutdown message. This is best effort, the event might not make
    // it out anymore. But the Zeek instances will eventually time out their
    // state if they don't hear from us anymore.
    transmitEvent("ZeekAgentAPI::agent_shutdown_v1", {});

    for ( const auto& transport : _transports ) {
        if ( ! transport->isShutdown() )
            transport->disconnect();
    }
}

void ZeekConnection::poll() {
    // Expire any state from Zeek instances we haven't seen in a while.
    std::vector<std::string> to_remove;
    for ( const auto& z : _zeek_instances ) {
        if ( z.second.last_seen + options().zeek_timeout < _scheduler->currentTime() )
            to_remove.emplace_back(z.first);
    }

    for ( const auto& id : to_remove ) {
        logger()->info("inactive Zeek instance, timing out [{}]", id);
        removeZeekInstance(id);
    }

    for ( const auto& transport : _transports )
        transport->poll();
}

void ZeekConnection::installQuery(ZeekQuery zquery) {
    auto zeek_id = zquery.zeek_id;
    if ( lookupQuery(zeek_id) )
        // Already installed.
        return;

    zquery.query.callback_result = [this, zeek_id](query::ID /* query_id */, const query::Result& result) {
        transmitResult(zeek_id, result);
    };

    zquery.query.callback_done = [this, zeek_id](query::ID /* query_id */, bool /* cancelled */) {
        ZEEK_CONN_DEBUG("database done with query {}, removing", zeek_id);
        _zeek_queries.erase(zeek_id);
    };

    if ( auto rc = _db->query(zquery.query) ) {
        zquery.query_id = *rc; // could be unset
        _zeek_queries.emplace(zeek_id, std::move(zquery));
    }
    else if ( zquery.zeek_instance )
        // We don't log this as an error locally, but send it back to Zeek.
        transmitError(*zquery.zeek_instance, frmt("could not compile query ({})", rc.error()), zquery.zeek_id,
                      zquery.zeek_cookie);
}

void ZeekConnection::cancelQuery(const std::string& zeek_id) {
    auto i = _zeek_queries.find(zeek_id);
    if ( i == _zeek_queries.end() )
        // already gone
        return;

    if ( i->second.query_id )
        _db->cancel(*i->second.query_id);

    _zeek_queries.erase(i);
}

void ZeekConnection::removeZeekInstance(const std::string& zeek_instance) {
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

void ZeekConnection::cancelAllQueries() {
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

void ZeekConnection::unexpectedEventArguments(const std::string& zeek_agent, const std::string& name,
                                              const std::vector<Value>& args) {
    ZEEK_INSTANCE_DEBUG(zeek_agent, "ignoring event with unexpected argument types: {}{}", name, to_string(args));
}

void ZeekConnection::processEvent(const std::string& name, const std::vector<Value>& args) {
    std::string zeek_instance_id = "<unknown-zeek>";
    auto zeek_instance = _zeek_instances.end();

    try {
        if ( args.empty() )
            throw std::runtime_error("argument error");

        zeek_instance_id = std::get<std::string>(args[0]);
        zeek_instance = _zeek_instances.find(zeek_instance_id);

        if ( zeek_instance != _zeek_instances.end() )
            zeek_instance->second.last_seen = _scheduler->currentTime();

        else {
            logger()->info("new Zeek instance [{}]", zeek_instance_id);
            zeek_instance =
                _zeek_instances.emplace(zeek_instance_id, ZeekInstance{.last_seen = _scheduler->currentTime()}).first;
        }

    } catch ( const std::exception& e ) {
        unexpectedEventArguments(zeek_instance_id, name, args);
        return;
    }

    if ( zeek_instance->second.disabled ) {
        ZEEK_INSTANCE_DEBUG(zeek_instance_id, "ignoring event from disabled Zeek: {}{}", name, to_string(args));
        return;
    }

    ZEEK_INSTANCE_DEBUG(zeek_instance_id, "got event: {}({})", name, to_string(args));

    assert(zeek_instance != _zeek_instances.end());

    if ( name == "ZeekAgentAPI::zeek_hello_v1" ) {
        try {
            auto old_hello_record = zeek_instance->second;

            auto hello_record = std::get<Record>(args[1]);
            zeek_instance->second.version_string = std::get<std::string>(hello_record[0].first);
            zeek_instance->second.version_number = std::get<int64_t>(hello_record[1].first);

            if ( auto pkg_version = std::get<std::string>(hello_record[2].first); ! pkg_version.empty() ) {
                zeek_instance->second.package_version = pkg_version;

                if ( auto pkg_version_number = parseVersion(pkg_version) ) {
                    if ( *pkg_version_number < MininumZeekPackageVersion ) {
                        const auto msg =
                            frmt("Zeek package version too old, disabling communication (want {}, but have {})",
                                 MininumZeekPackageVersion, *pkg_version_number);
                        logger()->warn("[{}] {}", zeek_instance_id, msg);

                        // We'll try to get the error message through still.
                        transmitError(zeek_instance_id, msg, {}, {});
                        zeek_instance->second.disabled = true;
                        return;
                    }
                }
                else
                    ZEEK_INSTANCE_DEBUG(zeek_instance_id, "cannot parse Zeek package version number ({})", pkg_version);
            }

            if ( zeek_instance->second != old_hello_record ) {
                ZEEK_INSTANCE_DEBUG(zeek_instance_id, "Zeek version: {} ({}), package {}",
                                    zeek_instance->second.version_string, zeek_instance->second.version_number,
                                    zeek_instance->second.package_version);
            }
        } catch ( const std::exception& e ) {
            unexpectedEventArguments(zeek_instance_id, name, args);
            return;
        }
    }

    else if ( name == "ZeekAgentAPI::zeek_shutdown_v1" ) {
        logger()->info("Zeek instance is shutting down [{}]", zeek_instance_id);
        removeZeekInstance(zeek_instance_id);
    }

    else if ( name == "ZeekAgentAPI::install_query_v1" ) {
        ZeekQuery zquery;

        try {
            if ( args.size() != 3 )
                throw std::runtime_error("argument error");

            auto zeek_id = std::get<std::string>(args[1]);
            if ( lookupQuery(zeek_id) ) {
                ZEEK_INSTANCE_DEBUG(zeek_instance_id, "ignoring already known query {}", zquery.zeek_id);
                return;
            }

            auto query_record = std::get<Record>(args[2]);
            if ( query_record.size() != 7 )
                throw std::runtime_error("argument error");

            auto sql_stmt = std::get<std::string>(query_record[0].first);

            Interval schedule_ = 0s;

            if ( ! std::holds_alternative<std::monostate>(query_record[1].first) )
                schedule_ = std::get<Interval>(query_record[1].first);

            std::optional<query::SubscriptionType> subscription;
            if ( ! std::holds_alternative<std::monostate>(query_record[2].first) ) {
                auto enum_name = std::get<std::string>(query_record[2].first);
                if ( enum_name == "ZeekAgent::Snapshots" )
                    subscription = query::SubscriptionType::Snapshots;
                else if ( enum_name == "ZeekAgent::Events" )
                    subscription = query::SubscriptionType::Events;
                else if ( enum_name == "ZeekAgent::Differences" )
                    subscription = query::SubscriptionType::Differences;
                else if ( enum_name == "ZeekAgent::SnapshotPlusDifferences" )
                    subscription = query::SubscriptionType::SnapshotPlusDifferences;
                else
                    ZEEK_INSTANCE_DEBUG(zeek_instance_id, "ignoring event with unknown subscription type: {}",
                                        enum_name);
            }

            auto event_name = std::get<std::string>(std::get<Record>(query_record[3].first)[0].first);

            std::optional<std::string> cookie;

            if ( ! std::holds_alternative<std::monostate>(query_record[4].first) )
                cookie = std::get<std::string>(query_record[4].first);

            std::set<std::string> requires_tables;
            for ( const auto& t : std::get<Set>(query_record[5].first) )
                requires_tables.emplace(std::get<std::string>(t));

            std::set<std::string> if_missing_tables;
            for ( const auto& t : std::get<Set>(query_record[6].first) )
                if_missing_tables.emplace(std::get<std::string>(t));

            zquery = ZeekQuery{.zeek_instance = std::move(zeek_instance_id),
                               .zeek_id = zeek_id,
                               .event_name = std::move(event_name),
                               .zeek_cookie = cookie,
                               .query = Query{
                                   .sql_stmt = std::move(sql_stmt),
                                   .subscription = subscription,
                                   .schedule = schedule_,
                                   .requires_tables = std::move(requires_tables),
                                   .if_missing_tables = std::move(if_missing_tables),
                                   .terminate = false,
                                   .cookie = cookie,
                               }};
        } catch ( const std::exception& e ) {
            unexpectedEventArguments(zeek_instance_id, name, args);
            return;
        }

        installQuery(std::move(zquery));
    }

    else if ( name == "ZeekAgentAPI::cancel_query_v1" ) {
        std::string zeek_id;
        try {
            if ( args.size() != 2 )
                throw std::runtime_error("argument error");

            zeek_id = std::get<std::string>(args[1]);
        } catch ( const std::exception& e ) {
            unexpectedEventArguments(zeek_instance_id, name, args);
            return;
        }

        if ( auto zquery = lookupQuery(zeek_id); zquery && zquery->query_id )
            _db->cancel(*zquery->query_id);
    }
}

void ZeekConnection::processError(const std::string& msg) { logger()->warn(msg); }

void ZeekConnection::connectionEstablished(const TransportProtocol* transport, const std::string& address,
                                           unsigned int port) {
    // Make this safe against concurrent execution.
    static std::mutex mutex;
    std::unique_lock<std::mutex> lock(mutex);

    if ( _transport_established )
        return;

    ZEEK_CONN_DEBUG("stopping transports other than {}", transport->name());
    _transport_established = true;
    _destination = frmt("{}:{}", address, port);

    // Once one of our transports has successfully connected, we'll stop all the other ones.
    for ( auto&& t : _transports ) {
        if ( t.get() != transport )
            t->disconnect();
    }
}

void ZeekConnection::connectionAttemptFailed(const TransportProtocol* transport, const std::string& reason) {
    if ( _transport_established )
        logger()->info("cannot reconnect to Zeek endpoint at {} via {}{}", endpoint(), transport->name(),
                       (reason.empty() ? std::string() : frmt(" ({})", reason)));
    else {
        // If we haven't established a single transport yet, we only report
        // once all transports have failed to connect.
        _transports_failed.insert(transport);

        if ( _transports_failed.size() == _transports.size() ) {
            logger()->info(frmt("cannot connect to Zeek endpoint at {}", endpoint()));
            _transports_failed.clear();
        }
    }
}

void ZeekConnection::processConnectivityChange(const ConnectivityChange& status, const std::string& msg) {
    logger()->info(msg);

    switch ( status ) {
        case ConnectivityChange::Added: {
            // Schedule repeated query sending agent hello.
            ZeekQuery hello = {.zeek_id = "agent_hello_" + randomUUID(), // unique ID for each query
                               .event_name = "ZeekAgentAPI::agent_hello_v1",
                               .query = Query{.sql_stmt = "SELECT * from zeek_agent",
                                              .subscription = query::SubscriptionType::Snapshots,
                                              .schedule = options().zeek_hello_interval}};

            installQuery(std::move(hello));
            break;
        }

        case ConnectivityChange::Lost:
        case ConnectivityChange::Removed:
            cancelAllQueries();
            _zeek_instances.clear();

            if ( options().terminate_on_disconnect )
                _scheduler->terminate();

            break;

        default: break; // ignore
    }
}

void ZeekConnection::transmitResult(const std::string& zeek_id, const query::Result& result) {
    auto zquery = lookupQuery(zeek_id);
    if ( ! zquery )
        // Cancelled in the meantime.
        return;

    for ( const auto& row : result.rows ) {
        Record columns;
        columns.reserve(result.columns.size());

        for ( auto i = 0U; i < result.columns.size(); i++ )
            columns.emplace_back(row.values[i], result.columns[i].type);

        auto args = Record({{std::move(columns), value::Type::Record}});
        transmitEvent(zquery->event_name, std::move(args), zquery->zeek_instance, zquery->zeek_id, zquery->zeek_cookie,
                      row.type);
    }
}

void ZeekConnection::transmitError(const std::string& zeek_instance, const std::string& msg,
                                   const std::optional<std::string>& zeek_id,
                                   const std::optional<std::string>& cookie) {
    if ( auto i = _zeek_instances.find(zeek_instance); i != _zeek_instances.end() && i->second.disabled ) {
        ZEEK_INSTANCE_DEBUG(zeek_instance, "not sending error to disabled Zeek: {}", msg);
        return;
    }

    ZEEK_INSTANCE_DEBUG(zeek_instance, "sending error: {}", msg);
    transmitEvent("ZeekAgentAPI::agent_error_v1", {{msg, value::Type::Text}}, zeek_instance, zeek_id, cookie);
}

void ZeekConnection::transmitEvent(const std::string& event_name, Record args,
                                   const std::optional<std::string>& zeek_instance,
                                   const std::optional<std::string>& zeek_id, const std::optional<std::string>& cookie,
                                   const std::optional<query::result::ChangeType>& change) {
    assert(! zeek_instance.has_value() || ! zeek_instance->empty());
    assert(! cookie.has_value() || ! cookie->empty());

    if ( zeek_instance ) {
        if ( auto i = _zeek_instances.find(*zeek_instance); i != _zeek_instances.end() && i->second.disabled ) {
            ZEEK_INSTANCE_DEBUG(*zeek_instance, "not sending event {} to disabled Zeek", event_name);
            return;
        }
    }

    Value change_data;
    if ( change ) {
        switch ( *change ) {
            case query::result::ChangeType::Add: change_data = "ZeekAgent::Add"; break;
            case query::result::ChangeType::Delete: change_data = "ZeekAgent::Delete"; break;
        }
    }

    Value v_zeek_id;
    Value v_cookie;

    if ( zeek_id )
        v_zeek_id = *zeek_id;

    if ( cookie )
        v_cookie = *cookie;

    Record context;
    context.emplace_back(options().agent_id, value::Type::Text);
    context.emplace_back(std::chrono::system_clock::now(), value::Type::Time);
    context.emplace_back(v_zeek_id, value::Type::Text);
    context.emplace_back(std::move(change_data), value::Type::Enum);
    context.emplace_back(v_cookie, value::Type::Text);

    args.insert(args.begin(), 1, {std::move(context), value::Type::Record});

    for ( const auto& transport : _transports ) {
        if ( zeek_instance ) {
            ZEEK_INSTANCE_DEBUG(*zeek_instance, "sending event: {}{}", event_name, to_string(args));
            transport->transmitEvent(frmt("/zeek-agent/response/{}/{}", *zeek_instance, options().agent_id), event_name,
                                     args);
        }
        else {
            ZEEK_INSTANCE_DEBUG("all", "sending event: {}{}", event_name, to_string(args));
            transport->transmitEvent(frmt("/zeek-agent/response/all/{}", options().agent_id), event_name, args);
        }
    }
}

const ZeekQuery* ZeekConnection::lookupQuery(const std::string& zeek_id) {
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

    const auto& options() const { return _db->configuration().options(); }

    Database* _db = nullptr;         // as passed into constructor
    Scheduler* _scheduler = nullptr; // as passed into constructor

    std::vector<std::unique_ptr<ZeekConnection>> _connections; // one connection per desintation passed into constructor
    bool _stopped = false;                                     // true once stop() can been executed
};

void Zeek::Implementation::start(const std::vector<std::string>& zeeks) {
    ix::initNetSystem();

    for ( const auto& z : zeeks ) {
        auto conn = std::make_unique<ZeekConnection>(_db, _scheduler);
        conn->addTransport(std::make_unique<WebSocketTransport>(_db->configuration()));
        conn->addTransport(std::make_unique<NativeBrokerTransport>(_db->configuration()));

        if ( auto rc = conn->connect(z) )
            _connections.push_back(std::move(conn));
        else
            logger()->error("{}", rc.error());
    }
}

void Zeek::Implementation::stop() {
    for ( const auto& c : _connections )
        c->disconnect();

    _connections.clear();
    ix::uninitNetSystem();
}

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
    pimpl()->start(zeeks);
}

void Zeek::stop() {
    ZEEK_IO_DEBUG("stopping");
    pimpl()->stop();
}

void Zeek::poll() {
    ZEEK_IO_DEBUG("polling");
    pimpl()->poll();
}

TEST_SUITE("Zeek") {
    TEST_CASE("connect/hello/disconnect/reconnect - native Broker" * doctest::timeout(10.0)) {
        Configuration cfg;
        Scheduler tmgr;
        Database db(&cfg, &tmgr);
        auto agent_table = Database::findRegisteredTable("zeek_agent");
        db.addTable(agent_table);
        Zeek zeek(&db, &tmgr);

        // Shorten reconnect interval.
        std::stringstream options{"[zeek]\nreconnect_interval = 1"};
        cfg.read(options, "-");

        broker::endpoint receiver;
        auto subscriber = receiver.make_subscriber({"/zeek-agent/response/"});
        auto status_subscriber = receiver.make_status_subscriber(true);
        auto port = receiver.listen("127.0.0.1", 0);

        // Initiate connection.
        zeek.start({frmt("localhost:{}", port)});

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
                CHECK_EQ(get_topic(msg), broker::topic(frmt("/zeek-agent/response/all/{}", cfg.options().agent_id)));

                hello = broker::zeek::Event(broker::move_data(msg));
            } while ( hello.name() == "ZeekAgentAPI::agent_shutdown_v1" ); // ignore shutdown event

            CHECK_EQ(hello.name(), "ZeekAgentAPI::agent_hello_v1");
            CHECK_EQ(hello.args().size(), 2); // context plus columns record
            CHECK_EQ(broker::get<broker::vector>(hello.args()[1]).size(),
                     13); // zeek_agent table has 12 columns

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

#ifndef HAVE_WINDOWS
#if ! defined(__has_warning) // Clang always has this
#define __suppress_warning
#elif __has_warning("-Wmaybe-uninitialized")
#define __suppress_warning
#endif

#ifdef __suppress_warning
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#endif
            receiver.unpeer(p.peer.network->address, p.peer.network->port);
#ifndef HAVE_WINDOWS
#ifdef __suppress_warning
#pragma GCC diagnostic pop
#undef __suppress_warning
#endif
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
