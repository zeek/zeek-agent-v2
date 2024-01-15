// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.
//
// The EndpointSecurity code borrows from
// https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba.

#include "endpoint-security.h"

#include "autogen/config.h"
#include "core/logger.h"
#include "util/helpers.h"

#include <EndpointSecurity/EndpointSecurity.h>

using namespace zeek::agent;
using namespace zeek::agent::platform::darwin;

es::Subscriber::Subscriber(std::string tag, es_client_t* client) : _tag(std::move(tag)), _client(client) {
    if ( ! _client )
        return;

    ZEEK_AGENT_DEBUG("darwin", "[EndpointSecurity] [{}] subscription created", _tag);
}

es::Subscriber::~Subscriber() {
    if ( ! _client )
        return;

    es_delete_client(_client);
    ZEEK_AGENT_DEBUG("darwin", "[EndpointSecurity] [{}] subscription deleted", _tag);
}

EndpointSecurity::EndpointSecurity() {
    if ( auto rc = subscribe("CheckAvailability", {}, [](const es_message_t*) {}) ) {
        ZEEK_AGENT_DEBUG("darwin", "[EndpointSecurity] available");
        _init_result = Nothing();
    }
    else {
        ZEEK_AGENT_DEBUG("darwin", "[EndpointSecurity] not available: {}", rc.error());
        _init_result = rc.error();
    }
}

EndpointSecurity::~EndpointSecurity() {}

Result<std::unique_ptr<es::Subscriber>> EndpointSecurity::subscribe(std::string tag, const Events& events,
                                                                    Callback callback) { // NOLINT
    es_client_t* client;
    es_new_client_result_t res = es_new_client(&client, ^(es_client_t* c, const es_message_t* msg) {
      callback(msg);
    });

    switch ( res ) {
        case ES_NEW_CLIENT_RESULT_SUCCESS: {
            if ( events.size() ) {
                if ( es_subscribe(client, events.data(), events.size()) != ES_RETURN_SUCCESS )
                    return result::Error("failed to subscribe to EndpointSecurity events");
            }

            return std::unique_ptr<es::Subscriber>(
                new es::Subscriber(std::move(tag), events.size() ? client : nullptr));
        }

        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return result::Error("macOS entitlement not available (com.apple.developer.endpoint-security.client)");

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return result::Error(
                "Application lacks Transparency, Consent, and Control (TCC) approval "
                "from the user. This can be resolved by granting 'Full Disk Access' from "
                "the 'Security & Privacy' tab of System Preferences.");

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return result::Error("not running as root");
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return result::Error("too many clients");
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return result::Error("invalid argument");
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: return result::Error("internal error");
    }

    cannot_be_reached();
}

EndpointSecurity* platform::darwin::endpointSecurity() {
    static auto es = std::unique_ptr<EndpointSecurity>{};

    if ( ! es )
        es = std::unique_ptr<EndpointSecurity>(new EndpointSecurity);

    return es.get();
}
