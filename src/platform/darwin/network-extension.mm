// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.
//
// Note that contrary to what Apple's documentation says, FilterDataProvider is
// *not* sandboxed on macOS. See // https://developer.apple.com/forums/thread/133761.

#include "network-extension.h"

#include "autogen/config.h"
#include "core/logger.h"

#include <Network/Network.h>
#include <NetworkExtension/NetworkExtension.h>
#include <bsm/libbsm.h>

using namespace zeek::agent;
using namespace zeek::agent::platform::darwin;

ne::Subscriber::~Subscriber() { _ne->_subscribers.remove(this); }

template<>
struct Pimpl<NetworkExtension>::Implementation {
    bool running = false;
};

Result<Nothing> NetworkExtension::isAvailable() {
    if ( pimpl()->running ) {
        ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] available");
        return Nothing();
    }
    else {
        ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] not available");
        return result::Error("network extension not running");
    }
}

NetworkExtension::NetworkExtension() {}

NetworkExtension::~NetworkExtension() {}

std::unique_ptr<ne::Subscriber> NetworkExtension::subscribe(std::string tag, Callback callback) {
    ZEEK_AGENT_DEBUG("NetworkExtension", "new subscriber: {}", tag);
    auto subscriber = std::unique_ptr<ne::Subscriber>(new ne::Subscriber(this, std::move(tag), std::move(callback)));
    _subscribers.push_back(subscriber.get());
    return std::move(subscriber);
}

void NetworkExtension::newFlow(const ne::Flow& flow) {
    ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] new flow: {}/{} -> {}/{}", to_string(flow.local_addr),
                     to_string(flow.local_port), to_string(flow.remote_addr), to_string(flow.remote_port));

    for ( const auto& s : _subscribers )
        s->_callback(flow);
}

NetworkExtension* platform::darwin::networkExtension() {
    static auto ne = std::unique_ptr<NetworkExtension>{};

    if ( ! ne )
        ne = std::unique_ptr<NetworkExtension>(new NetworkExtension);

    return ne.get();
}

@interface FilterDataProvider : NEFilterDataProvider
@end

@implementation FilterDataProvider
- (void)startFilterWithCompletionHandler:(void (^)(NSError* error))completionHandler {
    ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] starting");
    networkExtension()->pimpl()->running = true;

    // Create a filter that matches all traffic and let it all pass through our
    // `handleNewFlow()` filter.
    auto* all_traffic = [[NENetworkRule alloc] initWithRemoteNetworkEndpoint:nil
                                                                remotePrefix:0
                                                        localNetworkEndpoint:nil
                                                                 localPrefix:0
                                                                    protocol:NENetworkRuleProtocolAny
                                                                   direction:NETrafficDirectionAny];

    auto* rule = [[NEFilterRule alloc] initWithNetworkRule:all_traffic action:NEFilterActionFilterData];
    auto* setting = [[NEFilterSettings alloc] initWithRules:[NSArray arrayWithObjects:rule, nil]
                                              defaultAction:NEFilterActionAllow];
    [all_traffic release];
    [rule release];

    [self applySettings:setting
        completionHandler:^(NSError* _Nullable error) {
          if ( error != nil ) {
              logger()->info("failed to apply filter settings in network extension");
              networkExtension()->pimpl()->running = false;
          }

          completionHandler(error);
        }];
}

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] stopping");
    networkExtension()->pimpl()->running = false;
    completionHandler();
}

- (NEFilterNewFlowVerdict*)handleNewFlow:(NEFilterFlow*)flow {
    ZEEK_AGENT_DEBUG("darwin", "[NetworkExtension] got flow");

    if ( ! [flow isKindOfClass:[NEFilterSocketFlow class]] )
        return [NEFilterNewFlowVerdict allowVerdict];

    auto sf = (NEFilterSocketFlow*)flow;
    ne::Flow nf;

    // Audit token: copy out safely after validating length, instead of
    // reinterpret-casting the NSData backing store.
    NSData* tokenData = sf.sourceAppAuditToken;
    if ( tokenData && tokenData.length == sizeof(audit_token_t) ) {
        audit_token_t token;
        memcpy(&token, tokenData.bytes, sizeof(token));
        nf.pid = audit_token_to_pid(token);

        if ( auto p = platform::darwin::getProcessInfo(nf.pid) )
            nf.process = *p;
    }

    // `localFlowEndpoint` / `remoteFlowEndpoint` return an `nw_endpoint_t`
    // (an Objective-C / ARC-managed handle from `Network.framework`), NOT a
    // pointer-to-handle. The previous code added an extra level of
    // indirection (`(nw_endpoint_t*)... ; *local`) which produced a garbage
    // handle and crashed inside `nw_endpoint_get_hostname` on macOS 15+.
    if ( nw_endpoint_t local = sf.localFlowEndpoint; local != nil ) {
        if ( const char* h = nw_endpoint_get_hostname(local) )
            nf.local_addr = std::string(h);
        nf.local_port = static_cast<int64_t>(nw_endpoint_get_port(local));
    }

    if ( nw_endpoint_t remote = sf.remoteFlowEndpoint; remote != nil ) {
        if ( const char* h = nw_endpoint_get_hostname(remote) )
            nf.remote_addr = std::string(h);
        nf.remote_port = static_cast<int64_t>(nw_endpoint_get_port(remote));
    }

    nf.protocol = static_cast<int64_t>(sf.socketProtocol);
    nf.state = Value(); // TODO: Can we get this?

    switch ( sf.socketFamily ) {
        case PF_INET: nf.family = "IPv4"; break;
        case PF_INET6: nf.family = "IPv6"; break;
        default: nf.family = "Unknown"; break;
    }

    networkExtension()->newFlow(nf);

    return [NEFilterNewFlowVerdict allowVerdict];
}

@end

[[noreturn]] void platform::darwin::enterNetworkExtensionMode() {
    [NEProvider startSystemExtensionMode];
    dispatch_main();
}
