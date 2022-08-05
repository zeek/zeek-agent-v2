// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

// clang-format off
#include "platform.h"
#include "platform.darwin.h"
// clang-format on

#include "autogen/config.h"
#include "core/logger.h"

#include <CoreFoundation/CFPreferences.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <NetworkExtension/NetworkExtension.h>

using namespace zeek::agent;
using namespace zeek::agent::platform::darwin;

///// XPC types

@protocol IPCProtocol
- (void)getStatusWithReply:(void (^)(NSString*, NSString*, NSString*))reply;
- (void)getOptionsWithReply:(void (^)(NSDictionary<NSString*, NSString*>*))reply;
- (void)setOptions:(NSDictionary<NSString*, NSString*>*)options;
- (void)exit;
@end

@interface IPC : NSObject <NSXPCListenerDelegate, IPCProtocol>
+ (IPC*)sharedObject;
- (id)init;
- (const Options&)options;
@property(strong) NSUserDefaults* defaults;
@property(strong) NSXPCListener* listener;
@property const Configuration* configuration;
@end

////// Platform API

std::string platform::name() { return "Darwin"; }

std::optional<filesystem::path> platform::configurationFile() {
    if ( auto dir = getApplicationSupport() )
        return *dir / "zeek-agent.cfg";
    else
        return {};
}

std::optional<filesystem::path> platform::dataDirectory() { return getApplicationSupport(); }

std::optional<filesystem::path> platform::darwin::getApplicationSupport() {
    auto domain = platform::runningAsAdmin() ? NSLocalDomainMask : NSUserDomainMask;
    auto paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, domain, YES);
    auto dir = [paths firstObject];
    return filesystem::path([dir UTF8String]) / "ZeekAgent";
}

[[noreturn]] void platform::darwin::enterSystemExtensionMode() {
    [NEProvider startSystemExtensionMode];
    dispatch_main();
}

void platform::init(const Configuration& cfg) {
    platform::darwin::endpointSecurity();       // this initializes ES
    [[IPC sharedObject] setConfiguration:&cfg]; // create the shared object
}

void platform::initializeOptions(Options* options) {
    if ( auto service = platform::getenv("XPC_SERVICE_NAME"); service && *service != "0" )
        // Running as an installed system extension, log to oslog by default.
        options->log_type = options::LogType::System;
}

std::optional<std::string> platform::retrieveConfigurationOption(const std::string& path) {
    NSString* key = nullptr;
    NSString* value = nullptr;

    ScopeGuard _([&]() {
        if ( key )
            CFRelease(key);

        if ( value )
            CFRelease(value);
    });

    key = [NSString stringWithUTF8String:path.c_str()];
    value = [[[IPC sharedObject] defaults] stringForKey:key];

    if ( value )
        return [value UTF8String];
    else
        return {};
}

////// Logging

OSLogSink::OSLogSink() { _oslog = os_log_create("org.zeek.zeek-agent", "agent"); }

OSLogSink::~OSLogSink() {
    if ( _oslog )
        CFRelease(_oslog);
}

void OSLogSink::sink_it_(const spdlog::details::log_msg& msg) {
    std::string formatted = std::string(msg.payload.data(), msg.payload.size());
    os_log_type_t level;

    switch ( msg.level ) {
        case spdlog::level::critical: level = OS_LOG_TYPE_ERROR; break;
        case spdlog::level::debug: level = OS_LOG_TYPE_DEBUG; break;
        case spdlog::level::err: level = OS_LOG_TYPE_ERROR; break;
        case spdlog::level::info: level = OS_LOG_TYPE_INFO; break;
        case spdlog::level::n_levels: cannot_be_reached();
        case spdlog::level::off: return;
        case spdlog::level::trace: level = OS_LOG_TYPE_DEBUG; break;
        case spdlog::level::warn: level = OS_LOG_TYPE_INFO; break;
    }

    auto log_msg = std::string(msg.payload.data(), msg.payload.size());
    auto log_level = std::string(to_string_view(msg.level).data(), to_string_view(msg.level).size());
    os_log_with_type(_oslog, level, "[%{public}s] %{public}s", log_level.c_str(), log_msg.c_str());
}

void OSLogSink::flush_() {}

////// Network Extension

template<>
struct Pimpl<NetworkExtension>::Implementation {
    bool running = false;
};

Result<Nothing> NetworkExtension::isAvailable() {
    if ( pimpl()->running )
        return Nothing();
    else
        return result::Error("network extension  not running");
}

NetworkExtension::NetworkExtension() {}
NetworkExtension::~NetworkExtension() {}

NetworkExtension* platform::darwin::networkExtension() {
    static auto ne = std::unique_ptr<NetworkExtension>{};

    if ( ! ne )
        ne = std::unique_ptr<NetworkExtension>(new NetworkExtension);

    return ne.get();
}

// Note that contrary to what Apple's documentation says, FilterDataProvider is
// *not* sandboxed on macOS. See // https://developer.apple.com/forums/thread/133761.
@interface FilterDataProvider : NEFilterDataProvider
@end

@implementation FilterDataProvider
- (void)startFilterWithCompletionHandler:(void (^)(NSError* error))completionHandler {
    networkExtension()->pimpl()->running = true;

    // Create a filter that matches all traffic and let it all pass through our
    // `handleNewFlow()` filter.
    auto all_traffic = [[NENetworkRule alloc] initWithRemoteNetwork:nil
                                                       remotePrefix:0
                                                       localNetwork:nil
                                                        localPrefix:0
                                                           protocol:NENetworkRuleProtocolAny
                                                          direction:NETrafficDirectionAny];

    auto rule = [[NEFilterRule alloc] initWithNetworkRule:all_traffic action:NEFilterActionFilterData];
    auto setting = [[NEFilterSettings alloc] initWithRules:[NSArray arrayWithObjects:rule, nil]
                                             defaultAction:NEFilterActionAllow];
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
    networkExtension()->pimpl()->running = false;
    completionHandler();
}

- (NEFilterNewFlowVerdict*)handleNewFlow:(NEFilterFlow*)flow {
    // TODO: Report new flow to subscribers here.
    logger()->info("new flow");
    return [NEFilterNewFlowVerdict allowVerdict];
}

@end

////// Endpoint Security

// The EndpointSecurity code borrows from
// https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba.
template<>
struct Pimpl<EndpointSecurity>::Implementation {
    // Initialize ES, if not done yet.
    Result<Nothing> init();

    // Shutdown ES, if running.
    void done();

    es_client_t* _es_client = nullptr;
    Result<Nothing> _es_init_result;
};

static es_handler_block_t dummy_handler = ^(es_client_t* clt, const es_message_t* msg) {
};

Result<Nothing> EndpointSecurity::Implementation::init() {
    es_new_client_result_t res = es_new_client(&_es_client, dummy_handler);

    switch ( res ) {
        case ES_NEW_CLIENT_RESULT_SUCCESS: _es_init_result = Nothing(); break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            _es_init_result =
                result::Error("macOS entitlement not available (com.apple.developer.endpoint-security.client)");
            break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            _es_init_result = result::Error(
                "Application lacks Transparency, Consent, and Control (TCC) approval "
                "from the user. This can be resolved by granting 'Full Disk Access' from "
                "the 'Security & Privacy' tab of System Preferences.");
            break;

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: _es_init_result = result::Error("not running as root"); break;
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: _es_init_result = result::Error("too many clients"); break;
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: _es_init_result = result::Error("invalid argument"); break;
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: _es_init_result = result::Error("internal error"); break;
    }

    if ( _es_init_result )
        ZEEK_AGENT_DEBUG("darwin", "EndpointSecurity available");
    else
        ZEEK_AGENT_DEBUG("darwin", "EndpointSecurity not available: {}", _es_init_result.error());

    return _es_init_result;
}

void EndpointSecurity::Implementation::done() {
    if ( _es_client )
        es_delete_client(_es_client);

    _es_client = nullptr;
    _es_init_result = {};
}

Result<Nothing> EndpointSecurity::isAvailable() {
    if ( pimpl()->_es_init_result )
        return Nothing();
    else
        return pimpl()->init();
}

EndpointSecurity::EndpointSecurity() { pimpl()->init(); }
EndpointSecurity::~EndpointSecurity() { pimpl()->done(); }

EndpointSecurity* platform::darwin::endpointSecurity() {
    static auto es = std::unique_ptr<EndpointSecurity>{};

    if ( ! es )
        es = std::unique_ptr<EndpointSecurity>(new EndpointSecurity);

    return es.get();
}

////// XPC

@implementation IPC

+ (IPC*)sharedObject {
    static dispatch_once_t once;
    static IPC* sharedObject;
    dispatch_once(&once, ^{
      sharedObject = [[self alloc] init];
    });

    return sharedObject;
}

- (instancetype)init {
    [super init];
    _defaults = [NSUserDefaults standardUserDefaults];
    _listener = [[NSXPCListener alloc] initWithMachServiceName:@"org.zeek.zeek-agent.agent"];
    _listener.delegate = self;
    [_listener resume];
    return self;
}

- (const Options&)options {
    return _configuration->options();
}

- (BOOL)listener:(NSXPCListener*)listener shouldAcceptNewConnection:(NSXPCConnection*)connection {
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(IPCProtocol)];
    connection.exportedObject = self;
    [connection resume];
    return YES;
}

- (void)getStatusWithReply:(void (^)(NSString*, NSString*, NSString*))reply {
    logger()->debug("[IPC] remote call: getStatus");

    auto es = (platform::darwin::endpointSecurity()->isAvailable() ? "+ES" : "-ES");
    auto ne = (platform::darwin::networkExtension()->isAvailable() ? "+NE" : "-NE");

    auto version = [NSString stringWithUTF8String:Version];
    auto capabilities = join(std::vector<std::string>{es, ne}, " ");
    auto capabilities_ = [NSString stringWithUTF8String:capabilities.c_str()];
    auto agent_id = [NSString stringWithUTF8String:[[IPC sharedObject] options].agent_id.c_str()];
    reply(version, capabilities_, agent_id);
}

- (void)getOptionsWithReply:(void (^)(NSDictionary<NSString*, NSString*>*))reply {
    logger()->debug("[IPC] remote call: getOptions");

    auto options = [NSMutableDictionary dictionary];

    NSArray* keys = [NSArray arrayWithObjects:@"zeek.destination", @"log.level", nil];
    for ( id key in keys ) {
        NSString* value = [_defaults stringForKey:key];
        options[key] = (value ? value : @"");
    }

    reply(options);

    CFRelease(keys);
    CFRelease(options);
}

- (void)setOptions:(NSDictionary<NSString*, NSString*>*)options {
    logger()->debug("[IPC] remote call: setOptions");

    for ( id key in options ) {
        auto value = [options objectForKey:key];
        [_defaults setObject:value forKey:key];
    }
}

- (void)exit {
    logger()->debug("[IPC] remote call: exit");
    exit(0);
}
@end
