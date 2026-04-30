// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

#include "xpc.h"

#include "autogen/config.h"
#include "core/logger.h"
#include "endpoint-security.h"
#include "network-extension.h"

using namespace zeek::agent;

// Returns a freshly allocated `NSUserDefaults` object bound to our
// app-group suite. Callers own the returned object and must `release` it.
//
// We re-create the suite object on each access (rather than caching one)
// to avoid stale-cache races with `cfprefsd` on recent macOS versions,
// where values written by another process in the same app group may
// otherwise not be visible.
static NSUserDefaults* makeAppGroupDefaults() {
    return [[NSUserDefaults alloc] initWithSuiteName:@"group.org.zeek.zeek-agent"];
}

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
    self = [super init];
    if ( self ) {
        _listener = [[NSXPCListener alloc] initWithMachServiceName:@"group.org.zeek.zeek-agent"];
        _listener.delegate = self;
        [_listener resume];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_listener release];
    [super dealloc];
}

- (void)updateOptions {
    logger()->debug("updating configuration");

    auto options = _configuration->options();

    NSUserDefaults* defaults = makeAppGroupDefaults();

    auto log_level = [defaults stringForKey:@"log.level"];
    if ( log_level ) {
        if ( [log_level isEqual:@""] )
            options.log_level = options::default_log_level;
        else if ( const char* log_level_str = [log_level UTF8String] ) {
            if ( auto rc = options::log_level::from_str(log_level_str) )
                options.log_level = *rc;
            else
                logger()->warn("invalid log level: {}", log_level_str);
        }
    }

    auto zeek_destination = [defaults stringForKey:@"zeek.destination"];
    if ( zeek_destination && [zeek_destination length] > 0 ) {
        const char* dest_str = [zeek_destination UTF8String];
        if ( dest_str && *dest_str )
            options.zeek_destinations = {dest_str};
    }

    [defaults release];

    if ( auto rc = _configuration->setOptions(options); ! rc )
        logger()->warn("error applying new options: {}", rc.error());
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

    NSUserDefaults* defaults = makeAppGroupDefaults();

    auto log_level = [defaults stringForKey:@"log.level"];
    if ( log_level )
        options[@"log.level"] = log_level;
    else
        options[@"log.level"] = @"default";

    auto zeek_destination = [defaults stringForKey:@"zeek.destination"];
    if ( zeek_destination )
        options[@"zeek.destination"] = zeek_destination;
    else
        options[@"zeek.destination"] = @"";

    [defaults release];

    reply(options);

    CFRelease(options);
}

- (void)setOptions:(NSDictionary<NSString*, NSString*>*)options {
    logger()->debug("[IPC] remote call: setOptions");

    NSUserDefaults* defaults = makeAppGroupDefaults();

    for ( id key in options ) {
        auto value = [options objectForKey:key];
        [defaults setObject:value forKey:key];
    }

    // Force flush to cfprefsd so the next reader (possibly in another
    // process) sees the new values reliably.
    [defaults synchronize];
    [defaults release];

    [self updateOptions];
}

- (void)exit {
    logger()->debug("[IPC] remote call: exit");

    // Trigger a graceful shutdown via the scheduler instead of calling
    // `::exit()` directly: the latter runs C++ static destructors on the
    // XPC dispatch thread, which races with the still-running agent
    // threads (logger sinks, tables, scheduler) and reliably crashes
    // (e.g. inside `~Table()` -> spdlog after the global logger has gone).
    if ( _scheduler )
        _scheduler->terminate();
    else
        ::exit(0);
}
@end
