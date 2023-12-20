// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "xpc.h"

#include "core/logger.h"
#include "endpoint-security.h"
#include "network-extension.h"

using namespace zeek::agent;

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
    _defaults = [[NSUserDefaults alloc] initWithSuiteName:@"group.org.zeek.zeek-agent"];
    _listener = [[NSXPCListener alloc] initWithMachServiceName:@"org.zeek.zeek-agent.agent"];
    _listener.delegate = self;
    [_listener resume];

    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [super dealloc];
}

- (void)updateOptions {
    logger()->debug("updating configuration");

    auto options = _configuration->options();

    auto log_level = [_defaults stringForKey:@"log.level"];
    if ( log_level ) {
        if ( [log_level isEqual:@""] )
            options.log_level = options::default_log_level;
        else if ( auto rc = options::log_level::from_str([log_level UTF8String]) )
            options.log_level = *rc;
        else
            logger()->warn("invalid log level: {}", [log_level UTF8String]);
    }

    auto zeek_destination = [_defaults stringForKey:@"zeek.destination"];
    if ( zeek_destination )
        options.zeek_destinations = {[zeek_destination UTF8String]};

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

    auto log_level = [_defaults stringForKey:@"log.level"];
    if ( log_level )
        options[@"log.level"] = log_level;
    else
        options[@"log.level"] = @"default";

    auto zeek_destination = [_defaults stringForKey:@"zeek.destination"];
    if ( zeek_destination )
        options[@"zeek.destination"] = zeek_destination;
    else
        options[@"zeek.destination"] = @"";

    reply(options);

    CFRelease(options);
}

- (void)setOptions:(NSDictionary<NSString*, NSString*>*)options {
    logger()->debug("[IPC] remote call: setOptions");

    for ( id key in options ) {
        auto value = [options objectForKey:key];
        [_defaults setObject:value forKey:key];
    }

    [self updateOptions];
}

- (void)exit {
    logger()->debug("[IPC] remote call: exit");
    exit(0);
}
@end
