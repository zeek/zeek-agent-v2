// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// Defines the XPC protocol and API for communication between the installer app
// and the system extension.

#pragma once

#include "core/configuration.h"

#include <Foundation/Foundation.h>

@protocol IPCProtocol
- (void)getStatusWithReply:(void (^)(NSString*, NSString*, NSString*))reply;
- (void)getOptionsWithReply:(void (^)(NSDictionary<NSString*, NSString*>*))reply;
- (void)setOptions:(NSDictionary<NSString*, NSString*>*)options;
- (void)exit;
@end

@interface IPC : NSObject <NSXPCListenerDelegate, IPCProtocol>
+ (IPC*)sharedObject;
- (id)init;
- (const zeek::agent::Options&)options;
- (void)updateOptions;
@property(strong) NSUserDefaults* defaults;
@property(strong) NSXPCListener* listener;
@property zeek::agent::Configuration* configuration;
@end
