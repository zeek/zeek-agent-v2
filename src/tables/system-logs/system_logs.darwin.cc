// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// Inspired by https://github.com/steipete/OSLogTest/blob/master/LoggingTest/OSLogStream.swift
// and https://github.com/llvm-mirror/lldb/blob/master/tools/debugserver/source/MacOSX/DarwinLog/DarwinLogCollector.cpp

#include "system_logs.h"

#include "ActivityStreamSPI.h"
#include "core/database.h"
#include "core/logger.h"
#include "util/fmt.h"
#include "util/helpers.h"

#include <csignal>

#include <unistd.h>

using namespace zeek::agent;
using namespace zeek::agent::table;

extern "C" os_activity_stream_t os_activity_stream_for_pid(pid_t pid, os_activity_stream_flag_t flags,
                                                           os_activity_stream_block_t stream_block);
extern "C" void os_activity_stream_resume(os_activity_stream_t stream);
extern "C" void os_activity_stream_cancel(os_activity_stream_t stream);
extern "C" char* os_log_copy_formatted_message(os_log_message_t log_message);
// extern "C" void os_activity_stream_set_event_handler(os_activity_stream_t stream,
//                                                      os_activity_stream_event_block_t block);

namespace {

class SystemLogsDarwin : public SystemLogs {
public:
    bool init() override;
    void activate() override;
    void deactivate() override;

    void recordEntry(os_activity_stream_entry_t entry, int error);

    os_activity_stream_t _activity_stream = nullptr;
};

database::RegisterTable<SystemLogsDarwin> _;

void SystemLogsDarwin::recordEntry(os_activity_stream_entry_t entry, int error) {
    if ( entry->type != OS_ACTIVITY_STREAM_TYPE_LOG_MESSAGE &&
         entry->type != OS_ACTIVITY_STREAM_TYPE_LEGACY_LOG_MESSAGE )
        return;

    // Notes:
    // - Can't reliably read 'category', accesses cause crashes
    // - Format seems to be always empty
    // - Subsystem seems to be always empty

    Value process;
    if ( entry->proc_imagepath ) {
        if ( auto x = split(entry->proc_imagepath, "/"); x.size() )
            process = x.back();
    }

    auto t = value::fromTime(to_time(entry->log_message.tv_gmt.tv_sec));
    auto msg = os_log_copy_formatted_message(&entry->log_message);
    newEvent({t, process, "default", msg});
    free(msg);
}

bool SystemLogsDarwin::init() { return true; }

void SystemLogsDarwin::activate() {
    // Notes:
    //
    // OS_ACTIVITY_STREAM_BUFFERED - not sure what it does exactly, but reduces CPU load
    // OS_ACTIVITY_STREAM_INFO - include INFO level
    // OS_ACTIVITY_STREAM_DEBUG - include DEBUG level
    //
    // - We don't set an event handler, doesn't seem provide anything we need.
    os_activity_stream_block_t callback = ^bool(os_activity_stream_entry_t entry, int error) { // NOLINT
      if ( ! entry )
          return true;

      recordEntry(entry, error);
      return true;
    };

    _activity_stream = os_activity_stream_for_pid(-1, OS_ACTIVITY_STREAM_BUFFERED, callback);
    os_activity_stream_resume(_activity_stream);
}

void SystemLogsDarwin::deactivate() {
    assert(_activity_stream);
    os_activity_stream_cancel(_activity_stream);
    _activity_stream = nullptr;
}

} // namespace
