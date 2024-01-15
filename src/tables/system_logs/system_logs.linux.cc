// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.
//
// Interface to journald. To avoid dependencies on external libraries, we spawn
// journalctl as a child process if we find it, reading from its output.

#include "system_logs.h"

#include "core/database.h"
#include "core/logger.h"
#include "util/fmt.h"
#include "util/helpers.h"

#include <chrono>
#include <iostream>
#include <vector>

#include <nlohmann/json.hpp>
#include <reproc++/run.hpp>

using namespace zeek::agent;
using namespace zeek::agent::table;

namespace {

class SystemLogsLinux : public SystemLogs {
public:
    Init init() override;
    void activate() override;
    void deactivate() override;
    void poll() override;

    void startProcess();
    void stopProcess();
    void parseJSON(const std::string& object);

    std::optional<filesystem::path> journalctl;
    std::unique_ptr<reproc::process> process;
    std::string buffer;
};

database::RegisterTable<SystemLogsLinux> _;

Table::Init SystemLogsLinux::init() {
    // See if we find 'journalctl'
    std::set<filesystem::path> candidates = {"/usr/bin/journalctl", "/usr/local/sbin/journalctl"};

    for ( const auto& p : candidates ) {
        if ( ! filesystem::is_regular_file(p) )
            continue;

        // See if we can execute it.
        reproc::options options;
        options.redirect.in.type = reproc::redirect::discard;
        options.redirect.out.type = reproc::redirect::discard;
        options.redirect.err.type = reproc::redirect::discard;

        auto [status, ec] = reproc::run(std::vector<std::string>{p.native(), "--version"}, options);
        if ( status == 0 ) {
            // It works.
            journalctl = p;
            break;
        }
    }

    if ( journalctl )
        ZEEK_AGENT_DEBUG("system_logs", "found journalctrl: {}", journalctl->native());
    else
        ZEEK_AGENT_DEBUG("system_logs", "did not find journalctrl");

    return journalctl ? Init::Available : Init::PermanentlyUnavailable;
}

void SystemLogsLinux::startProcess() {
    if ( ! journalctl )
        return;

    buffer.clear();

    reproc::options options;
    options.redirect.in.type = reproc::redirect::discard;
    options.redirect.out.type = reproc::redirect::default_;
    options.redirect.err.type = reproc::redirect::default_;

    process = std::make_unique<reproc::process>();
    std::vector<std::string> args = {journalctl->native(), "-f", "-o", "json-seq",
                                     "--output-fields=MESSAGE,PRIORITY,_EXE"};
    if ( auto ec = process->start(args, options) ) {
        logger()->warn("[system_logs] execution of {} failed, will not have data", journalctl->native());
        process.reset();
        journalctl.reset();
    }
}

void SystemLogsLinux::stopProcess() {
    if ( ! process )
        return;

    auto stop = reproc::stop_actions{
        .first = {.action = reproc::stop::terminate, .timeout = reproc::milliseconds(1000)},
        .second = {.action = reproc::stop::kill, .timeout = reproc::milliseconds::max()},
        .third = {.action = reproc::stop::kill, .timeout = reproc::milliseconds::max()},
    };

    if ( auto [status, ec] = process->stop(stop); ec ) {
        logger()->warn("[system_logs] could not stop journalctl; will stop using it");
        journalctl.reset();
    }

    process.reset();
}

void SystemLogsLinux::activate() {
    assert(! process);
    startProcess();
}

void SystemLogsLinux::deactivate() { stopProcess(); }

#include <iostream>

void SystemLogsLinux::poll() {
    if ( ! process )
        return;

    auto [events, ec] = process->poll(reproc::event::out | reproc::event::exit, reproc::milliseconds(10));

    if ( events & reproc::event::out ) {
        std::array<uint8_t, 4096> data;
        if ( auto [size, ec] = process->read(reproc::stream::out, data.begin(), data.size()); size && ! ec )
            buffer.append(reinterpret_cast<const char*>(data.begin()), size);

        // Chop buffer into JSON blocks.
        size_t cur = 0;
        while ( cur < buffer.size() ) {
            while ( buffer[cur] == '\x1e' ) // pre-msg separator
                ++cur;

            auto end = buffer.find('\n', cur); // post-msg separator
            if ( end == std::string::npos )
                // don't have a whole message
                break;

            parseJSON(buffer.substr(cur, end - cur));
            cur = end + 1;
        }

        buffer = buffer.substr(cur);
    }

    if ( events & reproc::event::exit ) {
        // Collect exit status and restart
        process->wait(reproc::milliseconds(0));
        startProcess();
        return;
    }
}

void SystemLogsLinux::parseJSON(const std::string& object) {
    try {
        auto j = nlohmann::json::parse(object);

        Value t;
        Value process;
        Value priority;
        Value msg;

        auto t_ = std::stoll(j.at("__REALTIME_TIMESTAMP").get<std::string>()); // always exists
        t = Time(std::chrono::time_point<std::chrono::system_clock>(std::chrono::microseconds(t_)));

        for ( const auto& i : std::vector<std::string>{"_COMM", "_EXE", "SYSLOG_IDENTIFIER"} ) {
            if ( j.contains(i) ) {
                process = j[i];
                break;
            }
        }

        if ( j.contains("PRIORITY") )
            priority = j["PRIORITY"];

        if ( j.contains("MESSAGE") )
            msg = j["MESSAGE"];

        newEvent({t, process, priority, msg, {}});

    } catch ( const nlohmann::json::exception& e ) {
        logger()->warn("[system_logs] failed to parse JSON data: {}", e.what());
    }
}

} // namespace
