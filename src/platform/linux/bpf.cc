// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "bpf.h"

#include "autogen/config.h"
#include "core/logger.h"
#include "platform.h"

#include <memory>
#include <string>
#include <utility>

#include <bpf/libbpf.h>

using namespace zeek::agent;
using namespace zeek::agent::platform::linux;

using bpf_open = void* (*)();
using bpf_load = int (*)(void*);
using bpf_attach = int (*)(void*);
using bpf_detach = void (*)(void*);
using bpf_destroy = void (*)(void*);

BPF* platform::linux::bpf() {
    static auto bpf = std::unique_ptr<BPF>{};

    if ( ! bpf )
        bpf = std::unique_ptr<BPF>(new BPF);

    return bpf.get();
}

static inline auto error(std::string_view name, std::string_view msg) {
    return result::Error(frmt("{} ({})", msg, name));
}

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    char buffer[1024];
    auto i = vsnprintf(buffer, sizeof(buffer), format, args);
    auto msg = trim(buffer);

    switch ( level ) {
        case LIBBPF_WARN: logger()->warn(msg); break;
        case LIBBPF_INFO: ZEEK_AGENT_DEBUG("bpf", msg); break;
        case LIBBPF_DEBUG: ZEEK_AGENT_TRACE("bpf", msg); break;
    }

    return i;
}

BPF::BPF() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);
    _thread = std::make_unique<std::thread>([&]() { poll(); });
}

BPF::~BPF() {
    _stopping = true;
    _thread->join();

    if ( _ring_buffers )
        ring_buffer__free(_ring_buffers);

    while ( ! _skeletons.empty() )
        destroy(_skeletons.begin()->first);
}

bool BPF::isAvailable() const {
    auto kernel = platform::linux::kernelVersion();

    if ( kernel < 508 ) {
        ZEEK_AGENT_DEBUG("bpf",
                         frmt("BPF support disabled; kernel version is too old (need at least 508, have {})", kernel));
        return false;
    }

    return true;
}

Result<void*> BPF::load(Skeleton skel) {
    const std::unique_lock lock(_skeletons_mutex);

    skel._bpf = (*reinterpret_cast<bpf_open>(skel.open))();
    if ( ! skel._bpf )
        return error(skel.name, "opening failed");

    ZEEK_AGENT_DEBUG("bpf", "opened program '{}'", skel.name);

    if ( auto err = ((*reinterpret_cast<bpf_load>(skel.load))(skel._bpf)) ) {
        (*reinterpret_cast<bpf_destroy>(skel.destroy))(skel._bpf);
        return error(skel.name, "loading failed");
    }

    ZEEK_AGENT_DEBUG("bpf", "loaded program '{}'", skel.name);

    _skeletons.emplace(skel.name, std::move(skel));
    return skel._bpf;
}

Result<Nothing> BPF::init(const std::string& name, void* ring_buffer) {
    std::unique_lock lock(_skeletons_mutex);

    if ( _skeletons.find(name) == _skeletons.end() )
        return error(name, "unknown skeleton");

    const auto& skel = _skeletons.at(name);

    if ( ! _ring_buffers ) {
        _ring_buffers = ring_buffer__new(bpf_map__fd(reinterpret_cast<struct bpf_map*>(ring_buffer)),
                                         skel.event_callback, skel.event_context, nullptr);
        if ( ! _ring_buffers ) {
            lock.unlock();
            destroy(skel.name);
            return error(skel.name, "creation of ring buffer failed");
        }
    }
    else {
        if ( auto rc = ring_buffer__add(_ring_buffers, bpf_map__fd(reinterpret_cast<struct bpf_map*>(ring_buffer)),
                                        skel.event_callback, skel.event_context);
             rc != 0 ) {
            return error(skel.name, "creation of another ring buffer failed");
        }
    }

    ZEEK_AGENT_DEBUG("bpf", "created ring buffer for program '{}'", skel.name);
    return Nothing();
}

Result<Nothing> BPF::attach(const std::string& name) const {
    const std::unique_lock lock(_skeletons_mutex);

    if ( _skeletons.find(name) == _skeletons.end() )
        return error(name, "unknown skeleton");

    const auto& skel = _skeletons.at(name);

    if ( auto err = ((*reinterpret_cast<bpf_attach>(skel.attach))(skel._bpf)) )
        return error(skel.name, "attaching failed");

    ZEEK_AGENT_DEBUG("bpf", "attached program '{}'", skel.name);
    return Nothing();
}

Result<Nothing> BPF::detach(const std::string& name) const {
    const std::unique_lock lock(_skeletons_mutex);

    if ( _skeletons.find(name) == _skeletons.end() )
        return error(name, "unknown skeleton");

    const auto& skel = _skeletons.at(name);

    (*reinterpret_cast<bpf_detach>(skel.detach))(skel._bpf);
    ZEEK_AGENT_DEBUG("bpf", "detached program '{}'", skel.name);
    return Nothing();
}

Result<Nothing> BPF::destroy(const std::string& name) {
    const std::unique_lock lock(_skeletons_mutex);

    if ( _skeletons.find(name) == _skeletons.end() )
        return error(name, "unknown skeleton");

    const auto& skel = _skeletons.at(name);

    ZEEK_AGENT_DEBUG("bpf", "destroying program '{}'", skel.name);
    (*reinterpret_cast<bpf_destroy>(skel.destroy))(skel._bpf);
    _skeletons.erase(name);

    return Nothing();
}

void BPF::poll() {
    ZEEK_AGENT_DEBUG("bpf", "polling thread starting up");

    while ( ! _stopping ) {
        if ( _ring_buffers )
            ring_buffer__poll(_ring_buffers, 100);
        else
            sleep(1);
    }

    ZEEK_AGENT_DEBUG("bpf", "polling thread shutting down");
}
