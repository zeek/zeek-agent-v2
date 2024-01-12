// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "util/pimpl.h"
#include "util/result.h"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

struct ring_buffer;

namespace zeek::agent::platform::linux {

/**
 * Wrapper around Linux' BPF functionality. This centralizes BPF state across
 * all agent components using BPF. All public methods are thread-safe.
 */
class BPF {
public:
    using EventCallback = int (*)(void* ctx, void* data, size_t data_sz);

    /** Captures a BPF program skeleton. */
    struct Skeleton {
        std::string name;        /**< Name of the BPF program. */
        void* open = nullptr;    /**< Function pointer to the BPF program's `open` function. */
        void* load = nullptr;    /**< Function pointer to the BPF program's `load` function. */
        void* attach = nullptr;  /**< Function pointer to the BPF program's `attach` function. */
        void* detach = nullptr;  /**< Function pointer to the BPF program's `detach` function. */
        void* destroy = nullptr; /**< Function pointer to the BPF program's `destroy` function. */

        EventCallback event_callback = nullptr; /**< Callback function to be invoked when an event is received. */
        void* event_context = nullptr;          /**< Context to be passed to the event callback function. */

        void* _bpf = nullptr; /**< Pointer to the BPF program. */
    };

    ~BPF();

    /**
     * Returns true if BPF has been initialized successfully and is available
     * for use.
     */
    bool isAvailable() const;

    template<typename T>
    Result<T*> load(Skeleton skel) {
        if ( auto rc = load(std::move(skel)) )
            return reinterpret_cast<T*>(*rc);
        else
            return rc.error();
    }

    Result<Nothing> init(const std::string& name, void* ring_buffer);
    Result<Nothing> attach(const std::string& name) const;
    Result<Nothing> detach(const std::string& name) const;
    Result<Nothing> destroy(const std::string& name);

private:
    friend BPF* bpf();

    BPF();
    Result<void*> load(Skeleton skel);
    void poll();

    std::atomic<bool> _stopping = false;
    std::unique_ptr<std::thread> _thread;
    mutable std::mutex _skeletons_mutex;
    std::map<std::string, Skeleton> _skeletons;
    struct ::ring_buffer* _ring_buffers = nullptr;
};

/** Returns the global `BPF` singleton. */
BPF* bpf();

} // namespace zeek::agent::platform::linux
