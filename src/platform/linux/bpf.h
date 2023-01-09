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
 * Wrapper around macOS's Endpoint Security API. This encapsulates API state
 * across multiple clients, maintaining just a single internal copy.
 */
class BPF {
public:
    using EventCallback = int (*)(void* ctx, void* data, size_t data_sz);

    struct Skeleton {
        std::string name;
        void* open = nullptr;
        void* load = nullptr;
        void* attach = nullptr;
        void* detach = nullptr;
        void* destroy = nullptr;

        EventCallback event_callback = nullptr;
        void* event_context = nullptr;

        void* _bpf = nullptr;
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
    Result<void*> load(Skeleton skel);
    void poll();

    friend BPF* bpf();
    BPF();

    std::atomic<bool> _stopping = false;
    std::unique_ptr<std::thread> _thread;
    mutable std::mutex _skeletons_mutex;
    std::map<std::string, Skeleton> _skeletons;
    struct ::ring_buffer* _ring_buffers = nullptr;
};

/** Returns the global `BPF` singleton. */
BPF* bpf();

} // namespace zeek::agent::platform::linux
