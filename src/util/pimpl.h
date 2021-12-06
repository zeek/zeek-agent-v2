// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>

namespace zeek::agent {

/** Helper base class to implement the PIMPL idiom. */
template<typename T>
class Pimpl {
public:
    Pimpl() : _pimpl(std::make_unique<Implementation>()) {}
    ~Pimpl() {}

    inline const auto* pimpl() const { return _pimpl.get(); }
    inline auto* pimpl() { return _pimpl.get(); }

    Pimpl(const Pimpl& other) = delete;
    Pimpl(Pimpl&& other) = delete;
    Pimpl& operator=(const Pimpl& other) = delete;
    Pimpl& operator=(Pimpl&& other) = delete;

    struct Implementation;

private:
    std::unique_ptr<Implementation> _pimpl;
};

} // namespace zeek::agent
