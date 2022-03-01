// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "util/result.h"

namespace zeek::agent::darwin {

class EndpointSecurity {
public:
    Result<Nothing> start();
    void stop();
};

} // namespace zeek::agent::darwin
