# Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent
    PRIVATE
        ascii-table.cc
        helpers.cc
        result.cc
        socket.cc
)

if ( HAVE_POSIX )
    target_sources(zeek-agent PRIVATE socket.posix.cc)
else ()
    target_sources(zeek-agent PRIVATE socket.no-ipc.cc)
endif ()
