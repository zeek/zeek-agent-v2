# Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent
    PRIVATE
        configuration.cc
        database.cc
        logger.cc
        scheduler.cc
        sqlite.cc
        table.cc
)

if ( HAVE_POSIX )
    target_sources(zeek-agent PRIVATE signal.posix.cc)
elseif ( HAVE_WINDOWS )
    target_sources(zeek-agent PRIVATE signal.windows.cc)
endif ()
