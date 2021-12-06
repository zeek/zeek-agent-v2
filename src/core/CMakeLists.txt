# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent
    PRIVATE
        configuration.cc
        database.cc
        logger.cc
        scheduler.cc
        signal.cc
        sqlite.cc
        table.cc
)
