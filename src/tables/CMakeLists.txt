# Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

if ( HAVE_LINUX )
include(BPF)
endif ()

add_subdirectory(files)
add_subdirectory(processes)
add_subdirectory(sockets)
add_subdirectory(system_logs)
add_subdirectory(users)
add_subdirectory(zeek_agent)
