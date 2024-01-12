# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE processes.test.cc)

if ( HAVE_DARWIN )
    target_sources(zeek-agent PRIVATE processes.darwin.cc)
endif ()

if ( HAVE_LINUX )
    generate_bpf_code(zeek-agent processes processes.linux.bpf.c)
    target_sources(zeek-agent PRIVATE processes.linux.cc)
    target_link_libraries(zeek-agent PRIVATE pfs)
endif ()

if ( HAVE_WINDOWS )
    target_sources(zeek-agent PRIVATE processes.windows.cc)
endif ()
