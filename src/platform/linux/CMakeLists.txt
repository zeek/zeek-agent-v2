# Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

target_sources(zeek-agent PRIVATE platform.cc bpf.cc)
set_property(SOURCE bpf.cc APPEND PROPERTY OBJECT_DEPENDS bpftool)
target_link_libraries(zeek-agent PRIVATE bpf)
