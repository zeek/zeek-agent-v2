
if ( NOT BPFTOOL )
    message(FATAL_ERROR "BPFTOOL not available (but should be set automatically by build when on Linux")
endif ()

if ( NOT CMAKE_C_COMPILER_ID STREQUAL "Clang" )
    message(FATAL_ERROR "Must compile with clang as C compiler because of BPF support (have: ${CMAKE_C_COMPILER_ID}).")
endif ()

file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/include/autogen/bpf")

# Map target architecture (per CMAKE_SYSTEM_PROCESSOR) to architecture define
# as expected by bpf_traching.h. Add missing architectures as needed.
set(bpf_arch_aarch64 arm64)
set(bpf_arch_i386 x86)
set(bpf_arch_i686 x86)
set(bpf_arch_x86_64 x86)
set(bpf_arch "${bpf_arch_${CMAKE_SYSTEM_PROCESSOR}}")

if ( "${bpf_arch}" STREQUAL "" )
    message(FATAL_ERROR "Unknown architecture ${CMAKE_SYSTEM_PROCESSOR} for BPF, update BPF.cmake for ${CMAKE_SYSTEM_PROCESSOR}")
endif ()

# Send the object code through bpftool to get the header skeleton, which
# will contain the compiled BPF byte code. The caller will need to `#include`
# this header somewhere.
macro (generate_bpf_code target name src)
    set(lib "bpf_${name}")
    add_library(${lib} ${src})
    set_property(SOURCE ${src} APPEND PROPERTY OBJECT_DEPENDS bpftool)
    target_include_directories(${lib} PRIVATE ${BPF_INCLUDE_DIR})
    target_compile_options(${lib} PRIVATE -target bpf -O2 -D__TARGET_ARCH_${bpf_arch}) # -O2 because of https://bugzilla.redhat.com/show_bug.cgi?id=1618958

    set(skel_h "${CMAKE_BINARY_DIR}/include/autogen/bpf/${name}.skel.h")
    set(lib_skel "bpf_${name}_skel")

    add_custom_command(
        COMMAND ${BPFTOOL} gen skeleton $<TARGET_OBJECTS:${lib}> name ${name} >${skel_h}
        DEPENDS bpftool ${lib}
        OUTPUT ${skel_h}
    )

    add_custom_target(${lib_skel} DEPENDS ${skel_h})
    add_dependencies(${target} ${lib_skel})
endmacro ()
