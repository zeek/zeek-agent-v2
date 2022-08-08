# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

### Setup compiler

if ( HAVE_WINDOWS )
    # We require C++20 on MSVC because designated-initializers don't exist in C++17 mode.
    set(CMAKE_CXX_STANDARD 20)
else()
    set(CMAKE_CXX_STANDARD 17)
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CheckCompiler)
include(CheckFunctions)

if ( NOT HAVE_WINDOWS )
    if ( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        add_compile_options(-O0)
    endif()

    add_compile_options($<$<BOOL:${USE_WERROR}>:-Werror>)
    add_compile_options(-Wno-unused-parameter)
endif()

if ( HAVE_CLANG )
    add_compile_options(-Wpedantic)
    add_compile_options(-Wno-c99-designator)
    add_compile_options(-Wno-vla-extension)
endif ()

if ( HAVE_GCC )
    add_compile_options(-Wno-missing-field-initializers)
endif ()

if ( HAVE_WINDOWS )
    # Keep min and max macros from being defined, which breaks std::min and std::max.
    add_compile_options(/DNOMINMAX)
    # Reduce the amount of stuff that gets included with windows.h.
    add_compile_options(/DWIN32_LEAN_AND_MEAN)

    add_compile_options($<$<BOOL:${USE_WERROR}>:/WX>)
    # TODO: enable this eventually after figuring out how to disable it for third party code.
    # Equivalent to -Wpedantic but on Windows
#    add_compile_options(/Wall)

    # This is needed so that the console window pops up when you run the exe.
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")

    set(APP_ICON_RESOURCE_WINDOWS "${CMAKE_SOURCE_DIR}/packaging/windows/appicon.rc")
endif ()

if ( NOT "${USE_DOCTEST}" )
    add_compile_definitions(DOCTEST_CONFIG_DISABLE)
endif ()

if ( USE_SANITIZERS )
    add_compile_options(-fsanitize=${USE_SANITIZERS})

    if ( NOT HAVE_WINDOWS )
        # Recommended flags per https://github.com/google/sanitizers/wiki/AddressSanitizer
        # GCC vs clang: https://stackoverflow.com/a/47022141
        add_compile_options(-fno-omit-frame-pointer -fno-optimize-sibling-calls) # Removed -O1
        add_link_options(-fsanitize=${USE_SANITIZERS})
    endif ()

    if ( HAVE_CLANG )
        add_compile_options(-shared-libsan)
        add_link_options(-shared-libsan -frtlib-add-rpath)
    endif ()
endif()

### Configure build
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_BINARY_DIR}/include)

add_executable(zeek-agent main.cc ${APP_ICON_RESOURCE_WINDOWS})

add_subdirectory(core)
add_subdirectory(io)
add_subdirectory(platform)
add_subdirectory(tables)
add_subdirectory(util)

# Ensure that we include the our Broker version even if existing includes may lead us elswhere.
target_include_directories(zeek-agent PRIVATE $<TARGET_PROPERTY:broker_static,INCLUDE_DIRECTORIES>)

target_link_libraries(zeek-agent PRIVATE ${CMAKE_DL_LIBS})
target_link_libraries(zeek-agent PRIVATE broker_static)
target_link_libraries(zeek-agent PRIVATE doctest::doctest)
target_link_libraries(zeek-agent PRIVATE fmt::fmt)
target_link_libraries(zeek-agent PRIVATE ghcFilesystem::ghc_filesystem)
target_link_libraries(zeek-agent PRIVATE nlohmann_json)
target_link_libraries(zeek-agent PRIVATE ixwebsocket::ixwebsocket)
target_link_libraries(zeek-agent PRIVATE pathfind::pathfind)
target_link_libraries(zeek-agent PRIVATE replxx::replxx)
target_link_libraries(zeek-agent PRIVATE reproc++)
target_link_libraries(zeek-agent PRIVATE spdlog::spdlog)
target_link_libraries(zeek-agent PRIVATE sqlite::sqlite)
target_link_libraries(zeek-agent PRIVATE stduuid)
target_link_libraries(zeek-agent PRIVATE tomlplusplus::tomlplusplus)
target_link_libraries(zeek-agent PRIVATE ztd::out_ptr)
target_link_libraries(zeek-agent PRIVATE Glob)

if ( NOT HAVE_GETOPT_LONG )
    target_link_libraries(zeek-agent PRIVATE 3rdparty:3rdparty)
endif()

if ( HAVE_WINDOWS )
    target_link_libraries(zeek-agent PRIVATE ntdll)
    target_link_libraries(zeek-agent PRIVATE ws2_32)
    target_link_libraries(zeek-agent PRIVATE iphlpapi)
    target_link_libraries(zeek-agent PRIVATE wbemuuid)
    target_link_libraries(zeek-agent PRIVATE shlwapi)
endif()

if ( NOT HAVE_DARWIN ) # On Darwin, we customize the install location later
    install(TARGETS zeek-agent)
endif ()

configure_file(config.h.in "${CMAKE_BINARY_DIR}/include/autogen/config.h")

# Create a test with a dependency on zeek-agent.
# See https://stackoverflow.com/a/56448477
add_test(build-zeek-agent "${CMAKE_COMMAND}" --build "${CMAKE_BINARY_DIR}" --config "$<CONFIG>" --target zeek-agent)
set_tests_properties(build-zeek-agent PROPERTIES FIXTURES_SETUP test_fixture)
add_test(NAME zeek-agent COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/zeek-agent --test)
set_tests_properties(zeek-agent PROPERTIES FIXTURES_REQUIRED test_fixture)
