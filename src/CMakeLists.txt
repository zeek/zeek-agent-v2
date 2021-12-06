# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

### Setup compiler

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CheckCompiler)

add_compile_options(-Wall -Wextra)

add_compile_options(-Wno-unused-parameter)
add_compile_options($<$<BOOL:${USE_WERROR}>:-Werror>)

if ( HAVE_CLANG )
    add_compile_options(-Wpedantic)
    add_compile_options(-Wno-c99-designator)
    add_compile_options(-Wno-vla-extension)
endif ()

if ( NOT "${USE_DOCTEST}" )
    add_compile_definitions(DOCTEST_CONFIG_DISABLE)
endif ()

if ( USE_SANITIZERS )
    # Recommended flags per https://github.com/google/sanitizers/wiki/AddressSanitizer
    # GCC vs clang: https://stackoverflow.com/a/47022141
    add_compile_options(-fsanitize=${USE_SANITIZERS} -fno-omit-frame-pointer -fno-optimize-sibling-calls -O1)
    add_link_options(-fsanitize=${USE_SANITIZERS})

    if ( HAVE_CLANG )
        add_compile_options(-shared-libsan)
        add_link_options(-shared-libsan -frtlib-add-rpath)
    endif ()
endif()

### Configure build
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_BINARY_DIR}/include)

add_executable(zeek-agent main.cc)

add_subdirectory(core)
add_subdirectory(io)
add_subdirectory(tables)
add_subdirectory(util)

target_link_libraries(zeek-agent PRIVATE doctest::doctest)
target_link_libraries(zeek-agent PRIVATE fmt::fmt)
target_link_libraries(zeek-agent PRIVATE ghcFilesystem::ghc_filesystem)
target_link_libraries(zeek-agent PRIVATE pathfind::pathfind)
target_link_libraries(zeek-agent PRIVATE replxx::replxx)
target_link_libraries(zeek-agent PRIVATE spdlog::spdlog)
target_link_libraries(zeek-agent PRIVATE sqlite::sqlite)
target_link_libraries(zeek-agent PRIVATE stduuid)
target_link_libraries(zeek-agent PRIVATE tomlplusplus::tomlplusplus)
target_link_libraries(zeek-agent PRIVATE reproc++)
target_link_libraries(zeek-agent PRIVATE nlohmann_json)
target_link_libraries(zeek-agent PRIVATE ${CMAKE_DL_LIBS})

configure_file(config.h.in "${CMAKE_BINARY_DIR}/include/autogen/config.h")

# Create a test with a dependency on zeek-agent.
# See https://stackoverflow.com/a/56448477
add_test(build-zeek-agent "${CMAKE_COMMAND}" --build "${CMAKE_BINARY_DIR}" --config "$<CONFIG>" --target zeek-agent)
set_tests_properties(build-zeek-agent PROPERTIES FIXTURES_SETUP test_fixture)
add_test(NAME zeek-agent COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/zeek-agent --test)
set_tests_properties(zeek-agent PROPERTIES FIXTURES_REQUIRED test_fixture)
