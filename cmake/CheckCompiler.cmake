# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
#
# Adapted from Zeek.

set(clang_minimum_version "9.0")
set(apple_clang_minimum_version "11.0")
set(gcc_minimum_version "9.0")
set(msvc_toolset_minimum_version "143") # Visual Studio 2022

include(CheckCXXSourceCompiles)

macro(cxx17_compile_test)
    check_cxx_source_compiles("
        #include <optional>
        int main() { std::optional<int> a; }"
        cxx17_works)

    if (NOT cxx17_works)
        message(FATAL_ERROR "failed using C++17 for compilation")
    endif ()
endmacro()

set(HAVE_GCC   no)
set(HAVE_CLANG no)
set(HAVE_MSVC  no)

if ( CMAKE_CXX_COMPILER_ID STREQUAL "GNU" )
    set(HAVE_GCC yes)
    if ( CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${gcc_minimum_version} )
        message(FATAL_ERROR "GCC version must be at least "
                "${gcc_minimum_version} for C++17 support, detected: "
                "${CMAKE_CXX_COMPILER_VERSION}")
    endif ()

elseif ( CMAKE_CXX_COMPILER_ID STREQUAL "Clang" )
    set(HAVE_CLANG yes)
    if ( CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${clang_minimum_version} )
        message(FATAL_ERROR "Clang version must be at least "
                "${clang_minimum_version} for C++17 support, detected: "
                "${CMAKE_CXX_COMPILER_VERSION}")
    endif ()
    if ( CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5 )
        set(cxx17_flag "-std=c++1z")
    endif ()
elseif ( CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" )
    set(HAVE_CLANG yes)
    if ( CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${apple_clang_minimum_version} )
        message(FATAL_ERROR "Apple Clang version must be at least "
                "${apple_clang_minimum_version} for C++17 support, detected: "
                "${CMAKE_CXX_COMPILER_VERSION}")
    endif ()
elseif ( CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(HAVE_MSVC yes)
    if ( MSVC_TOOLSET_VERSION LESS ${msvc_toolset_minimum_version} )
        message(FATAL_ERROR "MSVC Toolset version must be at least "
                "${msvc_clang_minimum_version} for C++20 support, detected: "
                "${MSVC_TOOLSET_VERSION}")
    endif()
else()
    # Unrecognized compiler: fine to be permissive of other compilers as long
    # as they are able to support C++17 and can compile the test program, but
    # we just won't be able to give specific advice on what compiler version a
    # user needs in the case it actually doesn't support C++17.
endif ()

cxx17_compile_test()
