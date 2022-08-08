
# Adds our compile and link options to an executble target.
macro(add_target_options target scope)
    if ( NOT HAVE_WINDOWS )
        if ( CMAKE_BUILD_TYPE STREQUAL "Debug" )
            target_compile_options(${target} ${scope} -O0)
        endif()

        target_compile_options(${target} ${scope} $<$<BOOL:${USE_WERROR}>:-Werror>)
        target_compile_options(${target} ${scope} -Wno-unused-parameter)
    endif()

    if ( HAVE_CLANG )
        target_compile_options(${target} ${scope} -Wpedantic)
        target_compile_options(${target} ${scope} -Wno-c99-designator)
        target_compile_options(${target} ${scope} -Wno-vla-extension)
    endif ()

    if ( HAVE_GCC )
        target_compile_options(${target} ${scope} -Wno-missing-field-initializers)
    endif ()

    if ( HAVE_WINDOWS )
        # Keep min and max macros from being defined, which breaks std::min and std::max.
        target_compile_options(${target} ${scope} /DNOMINMAX)
        # Reduce the amount of stuff that gets included with windows.h.
        target_compile_options(${target} ${scope} /DWIN32_LEAN_AND_MEAN)

        target_compile_options(${target} ${scope} $<$<BOOL:${USE_WERROR}>:/WX>)
        # TODO: enable this eventually after figuring out how to disable it for third party code.
        # Equivalent to -Wpedantic but on Windows
        # target_compile_options(${target} ${scope} /Wall)

        # This is needed so that the console window pops up when you run the exe.
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")

        set(APP_ICON_RESOURCE_WINDOWS "${CMAKE_SOURCE_DIR}/packaging/windows/appicon.rc")
    endif ()

    if ( NOT "${USE_DOCTEST}" )
        add_compile_definitions(DOCTEST_CONFIG_DISABLE)
    endif ()

    if ( USE_SANITIZERS )
        target_compile_options(${target} ${scope} -fsanitize=${USE_SANITIZERS})

        if ( NOT HAVE_WINDOWS )
            # Recommended flags per https://github.com/google/sanitizers/wiki/AddressSanitizer
            # GCC vs clang: https://stackoverflow.com/a/47022141
            target_compile_options(${target} ${scope} -fno-omit-frame-pointer -fno-optimize-sibling-calls) # Removed -O1
            target_link_options(${target} ${scope} -fsanitize=${USE_SANITIZERS})
        endif ()

        if ( HAVE_CLANG )
            target_compile_options(${target} ${scope} -shared-libsan)
            target_link_options(${target} ${scope} -shared-libsan -frtlib-add-rpath)
        endif ()
    endif()

endmacro()
