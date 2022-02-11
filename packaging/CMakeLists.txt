
set(CPACK_COMPONENTS_ALL "")
set(CPACK_OUTPUT_FILE_PREFIX "dist")
set(CPACK_PACKAGE_CONTACT "info@zeek.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Zeek Agent is an endpoint monitoring tool that reports host information to Zeek.")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://zeek.org")
set(CPACK_PACKAGE_RELOCATABLE yes)
set(CPACK_PACKAGE_VENDOR "Zeek Project")
set(CPACK_PACKAGE_VERSION_MAJOR "${ZEEK_AGENT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${ZEEK_AGENT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${ZEEK_AGENT_VERSION_PATCH}")
set(CPACK_SET_DESTDIR no)
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "zeek-agent-${ZEEK_AGENT_VERSION}")
set(CPACK_SOURCE_IGNORE_FILES "build[^/]*/;\.cache/;\.clangd;\.git;compile_commands.json;tmp/;\.swp$;\.pyc$;")

if ( HAVE_DARWIN )
    set (CPACK_PRE_BUILD_SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}/darwin/codesign.cmake")

    # We generate TGZs for now, because for ZIP/DMG one needs to notarize the
    # container to let Gatekeeper accept the executable. With a tarball, it's
    # sufficient to sign the binary itself.
    #
    # set(CPACK_GENERATOR "ZIP;DragNDrop")
    # set(CPACK_DMG_DISABLE_APPLICATIONS_SYMLINK yes)

    execute_process(COMMAND sw_vers -productVersion OUTPUT_VARIABLE DARWIN_VERSION)
    string(REGEX MATCH "[0-9]+" DARWIN_MAJOR_VERSION "${DARWIN_VERSION}")
    set(CPACK_SYSTEM_NAME "macos${DARWIN_MAJOR_VERSION}")

    configure_file("darwin/org.zeek.zeek-agent.plist.in" "org.zeek.zeek-agent.plist")
    # install(FILES "${CMAKE_CURRENT_BINARY_DIR}/org.zeek.zeek-agent.plist" DESTINATION "Library/LaunchDaemons/")
elseif ( HAVE_LINUX )
    set(CPACK_GENERATOR "TGZ")
    set(CPACK_SYSTEM_NAME "linux-${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif ()

set(CPACK_PACKAGE_FILE_NAME "zeek-agent-${ZEEK_AGENT_VERSION}-${CPACK_SYSTEM_NAME}")

include(CPack)
