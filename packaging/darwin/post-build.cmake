# Validate/display signatures and entitlements to the degree we can.
foreach (pkg "${CPACK_PACKAGE_FILES}")
    string(REPLACE ".dmg" "" bundle "${pkg}")
    foreach (path
             ZeekAgent.app
             ZeekAgent.app/Contents/Library/SystemExtensions/org.zeek.zeek-agent.agent.systemextension
            )
        get_filename_component(name "${path}" NAME)
        message(STATUS "Validating ${name}")
        execute_process(COMMAND /usr/bin/codesign -vv --strict "${bundle}/${path}")
        execute_process(COMMAND /usr/bin/codesign -dv --strict "${bundle}/${path}")
        execute_process(COMMAND /usr/bin/codesign -d --entitlements - "${bundle}/${path}")
    endforeach()
endforeach()

if ( NOT "$ENV{MACOS_NOTARIZE}" STREQUAL "")
    foreach (pkg "${CPACK_PACKAGE_FILES}")
        execute_process(COMMAND ${CMAKE_CURRENT_LIST_DIR}/notarize application "${pkg}" COMMAND_ERROR_IS_FATAL ANY)
    endforeach()
else ()
    message(STATUS "Not notarizing application, MACOS_NOTARIZE not set")
endif()
