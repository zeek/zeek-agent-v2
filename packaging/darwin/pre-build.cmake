# execute_process(COMMAND find ${CPACK_TEMPORARY_INSTALL_DIRECTORY})

# Move binary into MacOS folder.
file(MAKE_DIRECTORY "${CPACK_TEMPORARY_INSTALL_DIRECTORY}/ZeekAgent.app/Contents/MacOS")

file(RENAME
    "${CPACK_TEMPORARY_INSTALL_DIRECTORY}/ZeekAgent.app/Contents/Resources/bin/zeek-agent"
    "${CPACK_TEMPORARY_INSTALL_DIRECTORY}/ZeekAgent.app/Contents/MacOS/ZeekAgent"
)

file(REMOVE_RECURSE "${CPACK_TEMPORARY_INSTALL_DIRECTORY}/ZeekAgent.app/Contents/Resources/bin" )

file(COPY "${CMAKE_CURRENT_LIST_DIR}/embedded.provisionprofile"
          DESTINATION "${CPACK_TEMPORARY_INSTALL_DIRECTORY}/ZeekAgent.app/Contents/")

#if ("$ENV{MACOS_CERTIFICATE_APPLICATION_ID}" STREQUAL "" OR "$ENV{MACOS_APP_ID}" STREQUAL "")
#    message(STATUS "Not running code signing: MACOS_CERTIFICATE_APPLICATION_ID/MACOS_APP_ID not set")
#    return()
#endif()

#execute_process(COMMAND ${CMAKE_CURRENT_LIST_DIR}/codesign "${CPACK_TEMPORARY_INSTALL_DIRECTORY}/${CPACK_BUNDLE_NAME}.app/Contents/Resources/bin/zeek-agent"
#               COMMAND_ERROR_IS_FATAL ANY)
