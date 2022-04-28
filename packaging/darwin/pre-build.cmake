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

string(REPLACE " " ";" args "${CPACK_BUNDLE_APPLE_CODESIGN_PARAMETER}")

execute_process(COMMAND "/usr/bin/codesign" "--sign" "$ENV{MACOS_CERTIFICATE_APPLICATION_ID}" ${args} "${CPACK_TEMPORARY_INSTALL_DIRECTORY}/ZeekAgent.app/Contents/MacOS/ZeekAgent"
                COMMAND_ERROR_IS_FATAL ANY)
