
# Always build universal version of the app (CMake doesn't support this out of
# the box).
add_executable(ZeekAgent-x86 main.swift)
add_executable(ZeekAgent-arm64 main.swift)
target_compile_options(ZeekAgent-x86 PRIVATE -target "x86_64-apple-macos${CMAKE_OSX_DEPLOYMENT_TARGET}")
target_compile_options(ZeekAgent-arm64 PRIVATE -target "arm64-apple-macos${CMAKE_OSX_DEPLOYMENT_TARGET}")

add_custom_target(ZeekAgent ALL
    COMMAND lipo -create ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ZeekAgent-x86 ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ZeekAgent-arm64 -output ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ZeekAgent
                  DEPENDS ZeekAgent-x86 ZeekAgent-arm64)

configure_file("Info.plist.app.in" "Info.plist.app")
configure_file("Info.plist.agent.in" "Info.plist.agent")
configure_file("Info.plist.network-extension.in" "Info.plist.network-extension")

set(contents "..") # target paths are releative to "Contents/contents", so "Contents" is one level up.
set(resources ".")

# Additional pieces/config for the outer app.
install(PROGRAMS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ZeekAgent DESTINATION ${contents}/MacOS)
install(FILES "embedded.provisionprofile.app" DESTINATION "${contents}" RENAME "embedded.provisionprofile")
install(FILES "zeek.png" DESTINATION "${resources}")
install(FILES "../../zeek-agent.cfg.template" DESTINATION "${resources}")
install(FILES "../../zeek-agent.cfg.template" DESTINATION "${resources}")

# System extension (the main zeek-agent binary)
set(sext_base "${contents}/Library/SystemExtensions/org.zeek.zeek-agent.agent.systemextension")
install(DIRECTORY DESTINATION "${sext_base}/Contents/MacOS")
install(DIRECTORY DESTINATION "${sext_base}/Contents/Resources")
install(TARGETS zeek-agent DESTINATION "${sext_base}/Contents/MacOS")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/Info.plist.agent" DESTINATION "${sext_base}/Contents" RENAME "Info.plist")
install(FILES "embedded.provisionprofile.agent" DESTINATION "${sext_base}/Contents" RENAME "embedded.provisionprofile")
install(FILES "ZeekAgent.icns" DESTINATION "${sext_base}/Contents/Resources")

# Network extension (helper providing network information to zeek-agent)
set(next_base "${contents}/Library/SystemExtensions/org.zeek.zeek-agent.network-extension.systemextension")
install(DIRECTORY DESTINATION "${next_base}/Contents/MacOS")
install(DIRECTORY DESTINATION "${next_base}/Contents/Resources")
add_executable(zeek-agent-network-extension NetworkExtension.swift)
install(TARGETS zeek-agent-network-extension DESTINATION "${next_base}/Contents/MacOS")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/Info.plist.network-extension" DESTINATION "${next_base}/Contents" RENAME "Info.plist")
install(FILES "embedded.provisionprofile.network-extension" DESTINATION "${next_base}/Contents" RENAME "embedded.provisionprofile")
install(FILES "ZeekAgent.icns" DESTINATION "${next_base}/Contents/Resources")
