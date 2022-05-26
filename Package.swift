// swift-tools-version:5.3
//
// We don't use this for the actualy build. We have it only so that
// sourcekit-lsp knows about our Swift code.

import PackageDescription

let package = Package(
    name: "ZeekAgent",
    platforms: [.macOS("12.0")],
    targets: [
        .target(name: "ZeekAgent", path: "packaging/darwin/ZeekAgent.app"),
    ]
)
