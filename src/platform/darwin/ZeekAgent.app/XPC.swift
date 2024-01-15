// Copyright (c) 2021-2024 by the Zeek Project. See LICENSE for details.

import Foundation
import os.log

// XPC protocol between container app to communicate with the extension. The
// app the caller, the extension the receiver. Any changes here need to be
// reflected on the Objective-C side inside the extension.
@objc(IPCProtocol) protocol IPCProtocol {
    func getStatus(reply: @escaping (String, String, String) -> Void)
    func getOptions(reply: @escaping ([String: String]) -> Void)
    func setOptions(_ options: [String: String])
    func exit()
}

// API for the container app to communicate with the extension.
class XPC {
    private var service: IPCProtocol?
    private var connection: NSXPCConnection?

    private let logger = Logger(subsystem: "org.zeek.zeek-agent", category: "installer")

    func log(_ msg: String) {
        logger.info("\(msg, privacy: .public)")
    }

    // Returns true if the extension is currently running (i.e., we can
    // communicate with it). If yes, returns the version string of the running instance.
    public func isExtensionRunning() -> String? {
        let semaphore = DispatchSemaphore(value: 0)

        var version: String?
        _ = getStatus { version_, capabilities, agent_id in
            version = version_
            semaphore.signal()
        }

        _ = semaphore.wait(timeout: .now() + 1)
        return version
    }

    // XPC: Retrieve status from extension.
    public func getStatus(_ callback: @escaping ((String, String, String) -> Void)) -> Bool {
        guard let service = connectXPC() else { return false }
        service.getStatus(reply: callback)
        return true
    }

    // XPC: Retrieve configuration options from extension.
    public func getOptions(_ callback: @escaping (([String: String]) -> Void)) -> Bool {
        guard let service = connectXPC() else { return false }
        service.getOptions(reply: callback)
        return true
    }

    // XPC: Send options to extension.
    public func setOptions(_ options: [String: String]) -> Bool {
        guard let service = connectXPC() else { return false }
        service.setOptions(options)
        return true
    }

    // XPC: Restart the extension's process.
    public func restart() -> Bool {
        guard let service = connectXPC() else { return false }
        service.exit()
        return true
    }

    // Terminates the current XPC connection to the extension (if any), and
    // resets any internal state.
    public func resetConnection() {
        service = nil
        connection = nil
    }

    // Initiates an XPC connection the extension. If the connection is already
    // up, returns directly without doing anything.
    private func connectXPC() -> IPCProtocol? {
        if connection == nil {
            connection = NSXPCConnection(machServiceName: "org.zeek.zeek-agent.agent")
            if connection == nil {
                logger.error("Failed to create XPC connection")
                return nil
            }

            connection!.remoteObjectInterface = NSXPCInterface(with: IPCProtocol.self)
            connection!.interruptionHandler = { self.resetConnection() }
            connection!.invalidationHandler = { self.resetConnection() }
            connection!.resume()
            service = nil
        }

        if service == nil {
            service =
                connection!.remoteObjectProxyWithErrorHandler { error in
                    self.resetConnection()
                } as? IPCProtocol
        }

        return service
    }
}
