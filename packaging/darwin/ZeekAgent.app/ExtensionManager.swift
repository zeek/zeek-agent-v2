// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

import NetworkExtension
import SystemExtensions

// Handles activation and configuration of our macOS system extension.
class ExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    private var version_old: String?
    private var version_new: String?

    // Trigger installation of our system extension.
    public func install() {
        let r = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "org.zeek.zeek-agent.agent", queue: .main)
        r.delegate = self
        OSSystemExtensionManager.shared.submitRequest(r)
    }

    // Enable the network extension.
    func startFilter() {
        let mgr = NEFilterManager.shared()
        guard !mgr.isEnabled else { return }

        loadFilterConfiguration { success in
            guard success else { return }
            mgr.isEnabled = true

            if mgr.providerConfiguration == nil {
                let providerConfiguration = NEFilterProviderConfiguration()
                providerConfiguration.filterSockets = true
                providerConfiguration.filterPackets = false

                mgr.providerConfiguration = providerConfiguration
                mgr.localizedDescription = "Zeek Agent"
            }

            self.saveFilterConfiguration(mgr)
        }
    }

    // Disable the network extension.
    func stopFilter() {
        let mgr = NEFilterManager.shared()
        guard mgr.isEnabled else { return }

        loadFilterConfiguration { success in
            guard success else { return }
            mgr.isEnabled = false
            self.saveFilterConfiguration(mgr)
        }
    }

    // Callback
    internal func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        var version_msg = ""

        if version_old != nil && version_new != nil {
            version_msg =
                (version_old == version_new
                    ? "Reinstalled version \(version_new!)."
                    : "Upgraded from version \(version_old!) to \(version_new!).")
            version_msg += "\n\n"
        }

        self.startFilter()
        Controller.shared.showMessage(msg: "Installed Zeek Agent", sub: version_msg)
        Controller.shared.xpc.resetConnection()
        Controller.shared.openMain()
    }

    // Callback
    internal func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Controller.shared.showMessage(
            msg: "System extension failed to install", sub: error.localizedDescription, style: .critical)
        Controller.shared.application.terminate(self)
    }

    // Callback
    internal func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // This comes after the system's dialog sending people to preferences, which seems confusing.
        // Controller.shared.showMessage(
        //    msg: "Zeek Agent needs permission to monitor the system", sub: "Please allow access in System Preferences.")
        Controller.shared.openMain()
    }

    // Callback
    internal func request(
        _ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension extension_: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        version_old = existing.bundleVersion
        version_new = extension_.bundleVersion
        return .replace
    }

    // Helper to load the current filter configuration.
    internal func loadFilterConfiguration(completionHandler: @escaping (Bool) -> Void) {
        NEFilterManager.shared().loadFromPreferences { error in
            DispatchQueue.main.async {
                var success = true
                if let error = error {
                    Controller.shared.log("Failed to load the filter configuration: \(error.localizedDescription)")
                    success = false
                }
                completionHandler(success)
            }
        }
    }

    // Helpers to save a modified filter configuration.
    internal func saveFilterConfiguration(_ mgr: NEFilterManager) {
        mgr.saveToPreferences { error in
            DispatchQueue.main.async {
                if let error = error {
                    Controller.shared.log("Failed to save the filter configuration: \(error.localizedDescription)")
                    return
                }
            }
        }
    }
}
