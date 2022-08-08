// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
//
// This is the container app installing Zeek Agent as a system extension.

import SwiftUI
import os.log

// For debugging, set this to true to always open the main dialog directly.
// Normally, we'd try to install the extension first if it's not running yet,
// or not the right version.
let debug_open_main_directly = false

struct MainView: View {
    enum ExtensionState {
        case Running
        case NotRunning
        case Unknown
    }

    struct ExtensionStatus {
        var version = ""
        var capabilities = ""
        var agent_id = ""
    }

    @State public var state = ExtensionState.Unknown
    @State public var status = ExtensionStatus()

    let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    @ViewBuilder private func mainBody(
        headline: String? = nil, subheadline: String? = nil, note1: String? = nil, note2: String? = nil,
        help: String? = nil
    ) -> some View {
        if let headline = headline {
            Text(.init(headline))
                .font(.headline)
                .padding(.bottom, 10)
        }

        if let subheadline = subheadline {
            Text(.init(subheadline))
                .font(.subheadline)
                .foregroundColor(.gray)
                .padding(.bottom, 10)
                .multilineTextAlignment(.center)
        }

        if let note1 = note1 {
            Text(.init(note1))
                .font(.footnote)
        }

        if let note2 = note2 {
            Text(.init(note2))
                .font(.footnote)
        }

        if let help = help {
            Text(.init(help))
                .font(.footnote)
                .padding(.top, 1)
        }
    }

    var body: some View {
        VStack {
            Spacer()
            HStack(alignment: .center) {
                if let path = Bundle.main.path(forResource: "zeek", ofType: "png") {
                    VStack {
                        Image(nsImage: NSImage(contentsOfFile: path)!)
                            .resizable()
                            .frame(width: 80, height: 80)
                            .padding(.trailing, 20)
                        Spacer()
                    }
                }

                VStack(alignment: .trailing) {
                    VStack {
                        switch state {
                        case .Unknown:
                            mainBody()

                        case .Running:
                            let headline = "Zeek Agent is running"
                            let subheadline = "Version \(status.version) \(status.capabilities)\n\nAgent ID \(status.agent_id)"

                            if status.capabilities.contains("+ES") {
                                mainBody(headline: headline, subheadline: subheadline)
                            } else {
                                mainBody(
                                    headline: headline, subheadline: subheadline,
                                    note1: "Make sure you have enabled full disk access",
                                    note2: "for the Zeek Agent in your System Preferences.",
                                    help:
                                        "Check [Security & Privacy -> Privacy -> Full Disk Access](x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles)."
                                )
                            }

                        case .NotRunning:
                            mainBody(
                                headline: "Zeek Agent is not running",
                                subheadline: nil,
                                note1: "Make sure you have allowed Zeek Agent",
                                note2: "to execute in your System Preferences.",
                                help:
                                    "Check [Security & Privacy -> General](x-apple.systempreferences:com.apple.preference.security?General)."
                            )
                        }
                    }

                    Spacer()

                    HStack {
                        Button("Configure ...") { Controller.shared.openConfiguration() }
                            .disabled(state != .Running)

                        Button("Exit") { Controller.shared.application.terminate(nil) }
                            .keyboardShortcut(.defaultAction)
                    }.padding(.top, 20)
                }
            }

            Spacer()
        }

        .onAppear { updateStatus() }
        .onReceive(timer) { _ in
            DispatchQueue.main.async {
                updateStatus()
            }
        }

        .padding(25.0)
        .fixedSize()
    }

    func updateStatus() {
        if state == .Unknown {
            state = .NotRunning
        }

        _ = Controller.shared.xpc.getStatus { version, capabilities, agent_id in
            self.state = .Running
            self.status = ExtensionStatus(version: version, capabilities: capabilities, agent_id: agent_id)
        }
    }
}

struct ConfigurationView: View {
    @State private var log_level: String = ""
    @State private var zeek_destination: String = ""
    @State private var old_options: [String: String]?

    func asOptions() -> [String: String] {
        return [
            "log.level": log_level,
            "zeek.destination": zeek_destination,
        ]
    }

    var body: some View {
        VStack(alignment: .trailing) {
            Form {
                TextField("ZeekHost", text: $zeek_destination)
                    .frame(minWidth: 300)

                Picker("Level", selection: $log_level) {
                    Text("Default").tag("")
                    Text("Debug").tag("debug")
                    Text("Info").tag("info")
                    Text("Warn").tag("warn")
                    Text("Error").tag("error")
                    Text("Off").tag("off")
                }
            }
            .onAppear {
                old_options = asOptions()
                _ = Controller.shared.xpc.getOptions { options in
                    log_level = options["log.level", default: ""]
                    zeek_destination = options["zeek.destination", default: ""]
                    old_options = asOptions()
                }
            }
            .onDisappear {
                old_options = nil
            }

            HStack {
                Button("Cancel") { Controller.shared.application.stopModal() }
                    .keyboardShortcut(.cancelAction)

                Button("Save") {
                    let new_options = asOptions()

                    if let old_options = old_options {
                        if old_options == new_options {
                            // No change.
                            Controller.shared.application.stopModal()
                            return
                        }
                    }

                    if !Controller.shared.xpc.setOptions(new_options) {
                        Controller.shared.showMessage(msg: "Could not save options.", sub: "", style: .critical)
                    }

                    Controller.shared.application.stopModal()
                }.keyboardShortcut(.defaultAction)
            }.padding(.top)
        }
        .padding(25.0)
        .fixedSize()
    }
}

struct AboutView: View {
    var body: some View {

        VStack {
            Text("**Zeek Agent**")
            Text("")

            if let version = Bundle.main.infoDictionary!["CFBundleVersion"] {
                Text("`Version \(version as! String)`").padding(.bottom)
            } else {
                Text("`Version <not available>`").padding(.bottom)
            }

            Text(
                "[GitHub](https://github.com/zeek/zeek-agent-v2)   [README](https://github.com/zeek/zeek-agent-v2#readme)   [Report Issue](https://github.com/zeek/zeek-agent-v2/issues)"
            )
            Text("")
            Text("The Zeek Agent is an endpoint agent that sends host information to Zeek for central monitoring.")
            Text("")
            Text(
                "If you have any questions or feedback, reach out on the `#zeek-agent` channel on the [Zeek Slack](https://zeek.org/community)."
            )
            Text("")
            Text(
                "[License](https://raw.githubusercontent.com/zeek/zeek-agent-v2/main/LICENSE)   [Third-party Licenses](https://raw.githubusercontent.com/zeek/zeek-agent-v2/main/3rdparty/LICENSE.3rdparty)"
            )
        }
        .padding(25.0)
        .fixedSize()
    }
}

class Controller {
    static let shared = Controller()

    public var extensions: ExtensionManager
    public var xpc: XPC
    public var application: NSApplication

    public var main_view = MainView()
    public var main: NSWindow?
    public var about_view = AboutView()
    public var about: NSWindow?

    private let logger = Logger(subsystem: "org.zeek.zeek-agent", category: "installer")

    init() {
        extensions = ExtensionManager()
        xpc = XPC()
        application = NSApplication.shared
    }

    func log(_ msg: String) {
        logger.info("\(msg, privacy: .public)")
    }

    func openMain() {
        guard main == nil else { return }
        main = openWindow(
            content: main_view, title: "Zeek Agent Installer", style: [.closable, .miniaturizable, .titled])
    }

    func closeMain() {
        main?.close()
        main = nil
    }

    func openConfiguration() {
        let window = openWindow(content: ConfigurationView(), title: "Configuration", style: [.titled])
        application.runModal(for: window)
        window.close()
    }

    func openAbout() {
        if let about = about {
            about.makeKeyAndOrderFront(about)
            return
        }

        about = openWindow(content: AboutView(), title: "About", style: [.closable, .miniaturizable, .titled])
    }

    func showMessage(msg: String, sub: String, style: NSAlert.Style = .informational) {
        let alert = NSAlert()
        alert.messageText = msg
        alert.informativeText = sub
        alert.addButton(withTitle: "OK")
        alert.icon = nil
        alert.alertStyle = style
        alert.runModal()
    }

    private func openWindow<V: View>(content: V, title: String, style: NSWindow.StyleMask) -> NSWindow {
        let controller = NSHostingController(rootView: content)
        controller.view.autoresizesSubviews = false

        let window = NSWindow(contentViewController: controller)
        //window.styleMask.formUnion(.fullSizeContentView)
        window.title = title
        window.styleMask = style
        window.center()
        window.makeKeyAndOrderFront(window)
        window.isReleasedWhenClosed = false
        return window
    }

}

class AppDelegate: NSObject, NSApplicationDelegate {
    @objc func openAbout(sender: AnyObject) {
        Controller.shared.openAbout()
    }

    @objc func extensionsRestart(sender: AnyObject) {
        Controller.shared.main_view.state = .NotRunning
        _ = Controller.shared.xpc.restart()
    }

    @objc func extensionsReinstall(sender: AnyObject) {
        Controller.shared.main_view.state = .NotRunning
        Controller.shared.closeMain()
        Controller.shared.extensions.install()
    }

    @objc func startNetworkExtension(ssender: AnyObject) {
        Controller.shared.extensions.startFilter()
    }

    @objc func stopNetworkExtension(ssender: AnyObject) {
        Controller.shared.extensions.stopFilter()
    }

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        let app_menu = NSMenuItem()
        app_menu.submenu = NSMenu(title: "Zeek Agent Installer")
        app_menu.submenu?.autoenablesItems = true
        app_menu.submenu?.addItem(
            NSMenuItem(title: "About", action: #selector(openAbout), keyEquivalent: ""))
        app_menu.submenu?.addItem(.separator())
        app_menu.submenu?.addItem(
            NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))

        let extension_menu = NSMenuItem()
        extension_menu.submenu = NSMenu(title: "Extension")
        extension_menu.submenu?.autoenablesItems = true
        extension_menu.submenu?.addItem(
            NSMenuItem(title: "Restart", action: #selector(extensionsRestart), keyEquivalent: ""))
        extension_menu.submenu?.addItem(
            NSMenuItem(title: "Reinstall", action: #selector(extensionsReinstall), keyEquivalent: ""))
        extension_menu.submenu?.addItem(
            NSMenuItem(title: "Start network extension", action: #selector(startNetworkExtension), keyEquivalent: ""))
        extension_menu.submenu?.addItem(
            NSMenuItem(title: "Stop network extension", action: #selector(stopNetworkExtension), keyEquivalent: ""))

        let main_menu = NSMenu()
        main_menu.addItem(app_menu)
        main_menu.addItem(extension_menu)

        NSApplication.shared.mainMenu = main_menu

        NSApplication.shared.setActivationPolicy(.regular)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

}

////// Main.

let delegate = AppDelegate()
Controller.shared.application.delegate = delegate

let our_version = Bundle.main.infoDictionary?["CFBundleVersion"] as? String

if debug_open_main_directly {
    Controller.shared.openMain()
} else {
    if let their_version = Controller.shared.xpc.isExtensionRunning() {
        if their_version != our_version {
            Controller.shared.extensions.install()
        } else {
            Controller.shared.openMain()
        }
    } else {
        Controller.shared.extensions.install()
    }
}

Controller.shared.application.run()
