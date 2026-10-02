import SwiftUI
import AppKit
import ServiceManagement

@main
enum Entry {
    static func main() {
        Keys.register()
        if CommandLine.arguments.contains("--dump") {  // dry run: what would a purge kill?
            for p in Sampler.processes() where p.verifying { _ = Sampler.bundleInfo(p.bundlePath ?? p.path) }  // verify all first
            let procs = Sampler.processes()
            let ctx = Flags.Context(procs: procs, net: NetSampler.sample(), grants: TCC.grants())
            for c in Killer.candidates(procs, whitelist: WLEntry.load(), guiApps: Killer.guiAppPids()) {
                let flags = Flags.of(c.proc, ctx).map(\.label).joined(separator: ", ")
                print("\(c.group)\t\(c.proc.pid)\t\(Fmt.clean(c.proc.path))" + (flags.isEmpty ? "" : "\t[\(flags)]"))
            }
            exit(0)
        }
        // One instance only: two would double every alert and race on state.json.
        if let id = Bundle.main.bundleIdentifier,
           NSRunningApplication.runningApplications(withBundleIdentifier: id).contains(where: { $0.processIdentifier != getpid() }) {
            exit(0)
        }
        WardenApp.main()
    }
}

struct WardenApp: App {
    @StateObject private var mon = Monitor.shared

    init() {
        DispatchQueue.main.async(execute: Self.askAboutLoginOnce)
    }

    /// Asks once; the answer is only recorded after registration actually succeeded.
    static func askAboutLoginOnce() {
        let d = UserDefaults.standard
        guard !d.bool(forKey: "loginPromptDone"), !d.bool(forKey: "didAutoRegisterLogin") else { return }
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "Start Warden at login?"
        a.informativeText = "You can change this later in Settings."
        a.addButton(withTitle: "Start at Login")
        a.addButton(withTitle: "Not Now")
        if a.runModal() == .alertFirstButtonReturn {
            do { try SMAppService.mainApp.register() } catch {
                Monitor.shared.raise("Couldn't enable start at login", error.localizedDescription, notify: false)
                return
            }
        }
        d.set(true, forKey: "loginPromptDone")
    }

    var body: some Scene {
        MenuBarExtra {
            RootView().environmentObject(mon)
        } label: {
            MenuLabel().environmentObject(mon)
        }
        .menuBarExtraStyle(.window)
    }
}

struct MenuLabel: View {
    @EnvironmentObject var mon: Monitor
    var body: some View {
        if mon.unseen > 0 {
            Image(systemName: "eye.trianglebadge.exclamationmark.fill")
        } else if mon.writeRateTotal > 100 * 1_048_576 {
            Image(systemName: "externaldrive.fill.badge.exclamationmark")
        } else {
            Image(systemName: "eye")
        }
    }
}
