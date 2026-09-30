import SwiftUI
import AppKit
import Charts
import ServiceManagement

enum Tab: String, CaseIterable { case live = "Live", disk = "Disk", net = "Network", purge = "Purge", alerts = "Alerts", settings = "Settings" }

struct RootView: View {
    @EnvironmentObject var mon: Monitor
    @AppStorage("tab") private var tab: Tab = .live

    var body: some View {
        VStack(spacing: 8) {
            Header()
            Picker("", selection: $tab) {
                ForEach(Tab.allCases, id: \.self) { t in
                    Text(t == .alerts && mon.unseen > 0 ? "Alerts (\(mon.unseen))" : t.rawValue).tag(t)
                }
            }
            .pickerStyle(.segmented).labelsHidden()
            Group {
                if let pid = mon.selectedPid {
                    ProcessDetailView(pid: pid)
                } else {
                switch tab {
                case .live: LiveView()
                case .disk: DiskView()
                case .net: NetView()
                case .purge: PurgeView()
                case .alerts: AlertsView()
                case .settings: SettingsView()
                }
                }
            }
            .frame(maxHeight: .infinity, alignment: .top)
        }
        .padding(12)
        .frame(width: 520, height: 620)
        .onChange(of: tab) { _, t in
            mon.selectedPid = nil
            if t == .alerts { mon.unseen = 0 }
        }
    }
}

struct Header: View {
    @EnvironmentObject var mon: Monitor
    var body: some View {
        HStack(spacing: 14) {
            Stat(label: "CPU", value: String(format: "%.0f%%", mon.cpuTotal), hot: mon.cpuTotal > 70)
            Stat(label: "Memory", value: "\(Fmt.bytes(mon.memUsed)) / \(Fmt.bytes(mon.memTotal))",
                 hot: Double(mon.memUsed) / Double(mon.memTotal) > 0.85)
            Stat(label: "Disk free", value: Fmt.bytes(mon.disk.free), hot: mon.disk.free < 20 << 30)
            Stat(label: "Writing", value: Fmt.rate(mon.writeRateTotal), hot: mon.writeRateTotal > 100 * 1_048_576)
            Spacer()
            Button { NSApp.terminate(nil) } label: { Image(systemName: "power") }
                .buttonStyle(.borderless).help("Quit Warden")
        }
    }
}

struct Stat: View {
    let label: String, value: String, hot: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.system(.callout, design: .rounded).monospacedDigit().weight(.semibold))
                .foregroundStyle(hot ? .red : .primary)
        }
    }
}

// MARK: Live

enum SortKey: String, CaseIterable { case cpu = "CPU", mem = "Memory", write = "Writes" }

struct LiveView: View {
    @EnvironmentObject var mon: Monitor
    @State private var query = ""
    @AppStorage("sort") private var sort: SortKey = .cpu
    @AppStorage("mineOnly") private var mineOnly = false

    var rows: [Proc] {
        var l = mon.procs
        if mineOnly { let me = getuid(); l = l.filter { $0.uid == me } }
        if !query.isEmpty { l = l.filter { $0.path.localizedCaseInsensitiveContains(query) || String($0.pid) == query } }
        switch sort {
        case .cpu: l.sort { $0.cpu > $1.cpu }
        case .mem: l.sort { $0.rss > $1.rss }
        case .write: l.sort { ($0.writeRate, $0.written ?? 0) > ($1.writeRate, $1.written ?? 0) }
        }
        return Array(l.prefix(80))
    }

    var body: some View {
        VStack(spacing: 6) {
            HStack {
                TextField("Filter by name, path or pid", text: $query).textFieldStyle(.roundedBorder)
                Picker("", selection: $sort) { ForEach(SortKey.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
                    .labelsHidden().frame(width: 95)
                Toggle("Mine", isOn: $mineOnly).toggleStyle(.checkbox)
            }
            HStack {
                Text("Process").frame(maxWidth: .infinity, alignment: .leading)
                Text("CPU").frame(width: 50, alignment: .trailing)
                Text("Mem").frame(width: 70, alignment: .trailing)
                Text("Write").frame(width: 80, alignment: .trailing)
            }
            .font(.caption).foregroundStyle(.secondary).padding(.horizontal, 6)
            List(rows) { p in ProcRow(p: p) }
                .listStyle(.plain)
            Text("Write stats aren't available for root processes yet.")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }
}

struct ProcRow: View {
    @EnvironmentObject var mon: Monitor
    let p: Proc
    @State private var systemKill: Bool?  // force flag while the system-process warning is up
    var body: some View {
        HStack(spacing: 6) {
            AppIcon(path: p.bundlePath ?? p.path)
            VStack(alignment: .leading, spacing: 0) {
                Text(p.displayName).lineLimit(1)
                Text("\(p.pid) · \(p.uid == 0 ? "root" : p.uid == getuid() ? "you" : "uid \(p.uid)")"
                     + (p.verifying ? " · verifying signature…" : Killer.matches(p, mon.whitelist) ? " · whitelisted" : ""))
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Text(String(format: "%.1f", p.cpu)).frame(width: 50, alignment: .trailing)
                .foregroundStyle(p.cpu > 50 ? .red : .primary)
            Text(Fmt.bytes(p.rss)).frame(width: 70, alignment: .trailing)
            Text(Fmt.rate(p.writeRate)).frame(width: 80, alignment: .trailing)
                .foregroundStyle(p.writeRate > 20 * 1_048_576 ? .red : .primary)
        }
        .font(.system(.callout).monospacedDigit())
        .help(p.path)
        .contentShape(Rectangle())
        .onTapGesture { mon.selectedPid = p.pid }
        .contextMenu { ProcMenu(p: p, systemKill: $systemKill) }
        .confirmationDialog("Kill system process “\(p.name)”?",
                            isPresented: Binding(get: { systemKill != nil }, set: { if !$0 { systemKill = nil } })) {
            Button(systemKill == true ? "Force Kill" : "Terminate", role: .destructive) {
                Killer.kill([p], force: systemKill == true)
                systemKill = nil
            }
        } message: {
            Text("This is part of macOS. launchd will usually restart it, and some (loginwindow, WindowServer) end your session immediately.")
        }
    }
}

struct ProcMenu: View {
    @EnvironmentObject var mon: Monitor
    let p: Proc
    @Binding var systemKill: Bool?
    var body: some View {
        if Killer.isSystem(p) {
            Button("Terminate…") { systemKill = false }
            Button("Force Kill…") { systemKill = true }
        } else {
            Button("Quit / Terminate") { Killer.kill([p], force: false) }
            Button("Force Kill") { Killer.kill([p], force: true) }
        }
        Divider()
        if !Killer.isSystem(p) && !Killer.matches(p, mon.whitelist) {
            let entry = WLEntry.from(p)
            Button("Whitelist “\(entry.label)”") { mon.whitelist.append(entry) }
        }
        Button("Details…") { mon.selectedPid = p.pid }
        Button("Reveal in Finder") { NSWorkspace.shared.selectFile(p.bundlePath ?? p.path, inFileViewerRootedAtPath: "") }
        Button("Copy Path") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(p.path, forType: .string) }
        if let w = p.written { Text("Written since start: \(Fmt.bytes(w))") }
    }
}

struct AppIcon: View {
    let path: String
    private static var cache: [String: NSImage] = [:]
    var body: some View {
        Image(nsImage: Self.icon(path)).resizable().frame(width: 16, height: 16)
    }
    static func icon(_ path: String) -> NSImage {
        if let i = cache[path] { return i }
        if cache.count > 300 { cache.removeAll() }  // paths churn; don't grow forever
        let i = path.hasPrefix("/") ? NSWorkspace.shared.icon(forFile: path) : NSImage(named: NSImage.applicationIconName)!
        cache[path] = i
        return i
    }
}

// MARK: Disk

struct DiskView: View {
    @EnvironmentObject var mon: Monitor
    @StateObject private var scan = DiskScanner()
    @State private var history: [String] = []

    func delta(_ secs: TimeInterval) -> Int64? {
        guard let old = mon.freeHistory.first(where: { Date().timeIntervalSince($0.date) <= secs }),
              Date().timeIntervalSince(old.date) > secs * 0.3 else { return nil }
        return mon.disk.free - old.free
    }

    var topWriters: [(String, UInt64)] {
        mon.totals.sorted { $0.value > $1.value }.prefix(8).map { ($0.key, $0.value) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    Text("\(Fmt.bytes(mon.disk.free)) free of \(Fmt.bytes(mon.disk.total))").font(.headline)
                    if mon.disk.important > mon.disk.free {
                        Text("+\(Fmt.bytes(mon.disk.important - mon.disk.free)) purgeable").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if let d = delta(3600) { Text("1h \(Fmt.signed(d))").foregroundStyle(d < 0 ? .red : .green) }
                    if let d = delta(86400) { Text("24h \(Fmt.signed(d))").foregroundStyle(d < 0 ? .red : .green) }
                }
                .font(.caption.monospacedDigit())
                if mon.freeHistory.count > 1 {
                    Chart(mon.freeHistory, id: \.date) {
                        LineMark(x: .value("Time", $0.date), y: .value("Free GB", Double($0.free) / 1e9))
                    }
                    .chartYScale(domain: .automatic(includesZero: false))
                    .frame(height: 70)
                }

                HStack {
                    Text("Top writers since \(mon.totalsSince.formatted(date: .abbreviated, time: .shortened))").font(.subheadline.bold())
                    Spacer()
                    Button("Reset") { mon.resetTotals() }.controlSize(.small)
                }
                if topWriters.isEmpty { Text("Nothing yet.").foregroundStyle(.secondary).font(.caption) }
                ForEach(topWriters, id: \.0) { path, bytes in
                    HStack {
                        AppIcon(path: path)
                        Text((path as NSString).lastPathComponent).lineLimit(1).help(path)
                        Spacer()
                        Text(Fmt.bytes(bytes)).monospacedDigit()
                    }
                    .font(.callout)
                }
                Text("Counts bytes each process physically wrote. Deleted temp files still count — it tells you who churns the disk, not only who fills it.")
                    .font(.caption2).foregroundStyle(.secondary)

                Divider()
                WriteLandingView()

                Divider()
                Text("What's taking space").font(.subheadline.bold())
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack {
                        Button("Usual suspects") { history = []; scan.scanSuspects() }
                        ForEach(DiskScanner.roots, id: \.1) { name, path in
                            Button(name) { history = []; scan.scan(path) }
                        }
                    }
                    .controlSize(.small)
                }
                HStack {
                    if !history.isEmpty {
                        Button { scan.scan(history.removeLast()) } label: { Image(systemName: "chevron.left") }.buttonStyle(.borderless)
                    }
                    if let r = scan.root { Text(r).font(.caption).lineLimit(1).truncationMode(.head) }
                    if scan.rootTotal > 0 && !scan.busy { Text(Fmt.bytes(scan.rootTotal)).font(.caption.bold()) }
                    Spacer()
                    if scan.busy {
                        ProgressView().controlSize(.small)
                        Button("Stop") { scan.cancel() }.controlSize(.small)
                    }
                }
                ForEach(scan.entries.prefix(40)) { e in
                    HStack {
                        Button {
                            if let r = scan.root, r.hasPrefix("/") { history.append(r) }
                            scan.scan(e.path)
                        } label: {
                            HStack {
                                SizeBar(frac: Double(e.bytes) / Double(max(scan.entries.first?.bytes ?? 1, 1)))
                                Text(scan.root == "Usual suspects" ? e.path.replacingOccurrences(of: DiskScanner.home, with: "~") : e.name)
                                    .lineLimit(1).truncationMode(.middle)
                                Spacer()
                                Text(Fmt.bytes(e.bytes)).monospacedDigit()
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        Button { NSWorkspace.shared.selectFile(e.path, inFileViewerRootedAtPath: "") } label: {
                            Image(systemName: "magnifyingglass")
                        }
                        .buttonStyle(.borderless).help("Reveal in Finder")
                    }
                    .font(.callout)
                }
                if let n = scan.snapshots, n > 0 {
                    Text("\(n) local Time Machine snapshot(s) are also holding space (shown as purgeable). `tmutil thinlocalsnapshots / 999999999999 4` frees them.")
                        .font(.caption2).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Text("Grant Warden Full Disk Access (Settings tab) or some folders read as 0.")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .padding(.trailing, 8)
        }
        .onAppear { if scan.snapshots == nil { scan.checkSnapshots() } }
    }
}

struct SizeBar: View {
    let frac: Double
    var body: some View {
        ZStack(alignment: .leading) {
            Capsule().fill(.quaternary)
            Capsule().fill(Color.accentColor).frame(width: 40 * max(0.03, min(1, frac)))
        }
        .frame(width: 40, height: 6)
    }
}

// MARK: Purge

struct PurgeView: View {
    @EnvironmentObject var mon: Monitor
    @State private var flipped: Set<String> = []   // proc keys toggled away from their group default
    @State private var force = false
    @State private var newEntry = ""
    @State private var addError: String?
    @State private var pending: [Proc] = []        // frozen when the dialog opens; exactly this gets killed

    var cands: [Killer.Candidate] { Killer.candidates(mon.procs, whitelist: mon.whitelist, guiApps: Killer.guiAppPids()) }
    func isOn(_ c: Killer.Candidate) -> Bool { c.group.defaultOn != flipped.contains(c.id) }

    var body: some View {
        let all = cands
        let selected = all.filter(isOn).map(\.proc)
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Toggle("Force (no save prompts)", isOn: $force).toggleStyle(.checkbox)
                Spacer()
                Button(role: .destructive) { pending = selected } label: {
                    Label("Kill \(selected.count)", systemImage: "bolt.fill")
                }
                .buttonStyle(.borderedProminent).tint(.red).disabled(selected.isEmpty)
            }
            .confirmationDialog("Kill \(pending.count) processes?",
                                isPresented: Binding(get: { !pending.isEmpty }, set: { if !$0 { pending = [] } })) {
                Button(force ? "Force Kill" : "Kill", role: .destructive) {
                    Killer.kill(pending, force: force)
                    pending = []
                    flipped = []
                }
            } message: {
                let root = pending.filter { $0.uid != getuid() }.count
                Text(pending.map(\.displayName).joined(separator: ", ")
                     + (root > 0 ? "\n\n\(root) run as root — you'll be asked for your password." : ""))
            }

            List {
                ForEach(Killer.Group.allCases, id: \.self) { g in
                    let items = all.filter { $0.group == g }
                    if !items.isEmpty {
                        Section(g.defaultOn ? g.rawValue : g.rawValue + " (tick to include)") {
                            ForEach(items) { c in
                                HStack {
                                    Toggle("", isOn: Binding(get: { isOn(c) }, set: { v in
                                        if v == g.defaultOn { flipped.remove(c.id) } else { flipped.insert(c.id) }
                                    }))
                                    .toggleStyle(.checkbox).labelsHidden()
                                    AppIcon(path: c.proc.bundlePath ?? c.proc.path)
                                    Text(c.proc.displayName).lineLimit(1).help(c.proc.path)
                                    Spacer()
                                    Text(Fmt.bytes(c.proc.rss)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                    Button("Whitelist") { mon.whitelist.append(WLEntry.from(c.proc)) }
                                        .controlSize(.small)
                                }
                            }
                        }
                    }
                }
            }
            .listStyle(.inset)

            let verifying = mon.procs.filter(\.verifying).count
            if verifying > 0 {
                Text("\(verifying) processes are still having their signatures checked and are skipped until that finishes.")
                    .font(.caption).foregroundStyle(.orange)
            }
            Text("Whitelist — apps match by bundle ID + verified signer; children of whitelisted processes are spared too. Orange = loose rule.")
                .font(.caption).foregroundStyle(.secondary)
            FlowTags(items: mon.whitelist) { e in mon.whitelist.removeAll { $0 == e } }
            HStack {
                TextField("App name, bundle ID, /exact/path, /prefix/ or *substring", text: $newEntry)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(add)
                Button("Add", action: add).disabled(newEntry.trimmingCharacters(in: .whitespaces).isEmpty)
                Button("Choose App…", action: chooseApp)
            }
            if let addError { Text(addError).font(.caption).foregroundStyle(.red) }
        }
    }

    func append(_ e: WLEntry) {
        if !mon.whitelist.contains(e) { mon.whitelist.append(e) }
    }

    func add() {
        guard let e = WLEntry.parse(newEntry) else {
            addError = "No app called “\(newEntry)”. Use an app name, bundle ID, a path starting with /, or *substring."
            return
        }
        append(e)
        addError = nil
        newEntry = ""
    }

    func chooseApp() {
        let panel = NSOpenPanel()
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.allowedContentTypes = [.application]
        panel.allowsMultipleSelection = true
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK else { return }
        for url in panel.urls { if let e = WLEntry.app(at: url.path) { append(e) } }
    }
}

struct FlowTags: View {
    let items: [WLEntry]
    let remove: (WLEntry) -> Void
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 4) {
                ForEach(items) { e in
                    HStack(spacing: 3) {
                        Text(e.label)
                        Button { remove(e) } label: { Image(systemName: "xmark.circle.fill") }.buttonStyle(.borderless)
                    }
                    .font(.caption)
                    .padding(.horizontal, 6).padding(.vertical, 3)
                    .background(Capsule().fill(e.isLoose ? AnyShapeStyle(Color.orange.opacity(0.3)) : AnyShapeStyle(.quaternary)))
                    .help(e.detail)
                }
            }
        }
    }
}

// MARK: Alerts

struct AlertsView: View {
    @EnvironmentObject var mon: Monitor
    var body: some View {
        VStack(alignment: .leading) {
            if mon.alerts.isEmpty {
                Text("Quiet so far.").foregroundStyle(.secondary)
            }
            List(mon.alerts) { a in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(a.title).bold()
                        Spacer()
                        Text(a.date.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.secondary)
                    }
                    Text(a.body).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            .listStyle(.plain)
            HStack {
                Button("Clear") { mon.alerts = []; mon.saveState() }
                Button("Open log") {
                    NSWorkspace.shared.open(FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Warden.log"))
                }
            }
            .controlSize(.small)
        }
        .onAppear { mon.unseen = 0 }
    }
}

// MARK: Settings

struct SettingsView: View {
    @EnvironmentObject var mon: Monitor
    @AppStorage(Keys.writeAlertGB) private var writeGB = 3.0
    @AppStorage(Keys.writeWindowMin) private var windowMin = 10.0
    @AppStorage(Keys.dropAlertGB) private var dropGB = 5.0
    @AppStorage(Keys.lowFreeGB) private var lowGB = 15.0
    @AppStorage(Keys.enforce) private var enforce = false
    @AppStorage(Keys.resolveHosts) private var resolveHosts = true
    @AppStorage(Keys.uploadAlertGB) private var uploadGB = 1.0
    @AppStorage(Keys.notifyNewDest) private var notifyNewDest = false
    @State private var loginOn = SMAppService.mainApp.status == .enabled
    @State private var loginError: String?

    var body: some View {
        Form {
            Section("Alerts") {
                Stepper("Process writes ≥ \(Int(writeGB)) GB", value: $writeGB, in: 1...100)
                Stepper("… within \(Int(windowMin)) min", value: $windowMin, in: 1...120)
                Stepper("Free space drops ≥ \(Int(dropGB)) GB in 10 min", value: $dropGB, in: 1...200)
                Stepper("Free space below \(Int(lowGB)) GB", value: $lowGB, in: 1...500)
            }
            Section("Behaviour") {
                Toggle("Start at login", isOn: $loginOn)
                    .onChange(of: loginOn) { _, v in
                        do { v ? try SMAppService.mainApp.register() : try SMAppService.mainApp.unregister() }
                        catch { loginError = error.localizedDescription }
                        loginOn = SMAppService.mainApp.status == .enabled
                    }
                if let loginError { Text(loginError).font(.caption).foregroundStyle(.red) }
                Toggle("Enforce whitelist: quit any non-whitelisted app as soon as it launches", isOn: $enforce)
                Text("Covers apps only, not background processes. Uses the same rules as Purge.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Network") {
                Toggle("Show host names (reverse DNS lookups)", isOn: $resolveHosts)
                Text("Asks your normal DNS server for the name behind each address. Off = raw IPs only, Warden sends nothing.")
                    .font(.caption).foregroundStyle(.secondary)
                Stepper("Alert when an app uploads ≥ \(Int(uploadGB)) GB within \(Int(windowMin)) min", value: $uploadGB, in: 1...100)
                Toggle("Notify when an app connects somewhere new", isOn: $notifyNewDest)
                Text("New destinations always appear in the Network tab; this also sends a notification.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Permissions") {
                Button("Open Full Disk Access settings") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
                }
                Text("Needed for the Disk tab to size every folder.").font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}
