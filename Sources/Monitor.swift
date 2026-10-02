import Foundation
import AppKit
import UserNotifications

struct WardenAlert: Identifiable, Codable {
    var id = UUID()
    let date: Date
    let title: String
    let body: String
}

struct FreeSample { let date: Date; let free: Int64 }

enum Keys {
    static let writeAlertGB = "writeAlertGB"
    static let writeWindowMin = "writeWindowMin"
    static let dropAlertGB = "dropAlertGB"
    static let lowFreeGB = "lowFreeGB"
    static let enforce = "enforce"
    static let resolveHosts = "resolveHosts"
    static let uploadAlertGB = "uploadAlertGB"
    static let notifyNewDest = "notifyNewDest"

    static func register() {
        UserDefaults.standard.register(defaults: [
            writeAlertGB: 3.0,
            writeWindowMin: 10.0,
            dropAlertGB: 5.0,
            lowFreeGB: 15.0,
            enforce: false,
            resolveHosts: true,
            uploadAlertGB: 1.0,
            notifyNewDest: false,
        ])
    }
}

final class Monitor: ObservableObject {
    static let shared = Monitor()

    @Published var procs: [Proc] = []
    @Published var cpuTotal: Double = 0
    @Published var memUsed: UInt64 = 0
    @Published var disk = Sampler.Disk()
    @Published var freeHistory: [FreeSample] = []
    @Published var writeRateTotal: Double = 0
    @Published var totals: [String: UInt64] = [:]     // exe path -> bytes written since totalsSince
    @Published var totalsSince = Date()
    @Published var alerts: [WardenAlert] = []
    @Published var unseen = 0
    @Published var whitelist: [WLEntry] = WLEntry.load() {
        didSet { WLEntry.save(whitelist) }
    }
    // network
    @Published var net: [Int32: NetProc] = [:]
    @Published var netRateIn = 0.0
    @Published var netRateOut = 0.0
    @Published var netTotals: [String: NetTotal] = [:]   // exe path -> traffic since totalsSince
    @Published var newDests: [NetEvent] = []             // first time an app talked to an address
    // file activity
    @Published var openWrites: [Int32: [OpenFile]] = [:]
    @Published var files = FileSnapshot()
    /// Privacy grants by TCC client; nil = TCC databases unreadable (no Full Disk Access).
    @Published var tccGrants: [String: Set<String>]?
    /// Kill waiting for confirmation, shown as a card inside the popup.
    @Published var killRequest: KillRequest?
    /// Process shown in the detail view, if any.
    @Published var selectedPid: Int32?

    let memTotal = ProcessInfo.processInfo.physicalMemory
    private let q = DispatchQueue(label: "warden.sampler", qos: .utility)
    private var timer: Timer?
    private var tickCount = 0
    private var lastTick = Date()
    private var sampling = false  // main thread; skip ticks while a sample is still running
    // sampler-queue state
    private var lastWritten: [Int32: (key: String, bytes: UInt64)] = [:]
    private var lastPids: Set<Int32> = []
    private var firstSample = true
    private var lastNet: [Int32: (name: String, bytesIn: UInt64, bytesOut: UInt64)] = [:]
    private var prevOpenSizes: [Int32: [String: Int64]] = [:]
    private var writerSeen: [Int32: (paths: [String], at: Date)] = [:]
    // main-thread state
    private var windows: [String: [(Date, UInt64)]] = [:]
    private var upWindows: [String: [(Date, UInt64)]] = [:]
    private var knownDests: [String: Set<String>] = [:]  // exe path -> remote IPs seen
    private var netSeeded = false
    private let fs = FSWatcher(ignore: [])
    private var lastAlertAt: [String: Date] = [:]

    /// Test and preview builds use their own bundle ID, so they never touch the real app's data.
    private static let dataName: String = {
        let id = Bundle.main.bundleIdentifier ?? "local.warden.app"
        return id == "local.warden.app" ? "Warden" : id
    }()
    private let supportDir: URL = {
        let d = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(Monitor.dataName, isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }()
    private let logURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Logs/\(Monitor.dataName).log")

    private init() {
        loadState()
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.tick() }
        timer?.tolerance = 0.3
        fs.start()
        tick()
        observeLaunches()
    }

    // MARK: sampling

    private func tick() {
        guard !sampling else { return }
        sampling = true
        let now = Date()
        let dt = max(0.5, now.timeIntervalSince(lastTick))
        lastTick = now
        tickCount += 1
        let sampleDisk = tickCount % 15 == 1   // every ~30 s
        let inspect = selectedPid
        q.async { [weak self] in
            guard let self else { return }
            var list = Sampler.processes()
            let prevPids = self.lastPids
            let me = getuid()
            var newLast: [Int32: (key: String, bytes: UInt64)] = [:]
            var deltas: [String: UInt64] = [:]
            var rateTotal = 0.0
            for i in list.indices {
                let p = list[i]
                guard let w = Sampler.diskWritten(p.pid) else { continue }
                list[i].written = w
                var d: UInt64 = 0
                if let prev = self.lastWritten[p.pid], prev.key == p.key {
                    d = w >= prev.bytes ? w - prev.bytes : 0
                } else if !self.firstSample && !prevPids.contains(p.pid) {
                    d = w  // born since last sample: everything it wrote is new
                }
                newLast[p.pid] = (p.key, w)
                list[i].writeRate = Double(d) / dt
                rateTotal += list[i].writeRate
                if d > 0 { deltas[p.path, default: 0] += d }
            }
            self.lastWritten = newLast
            self.lastPids = Set(list.map(\.pid))
            let firstSample = self.firstSample
            self.firstSample = false

            // Who writes to what: scan open files only of processes that just wrote (plus the one
            // being inspected), and hand the result to the FSEvents watcher for attribution.
            var open: [Int32: [OpenFile]] = [:]
            for p in list where p.uid == me && (p.writeRate > 0 || p.pid == inspect) {
                var files = FDScan.writableFiles(p.pid)
                let prev = self.prevOpenSizes[p.pid] ?? [:]
                for i in files.indices {
                    if let s = prev[files[i].path] { files[i].growth = Double(files[i].size - s) / dt }
                }
                if !files.isEmpty { open[p.pid] = files.sorted { ($0.growth, $0.size) > ($1.growth, $1.size) } }
            }
            self.prevOpenSizes = open.mapValues { Dictionary($0.map { ($0.path, $0.size) }, uniquingKeysWith: { a, _ in a }) }
            for (pid, files) in open { self.writerSeen[pid] = (files.map(\.path), now) }
            let live = Set(list.map(\.pid))
            self.writerSeen = self.writerSeen.filter { now.timeIntervalSince($0.value.at) < 10 && live.contains($0.key) }
            var writers: [String: [Int32]] = [:]
            for (pid, v) in self.writerSeen { for path in v.paths { writers[path, default: []].append(pid) } }
            self.fs.setWriters(writers)
            self.fs.observe(open.flatMap { pid, files in files.map { (pid, $0.path, $0.size) } })

            // Network: nettop counters are cumulative, so rates come from deltas.
            var net = NetSampler.sample()
            let pathOf = Dictionary(list.map { ($0.pid, $0.path) }, uniquingKeysWith: { a, _ in a })
            var netDeltas: [String: (UInt64, UInt64)] = [:]
            var dests: [NetEvent] = []
            var netIn = 0.0, netOut = 0.0
            for (pid, np) in net {
                var np = np
                var di: UInt64 = 0, dout: UInt64 = 0
                if let prev = self.lastNet[pid], prev.name == np.name {
                    di = np.bytesIn >= prev.bytesIn ? np.bytesIn - prev.bytesIn : 0
                    dout = np.bytesOut >= prev.bytesOut ? np.bytesOut - prev.bytesOut : 0
                } else if !firstSample && !prevPids.contains(pid) {
                    (di, dout) = (np.bytesIn, np.bytesOut)
                }
                np.rateIn = Double(di) / dt
                np.rateOut = Double(dout) / dt
                netIn += np.rateIn
                netOut += np.rateOut
                net[pid] = np
                let path = pathOf[pid] ?? np.name
                if di + dout > 0 {
                    let cur = netDeltas[path] ?? (0, 0)
                    netDeltas[path] = (cur.0 + di, cur.1 + dout)
                }
                for c in np.conns where !NetSampler.isLocal(c.remoteIP) {
                    dests.append(NetEvent(date: now, path: path, ip: c.remoteIP, port: c.remotePort, proto: c.proto))
                }
            }
            self.lastNet = net.mapValues { ($0.name, $0.bytesIn, $0.bytesOut) }

            let cpu = list.reduce(0) { $0 + $1.cpu } / Double(ProcessInfo.processInfo.activeProcessorCount)
            let grants = self.tickCount % 30 == 1 ? Optional(TCC.grants()) : nil  // ~1 min
            let mem = Sampler.memoryUsed()
            let disk = sampleDisk ? Sampler.disk() : nil
            DispatchQueue.main.async {
                self.sampling = false
                self.procs = list
                self.cpuTotal = cpu
                self.memUsed = mem
                self.writeRateTotal = rateTotal
                self.openWrites = open
                if let grants { self.tccGrants = grants }
                self.net = net
                self.netRateIn = netIn
                self.netRateOut = netOut
                if self.tickCount % 5 == 1 || inspect != nil { self.fs.snapshot { self.files = $0 } }  // ~10 s, or live while inspecting
                self.account(deltas, at: now)
                self.accountNet(netDeltas, dests, at: now)
                if let disk { self.recordDisk(disk, at: now) }
                if self.tickCount % 30 == 0 { self.saveState() }
            }
        }
    }

    private func account(_ deltas: [String: UInt64], at now: Date) {
        let d = UserDefaults.standard
        let threshold = UInt64(d.double(forKey: Keys.writeAlertGB) * 1_073_741_824)
        let window = d.double(forKey: Keys.writeWindowMin) * 60
        for (path, bytes) in deltas {
            totals[path, default: 0] += bytes
            windows[path, default: []].append((now, bytes))
        }
        for (path, samples) in windows {
            let kept = samples.filter { now.timeIntervalSince($0.0) <= window }
            if kept.isEmpty { windows[path] = nil; continue }
            windows[path] = kept
            let sum = kept.reduce(0) { $0 + $1.1 }
            if threshold > 0, sum >= threshold, cooledDown("write:" + path, 30 * 60) {
                let name = (path as NSString).lastPathComponent
                raise("\(name) wrote \(Fmt.bytes(sum)) in \(Int(window / 60)) min",
                      "\(path).\(whereWriting(path)) Total since \(totalsSince.formatted(date: .abbreviated, time: .shortened)): \(Fmt.bytes(totals[path] ?? 0))")
            }
        }
    }

    private func recordDisk(_ disk: Sampler.Disk, at now: Date) {
        self.disk = disk
        freeHistory.append(FreeSample(date: now, free: disk.free))
        freeHistory.removeAll { now.timeIntervalSince($0.date) > 24 * 3600 }
        let d = UserDefaults.standard
        let dropGB = d.double(forKey: Keys.dropAlertGB)
        if dropGB > 0, let old = freeHistory.first(where: { now.timeIntervalSince($0.date) <= 600 }) {
            let drop = old.free - disk.free
            if Double(drop) >= dropGB * 1_073_741_824, cooledDown("drop", 15 * 60) {
                let top = topWritersRecent().prefix(3).map { "\(($0.0 as NSString).lastPathComponent) \(Fmt.bytes($0.1))" }
                raise("Free space dropped \(Fmt.bytes(drop)) in 10 min",
                      "Now \(Fmt.bytes(disk.free)) free." + (top.isEmpty ? "" : " Top writers: " + top.joined(separator: ", ")))
            }
        }
        let lowGB = d.double(forKey: Keys.lowFreeGB)
        if lowGB > 0, Double(disk.free) < lowGB * 1_073_741_824, cooledDown("low", 3600) {
            raise("Disk almost full", "Only \(Fmt.bytes(disk.free)) free.")
        }
    }

    /// Best guess at where a process is writing, for alert text.
    private func whereWriting(_ exe: String) -> String {
        let pids = procs.filter { $0.path == exe }.map(\.pid)
        if let t = pids.compactMap({ files.byPid[$0]?.first }).max(by: { $0.bytes < $1.bytes }), t.bytes > 0 {
            return " Mostly into \(Fmt.path(t.path)) (+\(Fmt.bytes(t.bytes)))."
        }
        if let f = pids.flatMap({ openWrites[$0] ?? [] }).max(by: { $0.size < $1.size }) {
            return " Writing \(Fmt.path(f.path)) (\(Fmt.bytes(f.size)))."
        }
        return ""
    }

    private func accountNet(_ deltas: [String: (UInt64, UInt64)], _ dests: [NetEvent], at now: Date) {
        let d = UserDefaults.standard
        let threshold = UInt64(d.double(forKey: Keys.uploadAlertGB) * 1_073_741_824)
        let window = d.double(forKey: Keys.writeWindowMin) * 60
        for (path, (i, o)) in deltas {
            netTotals[path, default: NetTotal()].bytesIn += i
            netTotals[path, default: NetTotal()].bytesOut += o
            if o > 0 { upWindows[path, default: []].append((now, o)) }
        }
        for (path, samples) in upWindows {
            let kept = samples.filter { now.timeIntervalSince($0.0) <= window }
            if kept.isEmpty { upWindows[path] = nil; continue }
            upWindows[path] = kept
            let sum = kept.reduce(0) { $0 + $1.1 }
            if threshold > 0, sum >= threshold, cooledDown("up:" + path, 30 * 60) {
                raise("\((path as NSString).lastPathComponent) uploaded \(Fmt.bytes(sum)) in \(Int(window / 60)) min", path)
            }
        }
        // First run ever: learn what's already talking instead of flooding the log.
        let seeding = !netSeeded && knownDests.isEmpty
        netSeeded = true
        let notify = d.bool(forKey: Keys.notifyNewDest)
        let resolve = d.bool(forKey: Keys.resolveHosts)
        for e in dests {
            if resolve { HostResolver.shared.request(e.ip) }
            guard knownDests[e.path, default: []].insert(e.ip).inserted, !seeding else { continue }
            if knownDests[e.path]!.count > 2000 { knownDests[e.path] = [e.ip] }
            newDests.insert(e, at: 0)
            if notify, cooledDown("dest:" + e.path, 60) {
                raise("\((e.path as NSString).lastPathComponent) → \(HostResolver.shared.name(e.ip) ?? e.ip)",
                      "New destination \(e.ip):\(e.port) (\(e.proto)). \(e.path)")
            }
        }
        if newDests.count > 500 { newDests.removeLast(newDests.count - 500) }
    }

    func topWritersRecent() -> [(String, UInt64)] {
        windows.map { ($0.key, $0.value.reduce(0) { $0 + $1.1 }) }.sorted { $0.1 > $1.1 }
    }

    // MARK: alerts

    private func cooledDown(_ key: String, _ secs: TimeInterval) -> Bool {
        if let t = lastAlertAt[key], Date().timeIntervalSince(t) < secs { return false }
        lastAlertAt[key] = Date()
        return true
    }

    func raise(_ title: String, _ body: String, notify: Bool = true) {
        // Titles and bodies embed process names/paths, which may contain control characters.
        let title = Fmt.clean(title), body = Fmt.clean(body)
        let a = WardenAlert(date: Date(), title: title, body: body)
        alerts.insert(a, at: 0)
        if alerts.count > 300 { alerts.removeLast(alerts.count - 300) }
        unseen += 1
        log("\(a.date.ISO8601Format())  \(title) — \(body)")
        guard notify else { return }
        let c = UNMutableNotificationContent()
        c.title = "Warden: " + title
        c.body = body
        c.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: a.id.uuidString, content: c, trigger: nil)) { err in
            guard err != nil else { return }
            let esc = { (s: String) in s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") }
            Sampler.run("/usr/bin/osascript", ["-e", "display notification \"\(esc(body))\" with title \"Warden: \(esc(title))\""])
        }
    }

    private func log(_ line: String) {
        let size = (try? logURL.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
        if size > 5 << 20 {  // keep one old generation
            let old = logURL.appendingPathExtension("1")
            try? FileManager.default.removeItem(at: old)
            try? FileManager.default.moveItem(at: logURL, to: old)
        }
        let data = Data((line + "\n").utf8)
        if let h = try? FileHandle(forWritingTo: logURL) {
            h.seekToEndOfFile(); h.write(data); try? h.close()
        } else {
            try? data.write(to: logURL)
        }
    }

    // MARK: enforce mode

    private func observeLaunches() {
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didLaunchApplicationNotification,
                                                          object: nil, queue: .main) { [weak self] n in
            guard let self, UserDefaults.standard.bool(forKey: Keys.enforce),
                  let app = n.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else { return }
            // Same rule as Purge (system / whitelist / whitelisted ancestor), on a fresh process list.
            let wl = self.whitelist, gui = Killer.guiAppPids(), pid = app.processIdentifier
            self.q.async {
                // Verify this one app right away, so it can't slip through while "verifying".
                if let b = app.bundleURL?.path { _ = Sampler.bundleInfo(b) }
                guard let c = Killer.candidates(Sampler.processes(), whitelist: wl, guiApps: gui)
                    .first(where: { $0.proc.pid == pid }) else { return }
                DispatchQueue.main.async {
                    app.terminate()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 3) { if !app.isTerminated { app.forceTerminate() } }
                    self.raise("Blocked \(app.localizedName ?? c.proc.name)", "Not whitelisted (enforce mode). \(c.proc.path)")
                }
            }
        }
    }

    // MARK: persistence

    private struct Saved: Codable {
        var totals: [String: UInt64]; var since: Date; var alerts: [WardenAlert]
        var netTotals: [String: NetTotal]?; var knownDests: [String: [String]]?; var newDests: [NetEvent]?
    }

    private func loadState() {
        guard let data = try? Data(contentsOf: supportDir.appendingPathComponent("state.json")),
              let s = try? JSONDecoder().decode(Saved.self, from: data) else { return }
        totals = s.totals
        totalsSince = s.since
        alerts = s.alerts
        netTotals = s.netTotals ?? [:]
        knownDests = (s.knownDests ?? [:]).mapValues(Set.init)
        newDests = s.newDests ?? []
    }

    func saveState() {
        if totals.count > 500 {  // paths churn (updaters, build outputs); keep the heavy hitters
            totals = Dictionary(uniqueKeysWithValues: totals.sorted { $0.value > $1.value }.prefix(500).map { ($0.key, $0.value) })
        }
        if netTotals.count > 500 {
            netTotals = Dictionary(uniqueKeysWithValues: netTotals.sorted { $0.value.bytesIn + $0.value.bytesOut > $1.value.bytesIn + $1.value.bytesOut }.prefix(500).map { ($0.key, $0.value) })
        }
        let s = Saved(totals: totals, since: totalsSince, alerts: Array(alerts.prefix(300)),
                      netTotals: netTotals, knownDests: knownDests.mapValues(Array.init), newDests: Array(newDests.prefix(500)))
        if let data = try? JSONEncoder().encode(s) {
            try? data.write(to: supportDir.appendingPathComponent("state.json"), options: .atomic)
        }
    }

    func resetTotals() {
        totals = [:]
        netTotals = [:]
        totalsSince = Date()
        saveState()
    }
}
