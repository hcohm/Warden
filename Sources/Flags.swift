import Foundation
import SQLite3

/// A reason to look twice at a process. Heuristics, not verdicts: each carries its explanation.
struct Flag: Hashable, Identifiable {
    enum Kind: Int { case suspicious, bloat, permission }
    let kind: Kind
    let label: String
    let why: String
    var id: String { label }
}

enum Flags {
    /// Everything the rules need beyond the process itself, built once per refresh.
    struct Context {
        var mainRunning: Set<String> = []        // bundle paths whose main executable is running
        var grants: [String: Set<String>] = [:]  // TCC client (bundle ID or path) -> permission names
        var net: [Int32: NetProc] = [:]

        init(procs: [Proc], net: [Int32: NetProc], grants: [String: Set<String>]?) {
            for p in procs {
                if let b = p.bundlePath, Sampler.mainExecutable(b) == p.path { mainRunning.insert(b) }
            }
            self.net = net
            self.grants = grants ?? [:]
        }
    }

    static let idleAfter: TimeInterval = 3 * 86400
    private static let home = FileManager.default.homeDirectoryForCurrentUser.path
    private static let oddPlaces: [(String, String)] = [
        ("/tmp/", "temp folder"), ("/private/tmp/", "temp folder"), ("/private/var/folders/", "temp folder"),
        ("/var/folders/", "temp folder"), ("/Users/Shared/", "/Users/Shared"),
        (home + "/Downloads/", "Downloads"), (home + "/Library/Caches/", "a cache folder"),
    ]
    private static let startFormat: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "EEE MMM d HH:mm:ss yyyy"
        return f
    }()

    static func started(_ p: Proc) -> Date? { startFormat.date(from: p.start) }

    static func of(_ p: Proc, _ ctx: Context) -> [Flag] {
        var f: [Flag] = []
        let n = ctx.net[p.pid]

        // suspicious
        if p.exeMissing {
            f.append(Flag(kind: .suspicious, label: "Binary deleted",
                          why: "Its executable no longer exists on disk: an old version still running after an update, or something that removed itself."))
        }
        if p.signed == false {
            f.append(Flag(kind: .suspicious, label: "Unsigned",
                          why: "No valid signature from an Apple-issued certificate. Normal for things you built or got via Homebrew/pip; worth a look if you don't recognise it."))
        }
        if let place = oddPlaces.first(where: { p.path.hasPrefix($0.0) })?.1 {
            f.append(Flag(kind: .suspicious, label: "Runs from \(place)",
                          why: "Installed apps rarely run from \(place); malware and leftover installers often do."))
        } else if p.path.split(separator: "/").dropLast().contains(where: { $0.hasPrefix(".") }) {
            f.append(Flag(kind: .suspicious, label: "Hidden folder",
                          why: "Runs from a hidden folder. Common for developer tools (~/.cargo, ~/.local), also a classic hiding spot."))
        }

        // bloat / forgotten
        if let b = p.bundlePath, let main = Sampler.mainExecutable(b), main != p.path, !ctx.mainRunning.contains(b) {
            let app = ((b as NSString).lastPathComponent as NSString).deletingPathExtension
            f.append(Flag(kind: .bloat, label: "\(app) isn't open",
                          why: "A helper from \(app) keeps running although the app itself is closed."))
        }
        if p.name.lowercased().contains("update") {
            f.append(Flag(kind: .bloat, label: "Updater",
                          why: "Background updater. Usually safe to quit; the app restarts it when needed."))
        }
        if let s = started(p), Date().timeIntervalSince(s) > idleAfter, p.cpu < 0.1, p.writeRate == 0,
           (n?.conns.isEmpty ?? true) {
            f.append(Flag(kind: .bloat, label: "Idle since \(s.formatted(date: .abbreviated, time: .omitted))",
                          why: "Running for days without using CPU, disk or network right now."))
        }

        // permissions
        if p.uid == 0 {
            f.append(Flag(kind: .permission, label: "Root", why: "Runs with full administrator rights."))
        }
        if let ports = n?.listens, !ports.isEmpty {
            f.append(Flag(kind: .permission, label: "Listens on :" + ports.prefix(3).joined(separator: ", :"),
                          why: "Accepts incoming connections from other machines on the network."))
        }
        let granted = (p.bundleID.flatMap { ctx.grants[$0] } ?? []).union(ctx.grants[p.path] ?? [])
        for g in granted.sorted() {
            f.append(Flag(kind: .permission, label: g, why: TCC.explain[g] ?? "Granted in Privacy & Security."))
        }
        return f
    }
}

/// Reads macOS privacy grants (Full Disk Access, Accessibility, …) from the TCC databases.
/// Both need Full Disk Access to read; without it this returns nil.
enum TCC {
    static let names: [String: String] = [
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServiceScreenCapture": "Screen Recording",
        "kTCCServiceListenEvent": "Input Monitoring",
        "kTCCServicePostEvent": "Can send input",
        "kTCCServiceCamera": "Camera",
        "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceEndpointSecurityClient": "Endpoint Security",
    ]
    static let explain: [String: String] = [
        "Full Disk Access": "Can read every file, including mail, messages and other apps' data.",
        "Accessibility": "Can control your Mac: read the screen's UI and click or type in any app.",
        "Screen Recording": "Can see everything on screen.",
        "Input Monitoring": "Can see every keystroke, in every app.",
        "Can send input": "Can type and click as if it were you.",
        "Camera": "Allowed to use the camera.",
        "Microphone": "Allowed to use the microphone.",
        "Endpoint Security": "Can watch every process and file operation on the system.",
    ]
    static let databases = [
        "/Library/Application Support/com.apple.TCC/TCC.db",
        FileManager.default.homeDirectoryForCurrentUser.path + "/Library/Application Support/com.apple.TCC/TCC.db",
    ]

    static func grants(_ paths: [String] = databases) -> [String: Set<String>]? {
        var res: [String: Set<String>] = [:]
        var readable = false
        for path in paths {
            var db: OpaquePointer?
            // immutable=1: read-only snapshot, no -shm/-wal writes into a database we don't own.
            let uri = "file:" + (path.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? path) + "?immutable=1"
            defer { sqlite3_close(db) }
            guard sqlite3_open_v2(uri, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nil) == SQLITE_OK else { continue }
            var st: OpaquePointer?
            guard sqlite3_prepare_v2(db, "SELECT service, client FROM access WHERE auth_value >= 2", -1, &st, nil) == SQLITE_OK else { continue }
            defer { sqlite3_finalize(st) }
            readable = true
            while sqlite3_step(st) == SQLITE_ROW {
                guard let s = sqlite3_column_text(st, 0), let c = sqlite3_column_text(st, 1),
                      let name = names[String(cString: s)] else { continue }
                res[String(cString: c), default: []].insert(name)
            }
        }
        return readable ? res : nil
    }
}
