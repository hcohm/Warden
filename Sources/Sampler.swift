import Foundation
import Darwin
import Security

struct Proc: Identifiable {
    let pid: Int32
    let ppid: Int32
    let uid: UInt32
    let cpu: Double          // % of one core
    let rss: UInt64          // bytes
    let start: String        // ps lstart, normalised; with pid it identifies one process instance
    let path: String
    var bundleID: String? = nil
    var teamID: String? = nil  // only set when the signature is valid and Apple-issued
    var written: UInt64?     // lifetime bytes written, nil = unknown (no permission)
    var writeRate: Double = 0

    var id: Int32 { pid }
    /// Survives pid reuse: a new process with the same pid has a different start time.
    var key: String { "\(pid)@\(start)" }
    var name: String { (path as NSString).lastPathComponent }
    /// Outermost bundle: "/Applications/Foo.app/.../Bar.app/x" -> "/Applications/Foo.app"
    var bundlePath: String? {
        guard let r = path.range(of: ".app/") else { return nil }
        return String(path[..<r.lowerBound]) + ".app"
    }
    var displayName: String {
        if let b = bundlePath {
            let app = ((b as NSString).lastPathComponent as NSString).deletingPathExtension
            return app == name ? app : "\(app) › \(name)"
        }
        return name
    }
}

enum Sampler {
    /// Runs a tool and returns stdout. Killed after `timeout` so a hung tool can't stall the caller.
    @discardableResult
    static func run(_ exe: String, _ args: [String], timeout: TimeInterval = 5) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = args
        p.environment = ["LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return "" }
        let watchdog = DispatchWorkItem { if p.isRunning { p.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: watchdog)
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        watchdog.cancel()
        return String(decoding: data, as: UTF8.self)
    }

    private static func tokens(_ line: Substring) -> (next: () -> Substring, rest: () -> String) {
        var s = line
        return ({
            s = s.drop(while: { $0 == " " })
            let t = s.prefix(while: { $0 != " " })
            s = s.dropFirst(t.count)
            return t
        }, { String(s.drop(while: { $0 == " " })) })
    }

    /// Full process list. /bin/ps is setuid root, so this sees every process.
    static func processes() -> [Proc] {
        let out = run("/bin/ps", ["-axo", "pid=,ppid=,uid=,%cpu=,rss=,lstart=,comm="])
        let me = getuid()
        var res: [Proc] = []
        res.reserveCapacity(1024)
        for line in out.split(separator: "\n") {
            let (next, rest) = tokens(line)
            guard let pid = Int32(next()), let ppid = Int32(next()), let uid = UInt32(next()),
                  let cpu = Double(next()), let rss = UInt64(next()) else { continue }
            let start = (0..<5).map { _ in String(next()) }.joined(separator: " ")
            var path = rest()
            if !path.hasPrefix("/"), uid == me, let full = pidPath(pid) { path = full }
            var p = Proc(pid: pid, ppid: ppid, uid: uid, cpu: cpu, rss: rss * 1024, start: start, path: path)
            if let b = p.bundlePath { (p.bundleID, p.teamID) = bundleInfo(b) }
            res.append(p)
        }
        return res
    }

    /// Current (start, path) for the given pids, to re-check identity right before signalling.
    static func identities(_ pids: [Int32]) -> [Int32: (start: String, path: String)] {
        guard !pids.isEmpty else { return [:] }
        let out = run("/bin/ps", ["-o", "pid=,lstart=,comm=", "-p", pids.map(String.init).joined(separator: ",")])
        var res: [Int32: (String, String)] = [:]
        for line in out.split(separator: "\n") {
            let (next, rest) = tokens(line)
            guard let pid = Int32(next()) else { continue }
            let start = (0..<5).map { _ in String(next()) }.joined(separator: " ")
            var path = rest()
            if !path.hasPrefix("/"), let full = pidPath(pid) { path = full }
            res[pid] = (start, path)
        }
        return res
    }

    static func pidPath(_ pid: Int32) -> String? {
        var buf = [CChar](repeating: 0, count: 4096)
        return proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : nil
    }

    // MARK: bundle identity

    private static let lock = NSLock()
    private static var bundleCache: [String: (id: String?, team: String?, at: Date)] = [:]
    private static let appleIssued: SecRequirement? = {
        var r: SecRequirement?
        SecRequirementCreateWithString("anchor apple generic" as CFString, [], &r)
        return r
    }()

    /// Bundle ID and signing team of an app bundle. Team is nil unless the signature is intact
    /// and chains to Apple, so it can't be forged with a self-signed certificate.
    static func bundleInfo(_ bundlePath: String) -> (String?, String?) {
        lock.lock()
        if let c = bundleCache[bundlePath], Date().timeIntervalSince(c.at) < 600 { lock.unlock(); return (c.id, c.team) }
        lock.unlock()
        let plist = NSDictionary(contentsOfFile: bundlePath + "/Contents/Info.plist")
        let id = plist?["CFBundleIdentifier"] as? String
        let team = teamID(bundlePath)
        lock.lock()
        bundleCache[bundlePath] = (id, team, Date())
        lock.unlock()
        return (id, team)
    }

    private static func teamID(_ path: String) -> String? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), appleIssued) == errSecSuccess
        else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let d = info as? [String: Any] else { return nil }
        return d[kSecCodeInfoTeamIdentifier as String] as? String
    }

    // MARK: stats

    /// Lifetime disk bytes written. Works for our own processes; others need root.
    static func diskWritten(_ pid: Int32) -> UInt64? {
        var info = rusage_info_v4()
        let r = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) {
                proc_pid_rusage(pid, RUSAGE_INFO_V4, $0)
            }
        }
        return r == 0 ? info.ri_diskio_byteswritten : nil
    }

    /// Roughly what Activity Monitor calls "Memory Used".
    static func memoryUsed() -> UInt64 {
        var stats = vm_statistics64()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64>.size / MemoryLayout<integer_t>.size)
        let r = withUnsafeMutablePointer(to: &stats) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count)
            }
        }
        guard r == KERN_SUCCESS else { return 0 }
        let page = UInt64(vm_kernel_page_size)
        let app = UInt64(stats.internal_page_count) - min(UInt64(stats.internal_page_count), UInt64(stats.purgeable_count))
        return (app + UInt64(stats.wire_count) + UInt64(stats.compressor_page_count)) * page
    }

    struct Disk { var free: Int64 = 0; var important: Int64 = 0; var total: Int64 = 0 }

    static func disk() -> Disk {
        let v = try? URL(fileURLWithPath: "/System/Volumes/Data").resourceValues(forKeys: [
            .volumeAvailableCapacityKey, .volumeAvailableCapacityForImportantUsageKey, .volumeTotalCapacityKey])
        return Disk(free: Int64(v?.volumeAvailableCapacity ?? 0),
                    important: v?.volumeAvailableCapacityForImportantUsage ?? 0,
                    total: Int64(v?.volumeTotalCapacity ?? 0))
    }
}

enum Fmt {
    static func bytes<T: BinaryInteger>(_ b: T) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(b), countStyle: .file)
    }
    static func rate(_ bps: Double) -> String {
        bps < 1024 ? "–" : bytes(Int64(bps)) + "/s"
    }
    static func signed(_ b: Int64) -> String {
        (b >= 0 ? "+" : "−") + bytes(abs(b))
    }
    /// File names can contain newlines and other control characters; never let them into logs.
    static func clean(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        for u in s.unicodeScalars { out.append(CharacterSet.controlCharacters.contains(u) ? "?" : u) }
        return String(out)
    }
}
