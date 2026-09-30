import Foundation
import AppKit

enum Killer {
    /// Apple binaries. launchd respawns most of these instantly, and killing the rest
    /// breaks the session, so they're never purge candidates. /usr/local is Homebrew, not Apple.
    static let systemPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/",
                                 "/private/var/db/", "/Library/Developer/CommandLineTools/",
                                 "/Library/SystemExtensions/"]  // drivers managed by sysextd

    static func isSystem(_ p: Proc) -> Bool {
        if p.pid <= 1 || p.pid == getpid() { return true }
        if p.path.hasPrefix("/usr/local/") { return false }
        return systemPrefixes.contains(where: p.path.hasPrefix)
    }

    static func matches(_ p: Proc, _ whitelist: [WLEntry]) -> Bool {
        whitelist.contains { $0.matches(p) }
    }

    enum Group: String, CaseIterable {
        case apps = "Apps"
        case background = "Background (yours)"
        case privileged = "Root / other users — asks for password"
        case unidentified = "Unidentified path"
        /// Root and unidentified processes are opt-in per row.
        var defaultOn: Bool { self == .apps || self == .background }
    }

    struct Candidate: Identifiable {
        let proc: Proc
        let group: Group
        var id: String { proc.key }
    }

    static func guiAppPids() -> Set<Int32> {
        Set(NSWorkspace.shared.runningApplications.filter { $0.activationPolicy == .regular }.map(\.processIdentifier))
    }

    /// Everything that would die on a purge: not system, not whitelisted, and not a
    /// descendant of anything whitelisted (so whitelisted apps keep their children).
    /// `guiApps` comes from guiAppPids(), fetched on the main thread.
    static func candidates(_ procs: [Proc], whitelist: [WLEntry], guiApps: Set<Int32>) -> [Candidate] {
        let byPid = Dictionary(procs.map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        var protected: [Int32: Bool] = [:]
        func isProtected(_ pid: Int32, depth: Int = 0) -> Bool {
            if let c = protected[pid] { return c }
            guard pid > 1, depth < 64, let p = byPid[pid] else { return false }
            // Unverified signature = unknown identity: spare it (and its children) rather than guess.
            let r = p.verifying || matches(p, whitelist) || p.pid == getpid() || isProtected(p.ppid, depth: depth + 1)
            protected[pid] = r
            return r
        }
        let me = getuid()
        return procs.compactMap { p in
            guard !isSystem(p), !p.path.hasPrefix("("), !isProtected(p.pid) else { return nil }  // "(name)" = zombie
            let g: Group = !p.path.hasPrefix("/") ? .unidentified
                : p.uid != me ? .privileged : guiApps.contains(p.pid) ? .apps : .background
            return Candidate(proc: p, group: g)
        }
    }

    /// Only signals processes that are still the exact instance the user picked (same pid,
    /// start time and path). Without `force`, apps get a polite quit and the rest SIGTERM;
    /// nothing is escalated to SIGKILL behind the user's back — survivors are reported instead.
    static func kill(_ targets: [Proc], force: Bool) {
        let now = Sampler.identities(targets.map(\.pid))
        let live = targets.filter { t in now[t.pid].map { $0.start == t.start && $0.path == t.path } ?? false }
        let me = getuid()
        var privileged: [Proc] = []
        for p in live {
            if p.uid != me { privileged.append(p); continue }
            if let app = NSRunningApplication(processIdentifier: p.pid), app.activationPolicy == .regular {
                _ = force ? app.forceTerminate() : app.terminate()
            } else {
                Darwin.kill(p.pid, force ? SIGKILL : SIGTERM)
            }
        }
        if !privileged.isEmpty, let err = killPrivileged(privileged, force: force) {
            Monitor.shared.raise("Root kill failed", err, notify: false)
        }
        let skipped = targets.count - live.count
        if skipped > 0 {
            Monitor.shared.raise("Skipped \(skipped) process(es)", "They exited or their pid was reused before the kill.", notify: false)
        }
        guard !force, !live.isEmpty else { return }
        DispatchQueue.global().asyncAfter(deadline: .now() + 6) {
            let after = Sampler.identities(live.map(\.pid))
            let alive = live.filter { t in after[t.pid].map { $0.start == t.start && $0.path == t.path } ?? false }
            guard !alive.isEmpty else { return }
            let names = alive.prefix(8).map { Fmt.clean($0.displayName) }.joined(separator: ", ")
            DispatchQueue.main.async {
                Monitor.shared.raise("\(alive.count) still running after quit", names + (alive.count > 8 ? "…" : "") + ". Use Force to kill them.", notify: false)
            }
        }
    }

    /// One admin prompt for all root targets. Each kill re-checks the start time as root, so a
    /// recycled pid is left alone. Only digits and the validated start string reach the shell.
    private static func killPrivileged(_ procs: [Proc], force: Bool) -> String? {
        guard let script = privilegedScript(procs, force: force) else { return "no verifiable targets" }
        return runAsAdmin(script)
    }

    static func privilegedScript(_ procs: [Proc], force: Bool) -> String? {
        let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 :")
        let sig = force ? "-KILL" : "-TERM"
        let lines = procs.compactMap { p -> String? in
            guard p.start.unicodeScalars.allSatisfy(safe.contains) else { return nil }
            return "[ \"$(echo $(/bin/ps -o lstart= -p \(p.pid)))\" = '\(p.start)' ] && /bin/kill \(sig) \(p.pid)"
        }
        return lines.isEmpty ? nil : "export LC_ALL=C; " + lines.joined(separator: "; ") + "; true"
    }

    /// Runs a shell command as root via the standard macOS password prompt.
    /// Callers must only pass strings they built from validated data.
    @discardableResult
    static func runAsAdmin(_ shell: String) -> String? {
        let esc = shell.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        var err: NSDictionary?
        _ = NSAppleScript(source: "do shell script \"\(esc)\" with administrator privileges")?.executeAndReturnError(&err)
        if let err { return (err[NSAppleScript.errorMessage] as? String) ?? "failed" }
        return nil
    }
}
