import Foundation

/// launchd jobs behind running processes, and switching them off for good.
/// `launchctl disable` is stored by launchd and survives reboots and the app re-registering
/// its agent; `bootout` stops the job now.
enum Launchd {
    /// Labels are reverse-DNS names; anything else never reaches a shell.
    static func validLabel(_ l: String) -> Bool {
        !l.isEmpty && l.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || "._-".unicodeScalars.contains($0) }
    }

    /// pid -> service target ("gui/501/label" or "system/label") for running jobs.
    static func jobs() -> [Int32: String] {
        var res = parseList(Sampler.run("/bin/launchctl", ["list"]), domain: "gui/\(getuid())")
        for (pid, t) in parsePrintSystem(Sampler.run("/bin/launchctl", ["print", "system"])) where res[pid] == nil { res[pid] = t }
        return res
    }

    /// `launchctl list`: "PID\tStatus\tLabel". "application.*" are per-launch app instances, not jobs.
    static func parseList(_ out: String, domain: String) -> [Int32: String] {
        var res: [Int32: String] = [:]
        for line in out.split(separator: "\n") {
            let f = line.split(separator: "\t")
            guard f.count == 3, let pid = Int32(f[0]), pid > 0 else { continue }
            let label = String(f[2])
            if validLabel(label), !label.hasPrefix("application.") { res[pid] = domain + "/" + label }
        }
        return res
    }

    /// `launchctl print system`: the "services = {" block has "pid status label" rows.
    static func parsePrintSystem(_ out: String) -> [Int32: String] {
        var res: [Int32: String] = [:]
        var inServices = false
        for line in out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t == "services = {" { inServices = true; continue }
            if inServices && t == "}" { break }
            guard inServices else { continue }
            let f = t.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard f.count == 3, let pid = Int32(f[0]), pid > 0, validLabel(String(f[2])) else { continue }
            res[pid] = "system/" + f[2]
        }
        return res
    }

    /// Disable + stop. User jobs directly; system jobs through one admin prompt.
    @discardableResult
    static func disable(_ targets: [String]) -> String? {
        let (user, system) = split(targets)
        for t in user {
            Sampler.run("/bin/launchctl", ["disable", t])
            Sampler.run("/bin/launchctl", ["bootout", t])
        }
        guard !system.isEmpty else { return nil }
        return Killer.runAsAdmin(system.map { "/bin/launchctl disable \($0); /bin/launchctl bootout \($0)" }.joined(separator: "; ") + "; true")
    }

    /// Re-enable. The job loads again at next login, or when its app registers it.
    @discardableResult
    static func enable(_ targets: [String]) -> String? {
        let (user, system) = split(targets)
        for t in user { Sampler.run("/bin/launchctl", ["enable", t]) }
        guard !system.isEmpty else { return nil }
        return Killer.runAsAdmin(system.map { "/bin/launchctl enable \($0)" }.joined(separator: "; ") + "; true")
    }

    private static func split(_ targets: [String]) -> ([String], [String]) {
        let ok = targets.filter { t in
            let parts = t.split(separator: "/")
            return parts.count >= 2 && validLabel(String(parts.last!)) && parts.dropLast().allSatisfy { validLabel(String($0)) }
        }
        return (ok.filter { $0.hasPrefix("gui/") }, ok.filter { $0.hasPrefix("system/") })
    }
}

/// A process the user never wants running: its launchd jobs are disabled, and Warden kills it
/// whenever it shows up anyway.
struct BlockEntry: Codable, Hashable, Identifiable {
    var rule: WLEntry
    var jobs: [String] = []      // service targets Warden disabled for this entry
    var killOnSight = false      // false = only autostart stopped; you can still open it yourself
    var id: String { rule.id }

    /// Apps match by bundle ID alone: a look-alike claiming that ID is fine to kill too.
    func matches(_ p: Proc) -> Bool {
        rule.kind == .app ? p.bundleID == rule.value : rule.matches(p)
    }

    static let storeKey = "blocklist.v1"
    static func load() -> [BlockEntry] {
        guard let d = UserDefaults.standard.data(forKey: storeKey) else { return [] }
        return (try? JSONDecoder().decode([BlockEntry].self, from: d)) ?? []
    }
    static func save(_ l: [BlockEntry]) {
        if let d = try? JSONEncoder().encode(l) { UserDefaults.standard.set(d, forKey: storeKey) }
    }
}
