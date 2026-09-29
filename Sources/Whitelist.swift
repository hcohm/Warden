import Foundation
import AppKit

/// One whitelist rule. Apps are matched by bundle ID + Apple-verified signing team, so a
/// look-alike name or path can't borrow the protection. Unsigned apps fall back to bundle ID
/// pinned to their exact location. Substring rules exist but are opt-in and flagged as loose.
struct WLEntry: Codable, Hashable, Identifiable {
    enum Kind: String, Codable { case app, path, substring }
    var kind: Kind
    var value: String            // bundle ID, path (trailing "/" = prefix), or substring
    var team: String? = nil      // .app: required signing team
    var pinnedPath: String? = nil  // .app without team: required bundle location
    var label: String

    var id: String { "\(kind.rawValue):\(value):\(team ?? pinnedPath ?? "")" }
    var isLoose: Bool { kind == .substring || (kind == .app && team == nil) }
    var detail: String {
        switch kind {
        case .app: return team.map { "\(value) · team \($0)" } ?? "\(value) · unsigned, pinned to \(pinnedPath ?? "?")"
        case .path: return value.hasSuffix("/") ? "anything under \(value)" : value
        case .substring: return "any path containing “\(value)” (loose)"
        }
    }

    func matches(_ p: Proc) -> Bool {
        switch kind {
        case .app:
            guard p.bundleID == value else { return false }
            if let team { return p.teamID == team }
            return p.bundlePath == pinnedPath
        case .path:
            return value.hasSuffix("/") ? p.path.hasPrefix(value) : p.path == value
        case .substring:
            return p.path.localizedCaseInsensitiveContains(value)
        }
    }

    static func app(at bundlePath: String) -> WLEntry? {
        let (id, team) = Sampler.bundleInfo(bundlePath)
        guard let id else { return nil }
        let name = ((bundlePath as NSString).lastPathComponent as NSString).deletingPathExtension
        return WLEntry(kind: .app, value: id, team: team, pinnedPath: team == nil ? bundlePath : nil, label: name)
    }

    /// The rule the "Whitelist" buttons create for a running process.
    static func from(_ p: Proc) -> WLEntry {
        if let b = p.bundlePath, let e = app(at: b) { return e }
        return WLEntry(kind: .path, value: p.path, label: p.name)
    }

    /// Text field input: "/exact/path", "/prefix/", "*substring", a bundle ID or an app name.
    static func parse(_ text: String) -> WLEntry? {
        let t = text.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("/") { return WLEntry(kind: .path, value: t, label: (t as NSString).lastPathComponent.isEmpty ? t : (t as NSString).lastPathComponent) }
        if t.hasPrefix("*") {
            let s = String(t.dropFirst()).trimmingCharacters(in: .whitespaces)
            return s.isEmpty ? nil : WLEntry(kind: .substring, value: s, label: "*" + s)
        }
        if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: t) { return app(at: url.path) }
        let name = t.hasSuffix(".app") ? t : t + ".app"
        for dir in ["/Applications", FileManager.default.homeDirectoryForCurrentUser.path + "/Applications"] {
            let path = dir + "/" + name
            if FileManager.default.fileExists(atPath: path) { return app(at: path) }
        }
        return nil
    }

    static let storeKey = "whitelist.v2"

    static func load() -> [WLEntry] {
        if let data = UserDefaults.standard.data(forKey: storeKey),
           let l = try? JSONDecoder().decode([WLEntry].self, from: data) { return l }
        // v1 stored plain substrings; keep their behaviour but mark them loose so they stand out.
        let domain = UserDefaults.standard.persistentDomain(forName: Bundle.main.bundleIdentifier ?? "") ?? [:]
        if let old = domain["whitelist"] as? [String] {
            return old.map { WLEntry(kind: .substring, value: $0, label: "*" + $0) }
        }
        return defaults()
    }

    static func save(_ l: [WLEntry]) {
        if let data = try? JSONEncoder().encode(l) { UserDefaults.standard.set(data, forKey: storeKey) }
    }

    static func defaults() -> [WLEntry] {
        var r: [WLEntry] = []
        for id in ["com.anthropic.claudefordesktop", "com.googlecode.iterm2", "com.mitchellh.ghostty",
                   "com.1password.1password", "org.pqrs.Karabiner-Elements.Settings"] {
            if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: id), let e = app(at: url.path) { r.append(e) }
        }
        // Karabiner's keyboard services live here, not in an app bundle. The folder is root-owned.
        let pqrs = "/Library/Application Support/org.pqrs/"
        if FileManager.default.fileExists(atPath: pqrs) { r.append(WLEntry(kind: .path, value: pqrs, label: "Karabiner services")) }
        return r
    }
}
