import Foundation

struct DirEntry: Identifiable {
    let path: String
    let bytes: UInt64
    var id: String { path }
    var name: String { (path as NSString).lastPathComponent }
}

final class DiskScanner: ObservableObject {
    @Published var root: String?
    @Published var entries: [DirEntry] = []
    @Published var rootTotal: UInt64 = 0
    @Published var busy = false
    @Published var snapshots: Int?
    private var proc: Process?

    static let home = FileManager.default.homeDirectoryForCurrentUser.path
    static let roots: [(String, String)] = [
        ("Home", home), ("~/Library", home + "/Library"), ("/Applications", "/Applications"),
        ("/Library", "/Library"), ("/private/var", "/private/var"), ("Whole disk", "/System/Volumes/Data"),
    ]
    /// Places that usually explain "where did 80 GB go".
    static let suspects: [String] = [
        home + "/Library/Developer/Xcode/DerivedData",
        home + "/Library/Developer/Xcode/iOS DeviceSupport",
        home + "/Library/Developer/CoreSimulator",
        home + "/Library/Containers/com.docker.docker",
        home + "/.docker", home + "/.orbstack",
        home + "/Library/Caches", home + "/.cache",
        home + "/Library/Application Support/MobileSync/Backup",
        home + "/.ollama", home + "/.lmstudio",
        home + "/.npm", home + "/.cargo", home + "/.rustup", home + "/go/pkg",
        home + "/Library/Group Containers/group.com.apple.CoreSpeech",
        home + "/Library/Mail", home + "/Library/Messages",
        home + "/Downloads", home + "/.Trash",
        "/Library/Caches", "/private/var/vm", "/private/var/folders",
        "/opt/homebrew", "/Library/Developer/CoreSimulator",
    ]

    func scan(_ path: String) {
        cancel()
        root = path
        entries = []
        busy = true
        run(["-xk", "-d", "1", path]) { [weak self] rows in
            guard let self, self.root == path else { return }
            self.rootTotal = rows.first(where: { $0.path == path })?.bytes ?? 0
            self.entries = rows.filter { $0.path != path }.sorted { $0.bytes > $1.bytes }
        }
    }

    func scanSuspects() {
        cancel()
        root = "Usual suspects"
        entries = []
        busy = true
        let existing = Self.suspects.filter { FileManager.default.fileExists(atPath: $0) }
        run(["-xsk"] + existing) { [weak self] rows in
            guard let self, self.root == "Usual suspects" else { return }
            self.rootTotal = rows.reduce(0) { $0 + $1.bytes }
            self.entries = rows.filter { $0.bytes > 50 << 20 }.sorted { $0.bytes > $1.bytes }
        }
    }

    func cancel() {
        proc?.terminate()
        proc = nil
        busy = false
    }

    func checkSnapshots() {
        DispatchQueue.global(qos: .utility).async {
            let out = Sampler.run("/usr/bin/tmutil", ["listlocalsnapshots", "/"])
            let n = out.split(separator: "\n").filter { $0.contains("com.apple.TimeMachine") }.count
            DispatchQueue.main.async { self.snapshots = n }
        }
    }

    private func run(_ args: [String], done: @escaping ([DirEntry]) -> Void) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/du")
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        proc = p
        DispatchQueue.global(qos: .userInitiated).async {
            do { try p.run() } catch {
                DispatchQueue.main.async { self.busy = false }
                return
            }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            let rows: [DirEntry] = String(decoding: data, as: UTF8.self).split(separator: "\n").compactMap { line in
                guard let tab = line.firstIndex(of: "\t"), let kb = UInt64(line[..<tab]) else { return nil }
                return DirEntry(path: String(line[line.index(after: tab)...]), bytes: kb * 1024)
            }
            DispatchQueue.main.async {
                guard self.proc === p else { return }  // superseded or cancelled
                self.proc = nil
                self.busy = false
                done(rows)
            }
        }
    }
}
