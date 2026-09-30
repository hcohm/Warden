import Foundation
import Darwin
import CoreServices

struct OpenFile: Identifiable, Hashable {
    let path: String
    let size: Int64
    var growth: Double = 0   // bytes/s since the previous scan
    var id: String { path }
}

/// Files a process has open for writing. Works for our own processes; others need root.
enum FDScan {
    private static let FWRITE: UInt32 = 0x0002  // sys/fcntl.h, kernel-only in the SDK

    static func writableFiles(_ pid: Int32) -> [OpenFile] {
        let stride = MemoryLayout<proc_fdinfo>.stride
        let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bytes > 0 else { return [] }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(bytes) / stride + 32)
        let got = fds.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
        guard got > 0 else { return [] }
        var res: [OpenFile] = []
        for fd in fds.prefix(Int(got) / stride) where fd.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) {
            var vi = vnode_fdinfowithpath()
            let size = Int32(MemoryLayout<vnode_fdinfowithpath>.size)
            guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &vi, size) == size,
                  vi.pfi.fi_openflags & FWRITE != 0,
                  UInt32(vi.pvip.vip_vi.vi_stat.vst_mode) & UInt32(S_IFMT) == UInt32(S_IFREG) else { continue }
            let path = withUnsafeBytes(of: vi.pvip.vip_path) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
            if !path.isEmpty { res.append(OpenFile(path: path, size: vi.pvip.vip_vi.vi_stat.vst_size)) }
        }
        return res
    }
}

struct FolderActivity: Identifiable {
    let folder: String
    let bytes: Int64      // net growth in the window
    let events: Int
    let pids: Set<Int32>
    var id: String { folder }
}

struct FileTouch: Identifiable {
    let path: String
    let bytes: Int64
    let events: Int
    var id: String { path }
}

struct FileSnapshot {
    var folders: [FolderActivity] = []
    var byPid: [Int32: [FileTouch]] = [:]
}

/// Tracks how much each file grew, from two sources that share one size baseline (so bytes
/// are never counted twice):
///  - open-file scans of our own processes: reliable for long-running writers, because macOS
///    coalesces repeated writes to a file that stays open into very few FSEvents;
///  - file-level FSEvents for the whole disk: catch short writes and root processes by location.
/// FSEvents records are credited to whichever of our processes had that file open for writing,
/// at event time or, failing that, when the snapshot is taken.
final class FSWatcher {
    /// Per-file activity inside one 30 s bucket. Repeated writes to a file collapse into one entry,
    /// so cost scales with files touched, not with events.
    private struct Agg { var delta: Int64 = 0; var events = 0; var pids: Set<Int32> = [] }
    private static let bucketSpan: TimeInterval = 30

    private let q = DispatchQueue(label: "warden.fsevents", qos: .utility)
    private var stream: FSEventStreamRef?
    private var lastSize: [String: Int64] = [:]
    private var buckets: [(start: Date, files: [String: Agg])] = []
    private var writers: [String: [Int32]] = [:]
    private let window: TimeInterval = 600
    private let ignore: [String]

    init(ignore: [String]) { self.ignore = ignore }

    func start() {
        var ctx = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                       retain: nil, release: nil, copyDescription: nil)
        let cb: FSEventStreamCallback = { _, info, count, paths, flags, _ in
            let me = Unmanaged<FSWatcher>.fromOpaque(info!).takeUnretainedValue()
            let arr = unsafeBitCast(paths, to: NSArray.self)
            // Copy into native Swift strings once; bridged NSStrings make every hash/compare slow.
            var native: [String] = []
            native.reserveCapacity(count)
            for case let p as NSString in arr { var s = p as String; s.makeContiguousUTF8(); native.append(s) }
            me.handle(native, Array(UnsafeBufferPointer(start: flags, count: count)))
        }
        let flags = UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagIgnoreSelf)
        guard let s = FSEventStreamCreate(nil, cb, &ctx, ["/"] as CFArray,
                                          FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 1.0, flags) else { return }
        FSEventStreamSetDispatchQueue(s, q)
        FSEventStreamStart(s)
        stream = s
    }

    /// Files currently open for writing, by path, from the latest fd scan.
    func setWriters(_ w: [String: [Int32]]) { q.async { self.writers = w } }

    /// Sizes seen by an open-file scan. Growth since the last known size is credited to `pid`.
    func observe(_ items: [(pid: Int32, path: String, size: Int64)]) {
        guard !items.isEmpty else { return }
        q.async {
            let now = Date()
            for it in items {
                if let prev = self.lastSize[it.path], prev != it.size {
                    self.record(now, it.path, it.size - prev, pid: it.pid, event: false)
                }
                self.lastSize[it.path] = it.size
            }
        }
    }

    private func record(_ now: Date, _ path: String, _ delta: Int64, pid: Int32?, event: Bool) {
        if buckets.last.map({ now.timeIntervalSince($0.start) >= Self.bucketSpan }) ?? true {
            buckets.append((now, [:]))
            buckets.removeAll { now.timeIntervalSince($0.start) > window + Self.bucketSpan }
        }
        var agg = buckets[buckets.count - 1].files[path] ?? Agg()
        agg.delta += delta
        if event { agg.events += 1 }
        if let pid { agg.pids.insert(pid) } else if let w = writers[path] { agg.pids.formUnion(w) }
        buckets[buckets.count - 1].files[path] = agg
    }

    private func handle(_ paths: [String], _ flags: [FSEventStreamEventFlags]) {
        let now = Date()
        for (path, f) in zip(paths, flags) {
            guard f & UInt32(kFSEventStreamEventFlagItemIsFile) != 0,
                  !ignore.contains(where: path.hasPrefix) else { continue }
            var st = stat()
            var delta: Int64 = 0
            if lstat(path, &st) == 0 {
                let size = Int64(st.st_size)
                let created = f & UInt32(kFSEventStreamEventFlagItemCreated) != 0
                if let prev = lastSize[path] ?? (created ? 0 : nil) { delta = size - prev }
                lastSize[path] = size
            } else if let prev = lastSize.removeValue(forKey: path) {
                delta = -prev
            }
            record(now, path, delta, pid: nil, event: true)
        }
        if lastSize.count > 200_000 { lastSize.removeAll(keepingCapacity: true) }  // crude cap; baselines rebuild
    }

    func snapshot(_ done: @escaping (FileSnapshot) -> Void) {
        q.async {
            let now = Date()
            var files: [String: Agg] = [:]
            for b in self.buckets where now.timeIntervalSince(b.start) <= self.window {
                for (path, a) in b.files {
                    var t = files[path] ?? Agg()
                    t.delta += a.delta
                    t.events += a.events
                    t.pids.formUnion(a.pids)
                    files[path] = t
                }
            }
            var folders: [String: Agg] = [:]
            var perPid: [Int32: [FileTouch]] = [:]
            for (path, var a) in files {
                if a.pids.isEmpty, let w = self.writers[path] { a.pids = Set(w) }  // late attribution
                let dir = (path as NSString).deletingLastPathComponent
                var fa = folders[dir] ?? Agg()
                fa.delta += a.delta
                fa.events += a.events
                fa.pids.formUnion(a.pids)
                folders[dir] = fa
                for pid in a.pids { perPid[pid, default: []].append(FileTouch(path: path, bytes: a.delta, events: a.events)) }
            }
            var snap = FileSnapshot()
            snap.folders = folders.map { FolderActivity(folder: $0.key, bytes: $0.value.delta, events: $0.value.events, pids: $0.value.pids) }
                .sorted { ($0.bytes, $0.events) > ($1.bytes, $1.events) }
            snap.byPid = perPid.mapValues { $0.sorted { ($0.bytes, $0.events) > ($1.bytes, $1.events) } }
            DispatchQueue.main.async { done(snap) }
        }
    }
}
