import Foundation
import AppKit
setvbuf(stdout, nil, _IONBF, 0)
var fails = 0
func check(_ ok: Bool, _ msg: String) { print(ok ? "PASS" : "FAIL", msg); if !ok { fails += 1 } }
let dir = CommandLine.arguments[1]
func spawnOrphan(_ exe: String) -> Int32 {
    let out = Sampler.run("/bin/sh", ["-c", "'\(exe)' 300 >/dev/null 2>&1 & echo $!"])
    Thread.sleep(forTimeInterval: 0.5)
    return Int32(out.trimmingCharacters(in: .whitespacesAndNewlines))!
}
func find(_ pid: Int32) -> Proc? { Sampler.processes().first { $0.pid == pid } }
func alive(_ pid: Int32) -> Bool { Darwin.kill(pid, 0) == 0 }

// Security/behaviour checks for Warden. Run via tests/run.sh; they spawn and kill their own
// throwaway processes only.

// identity
let a = spawnOrphan(dir + "/fake/sleeper")
let pa = find(a)!
let idn = Sampler.identities([a])[a]!
check(pa.start == idn.start && pa.path == idn.path, "processes() and identities() agree: \(pa.start)")
check(pa.ppid == 1, "orphan reparented to launchd")

// whitelist / candidates
let wl = WLEntry.defaults()
print("defaults:", wl.map { "\($0.label)[\($0.detail)]" })
for p in Sampler.processes() { if let b = p.bundlePath { _ = Sampler.bundleInfo(b) } }  // finish signature checks
let procs = Sampler.processes()
check(!procs.contains { $0.verifying }, "no process left verifying after checks")
let cands = Killer.candidates(procs, whitelist: wl, guiApps: Killer.guiAppPids())
check(cands.contains { $0.proc.pid == a && $0.group == .background }, "orphan sleeper is a background candidate")
let hasClaude = FileManager.default.fileExists(atPath: "/Applications/Claude.app")
if hasClaude { check(!cands.contains { $0.proc.path.contains("/Applications/Claude.app/") }, "real Claude.app protected") }
check(cands.contains { $0.proc.path.contains("Bitwarden") } || !procs.contains { $0.path.contains("Bitwarden") }, "Bitwarden no longer protected by 'Warden'")
check(!cands.contains { $0.proc.pid == getpid() }, "self never a candidate")
let fakeClaude = spawnOrphan(dir + "/Claude.app/Contents/MacOS/Claude")
let fc = find(fakeClaude)!
check(fc.bundleID == "com.anthropic.claudefordesktop" && fc.teamID == nil, "fake Claude has spoofed bundle ID but no team")
let realClaudeRule = WLEntry(kind: .app, value: "com.anthropic.claudefordesktop", team: "Q6L2SF6YDW", label: "Claude")
check(!Killer.matches(fc, wl + [realClaudeRule]), "fake Claude.app does NOT match whitelist")
if hasClaude {
    let (_, team) = Sampler.bundleInfo("/Applications/Claude.app")
    check(team == "Q6L2SF6YDW", "real Claude.app team verified: \(team ?? "nil")")
    check(WLEntry.parse("Claude")?.team == "Q6L2SF6YDW", "parse app name -> signed app entry")
} else { print("SKIP Claude.app checks (not installed)") }
check(Killer.isSystem(Proc(pid: 5, ppid: 1, uid: 0, cpu: 0, rss: 0, start: "", path: "/usr/libexec/logd")), "/usr/libexec is system")
check(!Killer.isSystem(Proc(pid: 5, ppid: 1, uid: 0, cpu: 0, rss: 0, start: "", path: "/usr/local/bin/foo")), "/usr/local is not system")
check(!Killer.isSystem(Proc(pid: 5, ppid: 1, uid: 501, cpu: 0, rss: 0, start: "", path: "/Users/x/Dock")), "binary named Dock is not system")

// signature cache must notice in-place edits (ctime changes even if mtime is forged)
let fakeBundle = dir + "/Claude.app"
_ = Sampler.bundleInfo(fakeBundle)
_ = Sampler.run("/usr/libexec/PlistBuddy", ["-c", "Set :CFBundleIdentifier com.example.changed", fakeBundle + "/Contents/Info.plist"])
_ = Sampler.run("/usr/bin/touch", ["-t", "200001010000", fakeBundle + "/Contents/Info.plist"])
check(Sampler.bundleInfo(fakeBundle).0 == "com.example.changed", "bundle cache invalidated by in-place edit with forged mtime")

// unverified processes are protected, and so are their children
let unv = Proc(pid: 90001, ppid: 1, uid: getuid(), cpu: 0, rss: 0, start: "x", path: "/Applications/New.app/Contents/MacOS/New", verifying: true)
let child = Proc(pid: 90002, ppid: 90001, uid: getuid(), cpu: 0, rss: 0, start: "x", path: "/opt/tool")
let c2 = Killer.candidates([unv, child], whitelist: [], guiApps: [])
check(c2.isEmpty, "verifying process and its child are not purge candidates")

// parse
check(WLEntry.parse("*node")?.kind == .substring, "parse *substring")
check(WLEntry.parse("/opt/homebrew/")?.matches(Proc(pid: 1, ppid: 1, uid: 1, cpu: 0, rss: 0, start: "", path: "/opt/homebrew/bin/node")) == true, "path prefix matches")
check(WLEntry.parse("/opt/homebrew/bin/node")?.matches(Proc(pid: 1, ppid: 1, uid: 1, cpu: 0, rss: 0, start: "", path: "/opt/homebrew/bin/node2")) == false, "exact path doesn't prefix-match")
check(WLEntry.parse("NoSuchAppXYZ") == nil, "unknown name rejected")

// root-kill script builder, exercised as the current user
var bad = pa; bad = Proc(pid: a, ppid: 1, uid: 0, cpu: 0, rss: 0, start: "Mon Jan 1 00:00:00 2001", path: pa.path)
_ = Sampler.run("/bin/sh", ["-c", Killer.privilegedScript([bad], force: false)!])
Thread.sleep(forTimeInterval: 0.3)
check(alive(a), "script leaves pid alone when start time differs")
let inj = Proc(pid: a, ppid: 1, uid: 0, cpu: 0, rss: 0, start: "x'; touch /tmp/pwn; '", path: pa.path)
check(Killer.privilegedScript([inj], force: false) == nil, "script rejects unsafe start string")
_ = Sampler.run("/bin/sh", ["-c", Killer.privilegedScript([pa], force: false)!])
Thread.sleep(forTimeInterval: 0.3)
check(!alive(a), "script kills when identity matches")

// Killer.kill identity checks
let b = spawnOrphan(dir + "/fake/sleeper")
let pb = find(b)!
let stale = Proc(pid: b, ppid: 1, uid: getuid(), cpu: 0, rss: 0, start: "Mon Jan 1 00:00:00 2001", path: pb.path)
Killer.kill([stale], force: true)
check(alive(b), "kill() skips a recycled pid")
check(Monitor.shared.alerts.first?.title.hasPrefix("Skipped") == true, "skip reported as alert")
Killer.kill([pb], force: true)
Thread.sleep(forTimeInterval: 0.3)
check(!alive(b), "kill() kills the exact instance")
Darwin.kill(fakeClaude, SIGKILL)

// log sanitising
Monitor.shared.raise("evil\nname", "line1\nFAKE ALERT", notify: false)
check(!Monitor.shared.alerts[0].title.contains("\n") && !Monitor.shared.alerts[0].body.contains("\n"), "control chars stripped")

// timeout
let t0 = Date(); _ = Sampler.run("/bin/sleep", ["30"], timeout: 1)
check(Date().timeIntervalSince(t0) < 3, "run() watchdog kills hung tool")
// nettop parsing
let sample = """
,bytes_in,bytes_out,
apsd.506,17708,220559,
tcp4 172.17.2.187:59207<->17.57.146.138:5223,17708,220559,
tcp4 *:49251<->*:*,,,
weird, name.777,10,20,
tcp6 2001:db8::5.50000<->2606:4700::6810:84e5.443,5,6,
udp4 *:*<->*:*,,,
"""
let parsed = NetSampler.parse(sample)
check(parsed[506]?.bytesOut == 220559 && parsed[506]?.conns.count == 1, "nettop: process + v4 connection, listener skipped")
check(parsed[506]?.conns.first?.remoteIP == "17.57.146.138" && parsed[506]?.conns.first?.remotePort == "5223", "nettop: v4 host/port")
check(parsed[777]?.name == "weird, name" && parsed[777]?.bytesIn == 10, "nettop: comma in process name")
check(parsed[777]?.conns.first?.remoteIP == "2606:4700::6810:84e5" && parsed[777]?.conns.first?.remotePort == "443", "nettop: v6 host/port")
check(NetSampler.isLocal("192.168.1.4") && NetSampler.isLocal("fe80::1%en0") && !NetSampler.isLocal("17.57.146.138"), "local address detection")
check(!NetSampler.sample().isEmpty, "live nettop sample returns processes")

// file activity: open-for-write detection + FSEvents attribution
let fsw = FSWatcher(ignore: [])
fsw.start()
Thread.sleep(forTimeInterval: 1)
let target = String(cString: realpath(dir, nil)) + "/out.bin"  // kernel reports /private/var/...
let wout = Sampler.run("/bin/sh", ["-c", "'\(dir)/writer' '\(target)' 6 >/dev/null 2>&1 & echo $!"])
let wpid = Int32(wout.trimmingCharacters(in: .whitespacesAndNewlines))!
var sawOpen = false
var sizes: [Int64] = []
for _ in 0..<4 {
    Thread.sleep(forTimeInterval: 1)
    let open = FDScan.writableFiles(wpid)
    if let f = open.first(where: { $0.path == target && $0.size > 0 }) { sawOpen = true; sizes.append(f.size) }
    fsw.setWriters(Dictionary(uniqueKeysWithValues: open.map { ($0.path, [wpid]) }))
    fsw.observe(open.map { (wpid, $0.path, $0.size) })
}
if !sawOpen { print("  fds:", FDScan.writableFiles(wpid).map(\.path)) }
check(sawOpen, "FDScan sees file open for writing: \(target)")
Thread.sleep(forTimeInterval: 2)
let snapDone = DispatchSemaphore(value: 0)
var snap = FileSnapshot()
fsw.snapshot { snap = $0; snapDone.signal() }
while snapDone.wait(timeout: .now()) == .timedOut { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
let touch = snap.byPid[wpid]?.first { $0.path == target }
let scanned = (sizes.last ?? 0) - (sizes.first ?? 0)
check(scanned > 0 && (touch?.bytes ?? 0) >= scanned, "growth attributed to writer ≥ growth seen by scans (\(Fmt.bytes(scanned))): \(Fmt.bytes(touch?.bytes ?? 0))")
check(snap.folders.contains { $0.folder == (target as NSString).deletingLastPathComponent && $0.pids.contains(wpid) }, "folder activity lists writer")
Darwin.kill(wpid, SIGKILL)

print(fails == 0 ? "ALL PASS" : "\(fails) FAILED")
exit(fails == 0 ? 0 : 1)
