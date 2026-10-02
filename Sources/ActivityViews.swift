import SwiftUI
import AppKit

private func host(_ ip: String) -> String {
    guard UserDefaults.standard.bool(forKey: Keys.resolveHosts) else { return ip }
    if let n = HostResolver.shared.name(ip) { return n }
    HostResolver.shared.request(ip)  // deduplicated; shows up on the next refresh
    return ip
}

private func reveal(_ path: String) {
    NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
}

struct SectionTitle: View {
    let text: String
    var body: some View { Text(text).font(.subheadline.bold()).padding(.top, 6) }
}

// MARK: Disk tab: where writes land

struct WriteLandingView: View {
    @EnvironmentObject var mon: Monitor

    func names(_ pids: Set<Int32>) -> String {
        let n = Set(pids.compactMap { pid in mon.procs.first { $0.pid == pid }?.displayName })
        return n.isEmpty ? "unattributed" : n.sorted().joined(separator: ", ")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Where writes are landing (last 10 min)").font(.subheadline.bold())
            let top = mon.files.folders.filter { $0.bytes > 0 }.prefix(8)
            if top.isEmpty { Text("Nothing notable yet.").font(.caption).foregroundStyle(.secondary) }
            ForEach(Array(top)) { f in
                HStack {
                    VStack(alignment: .leading, spacing: 0) {
                        Text(Fmt.path(f.folder)).lineLimit(1).truncationMode(.head).help(f.folder)
                        Text(names(f.pids) + (f.events > 0 ? " · \(f.events) events" : "")).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer()
                    Text("+" + Fmt.bytes(f.bytes)).monospacedDigit()
                    Button { reveal(f.folder) } label: { Image(systemName: "magnifyingglass") }
                        .buttonStyle(.borderless).help("Reveal in Finder")
                }
                .font(.callout)
            }
            Text("Growth per folder, from macOS file events plus the files your processes hold open. Writes by root processes show where they land, but not who wrote them.")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }
}

// MARK: Network tab

enum NetSort: String, CaseIterable { case now = "Now", total = "Since reset" }

struct NetView: View {
    @EnvironmentObject var mon: Monitor
    @AppStorage("netSort") private var sort: NetSort = .now

    func proc(_ pid: Int32) -> Proc? { mon.procs.first { $0.pid == pid } }

    var body: some View {
        VStack(spacing: 6) {
            HStack {
                Label(Fmt.rate(mon.netRateIn), systemImage: "arrow.down").foregroundStyle(.blue)
                Label(Fmt.rate(mon.netRateOut), systemImage: "arrow.up").foregroundStyle(.orange)
                Spacer()
                Picker("", selection: $sort) { ForEach(NetSort.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
                    .pickerStyle(.segmented).labelsHidden().frame(width: 170)
            }
            .font(.callout.monospacedDigit())
            List {
                Section(sort == .now ? "Apps with open connections" : "Traffic since \(mon.totalsSince.formatted(date: .abbreviated, time: .shortened))") {
                    if sort == .now {
                        let rows = mon.net.values.filter { !$0.conns.isEmpty || $0.rateIn + $0.rateOut >= 1024 }
                            .sorted { ($0.rateIn + $0.rateOut, $0.conns.count) > ($1.rateIn + $1.rateOut, $1.conns.count) }
                        ForEach(rows.prefix(60), id: \.pid) { n in
                            let p = proc(n.pid)
                            HStack(spacing: 6) {
                                AppIcon(path: p?.bundlePath ?? p?.path ?? "")
                                VStack(alignment: .leading, spacing: 0) {
                                    Text(p?.displayName ?? n.name).lineLimit(1)
                                    Text("\(n.conns.count) connection\(n.conns.count == 1 ? "" : "s")"
                                         + (n.conns.first.map { " · " + host($0.remoteIP) } ?? ""))
                                        .font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                                }
                                Spacer()
                                Text("↓ " + Fmt.rate(n.rateIn)).frame(width: 85, alignment: .trailing)
                                Text("↑ " + Fmt.rate(n.rateOut)).frame(width: 85, alignment: .trailing)
                            }
                            .font(.callout.monospacedDigit())
                            .contentShape(Rectangle())
                            .onTapGesture { mon.selectedPid = n.pid }
                        }
                    } else {
                        let rows = mon.netTotals.sorted { $0.value.bytesIn + $0.value.bytesOut > $1.value.bytesIn + $1.value.bytesOut }
                        ForEach(rows.prefix(60), id: \.key) { path, t in
                            HStack(spacing: 6) {
                                AppIcon(path: path)
                                Text((path as NSString).lastPathComponent).lineLimit(1).help(path)
                                Spacer()
                                Text("↓ " + Fmt.bytes(t.bytesIn)).frame(width: 85, alignment: .trailing)
                                Text("↑ " + Fmt.bytes(t.bytesOut)).frame(width: 85, alignment: .trailing)
                            }
                            .font(.callout.monospacedDigit())
                        }
                    }
                }
                Section("New destinations") {
                    if mon.newDests.isEmpty {
                        Text("Nothing new since Warden started learning.").font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(mon.newDests.prefix(40)) { e in
                        HStack {
                            Text(e.date.formatted(date: .omitted, time: .shortened)).foregroundStyle(.secondary)
                                .frame(width: 55, alignment: .leading)
                            Text((e.path as NSString).lastPathComponent).lineLimit(1).help(e.path)
                            Image(systemName: "arrow.right").foregroundStyle(.secondary)
                            Text("\(host(e.ip)):\(e.port)").lineLimit(1).truncationMode(.middle).help("\(e.ip) · \(e.proto)")
                            Spacer()
                        }
                        .font(.caption)
                    }
                }
            }
            .listStyle(.inset)
            Text("Monitoring only. Blocking connections needs Apple's Network Extension entitlement (planned).")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }
}

// MARK: Process detail

struct ProcessDetailView: View {
    @EnvironmentObject var mon: Monitor
    let pid: Int32

    var body: some View {
        let p = mon.procs.first { $0.pid == pid }
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button { mon.selectedPid = nil } label: { Label("Back", systemImage: "chevron.left") }
                    .buttonStyle(.borderless)
                Spacer()
                if let p, !Killer.isSystem(p) {
                    if !Killer.matches(p, mon.whitelist) {
                        Button("Whitelist") { mon.whitelist.append(WLEntry.from(p)) }
                        Button("Stop autostart") { mon.askStop(p, killOnSight: false) }
                        Button("Block") { mon.askStop(p, killOnSight: true) }
                    }
                    Button("Quit") { Killer.kill([p], force: false) }
                    Button("Force Kill", role: .destructive) { Killer.kill([p], force: true) }
                }
            }
            .controlSize(.small)

            if let p {
                HStack(spacing: 8) {
                    Image(nsImage: AppIcon.icon(p.bundlePath ?? p.path)).resizable().frame(width: 32, height: 32)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(p.displayName).font(.headline)
                        Text(p.path).font(.caption2).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
                    }
                }
                HStack(spacing: 14) {
                    Stat(label: "CPU", value: String(format: "%.1f%%", p.cpu), hot: p.cpu > 50)
                    Stat(label: "Memory", value: Fmt.bytes(p.rss), hot: false)
                    Stat(label: "Writing", value: Fmt.rate(p.writeRate), hot: p.writeRate > 20 * 1_048_576)
                    Stat(label: "Written", value: p.written.map { Fmt.bytes($0) } ?? "–", hot: false)
                    let n = mon.net[pid]
                    Stat(label: "Net ↓/↑", value: "\(Fmt.rate(n?.rateIn ?? 0)) / \(Fmt.rate(n?.rateOut ?? 0))", hot: false)
                }
            } else {
                Text("Process \(pid) has exited.").foregroundStyle(.secondary)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    if let p {
                        let fl = Flags.of(p, Flags.Context(procs: mon.procs, net: mon.net, grants: mon.tccGrants))
                        if !fl.isEmpty {
                            SectionTitle(text: "Flags")
                            ForEach(fl) { f in
                                HStack(alignment: .firstTextBaseline) {
                                    Text(f.label).bold().foregroundStyle(FlagChips.color(f.kind))
                                    Text(f.why).foregroundStyle(.secondary)
                                }
                                .font(.caption)
                            }
                        }
                    }
                    SectionTitle(text: "Open for writing now")
                    let open = mon.openWrites[pid] ?? []
                    if p.map({ $0.uid != getuid() }) ?? false {
                        Text("Not visible for root processes.").font(.caption).foregroundStyle(.secondary)
                    } else if open.isEmpty {
                        Text("Nothing open for writing right now.").font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(open.prefix(30)) { f in
                        FileRow(path: f.path, right: Fmt.bytes(f.size) + (f.growth > 1024 ? "  +" + Fmt.rate(f.growth) : ""))
                    }

                    SectionTitle(text: "Written in the last 10 min")
                    let touched = mon.files.byPid[pid] ?? []
                    if touched.isEmpty {
                        Text("No attributed writes. Short writes by root processes can't be attributed; check Disk › Where writes are landing.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(touched.prefix(30)) { t in
                        FileRow(path: t.path, right: (t.bytes >= 0 ? "+" : "−") + Fmt.bytes(abs(t.bytes)) + " · \(t.events)×")
                    }

                    SectionTitle(text: "Network connections")
                    let conns = mon.net[pid]?.conns ?? []
                    if conns.isEmpty { Text("None right now.").font(.caption).foregroundStyle(.secondary) }
                    ForEach(conns.prefix(40)) { c in
                        HStack {
                            Text("\(host(c.remoteIP)):\(c.remotePort)").lineLimit(1).truncationMode(.middle)
                                .help("\(c.remoteIP) · \(c.proto) · local \(c.local)")
                            Spacer()
                            Text("↓ \(Fmt.bytes(c.bytesIn))  ↑ \(Fmt.bytes(c.bytesOut))").monospacedDigit().foregroundStyle(.secondary)
                        }
                        .font(.caption)
                    }
                }
                .padding(.trailing, 8)
            }
        }
    }
}

struct FileRow: View {
    let path: String
    let right: String
    var body: some View {
        HStack {
            Text(Fmt.path(path)).lineLimit(1).truncationMode(.head).help(path)
            Spacer()
            Text(right).monospacedDigit().foregroundStyle(.secondary)
            Button { reveal(path) } label: { Image(systemName: "magnifyingglass") }
                .buttonStyle(.borderless).help("Reveal in Finder")
        }
        .font(.caption)
    }
}
