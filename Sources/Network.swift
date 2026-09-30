import Foundation
import Darwin

struct NetConn: Identifiable, Hashable {
    let proto: String        // tcp4 / tcp6 / udp4 / udp6
    let local: String
    let remoteIP: String
    let remotePort: String
    let bytesIn: UInt64
    let bytesOut: UInt64
    var id: String { "\(proto) \(local)>\(remoteIP):\(remotePort)" }
}

struct NetProc {
    let pid: Int32
    let name: String
    let bytesIn: UInt64      // cumulative, as reported by nettop
    let bytesOut: UInt64
    var conns: [NetConn] = []
    var rateIn: Double = 0
    var rateOut: Double = 0
}

struct NetTotal: Codable { var bytesIn: UInt64 = 0; var bytesOut: UInt64 = 0 }

struct NetEvent: Identifiable, Codable {
    var id = UUID()
    let date: Date
    let path: String
    let ip: String
    let port: String
    let proto: String
}

/// Per-process and per-connection traffic from /usr/bin/nettop, which works unprivileged
/// and sees every process. Monitoring only: blocking needs a Network Extension entitlement.
enum NetSampler {
    static func sample() -> [Int32: NetProc] {
        parse(Sampler.run("/usr/bin/nettop", ["-L", "1", "-x", "-n", "-J", "bytes_in,bytes_out"]))
    }

    /// Lines are "name.pid,in,out," for a process, followed by "tcp4 local<->remote,in,out,"
    /// for each of its sockets. Columns are taken from the right so commas in names are harmless.
    static func parse(_ out: String) -> [Int32: NetProc] {
        var res: [Int32: NetProc] = [:]
        var current: Int32?
        for line in out.split(separator: "\n") {
            var cols = line.split(separator: ",", omittingEmptySubsequences: false)
            if cols.last == "" { cols.removeLast() }
            guard cols.count >= 3 else { continue }
            let bout = UInt64(cols.removeLast()) ?? 0
            let bin = UInt64(cols.removeLast()) ?? 0
            let head = cols.joined(separator: ",")
            guard !head.isEmpty else { continue }
            if let sp = head.firstIndex(of: " "), ["tcp4", "tcp6", "udp4", "udp6"].contains(head[..<sp]) {
                guard let pid = current, let arrow = head.range(of: "<->") else { continue }
                let proto = String(head[..<sp])
                let local = String(head[head.index(after: sp)..<arrow.lowerBound])
                guard let (ip, port) = hostPort(head[arrow.upperBound...], v6: proto.hasSuffix("6")), ip != "*" else { continue }
                res[pid]?.conns.append(NetConn(proto: proto, local: local, remoteIP: ip, remotePort: port, bytesIn: bin, bytesOut: bout))
            } else {
                guard let dot = head.lastIndex(of: "."), let pid = Int32(head[head.index(after: dot)...]) else { current = nil; continue }
                current = pid
                res[pid] = NetProc(pid: pid, name: String(head[..<dot]), bytesIn: bin, bytesOut: bout)
            }
        }
        return res
    }

    /// "1.2.3.4:443" (v4) or "2606:4700::1.443" / "fe80::1%en0.5353" (v6).
    static func hostPort(_ s: Substring, v6: Bool) -> (String, String)? {
        guard let i = s.lastIndex(of: v6 ? "." : ":") else { return nil }
        return (String(s[..<i]), String(s[s.index(after: i)...]))
    }

    static func isLocal(_ ip: String) -> Bool {
        if ip.contains(":") {
            let l = ip.lowercased()
            return l == "::1" || l.hasPrefix("fe80") || l.hasPrefix("fc") || l.hasPrefix("fd") || l.hasPrefix("ff")
        }
        let p = ip.split(separator: ".").compactMap { Int($0) }
        guard p.count == 4 else { return false }
        return p[0] == 10 || p[0] == 127 || (p[0] == 172 && (16...31).contains(p[1]))
            || (p[0] == 192 && p[1] == 168) || (p[0] == 169 && p[1] == 254) || p[0] >= 224
    }
}

/// Reverse DNS with a cache. Lookups go to the system resolver, i.e. whatever DNS server
/// the Mac already uses; they can be switched off in Settings.
final class HostResolver {
    static let shared = HostResolver()
    private let lock = NSLock()
    private var cache: [String: String] = [:]
    private var pending: Set<String> = []
    private let sem = DispatchSemaphore(value: 4)
    var onResolve: (() -> Void)?

    func name(_ ip: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        return cache[ip]
    }

    func request(_ ip: String) {
        guard !NetSampler.isLocal(ip) else { return }
        lock.lock()
        if cache[ip] != nil || pending.contains(ip) || pending.count > 256 { lock.unlock(); return }
        pending.insert(ip)
        lock.unlock()
        DispatchQueue.global(qos: .utility).async {
            self.sem.wait()
            let name = Self.reverse(ip) ?? ip
            self.sem.signal()
            self.lock.lock()
            self.pending.remove(ip)
            if self.cache.count > 5000 { self.cache.removeAll() }
            self.cache[ip] = name
            self.lock.unlock()
            DispatchQueue.main.async { self.onResolve?() }
        }
    }

    private static func reverse(_ ip: String) -> String? {
        var hints = addrinfo()
        hints.ai_flags = AI_NUMERICHOST
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(ip, nil, &hints, &res) == 0, let ai = res else { return nil }
        defer { freeaddrinfo(res) }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) == 0 else { return nil }
        return String(cString: host)
    }
}
