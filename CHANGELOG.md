# Changelog

All notable changes to Warden are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-09-30

### Added
- **Network tab**: every app with open connections, with live download/upload rates or totals since the last reset. Data comes from `nettop`, which needs no root and sees every process.
- **New destinations log**: records the first time each app talks to a new remote address. On first launch Warden learns existing connections silently instead of flooding the log.
- **Host names** for remote addresses via reverse DNS, with a Settings toggle to show raw IPs only.
- **Upload alert**: when a single app uploads ≥ 1 GB within the alert window (adjustable).
- **Optional notification** when an app connects somewhere new (off by default).
- **Process detail view**: click a process in Live or Network to see the files it has open for writing (size and growth rate), the files it wrote in the last 10 minutes, and its live connections.
- **Where writes are landing** (Disk tab): the folders that grew most in the last 10 minutes and the processes writing there. Built from whole-disk file events plus open-file scans that share one size baseline, so bytes aren't counted twice.
- Big-write alerts now name the file or folder being written.
- Tests for `nettop` parsing (IPv6, commas in process names), open-file detection, write attribution, signature-cache invalidation and the "still verifying" safeguard (37 checks in total).

### Changed
- App signature checks now run in the background instead of blocking the first sample. On a busy disk the first sample used to take up to a minute; it's now immediate.
- Signature results are cached until the app's executable or `Info.plist` changes. The cache is keyed on inode, size and ctime, which a normal user can't forge. It used to re-check every 10 minutes, re-hashing multi-GB game binaries each time.
- CPU use under heavy disk load dropped from about 9% to about 2% of one core.
- Test and preview builds keep their own state and log files instead of sharing the real app's.

### Security
- A process whose signature hasn't been verified yet is treated as protected, together with everything it started. A purge right after login therefore can't kill a whitelisted app. Enforce mode verifies a newly launched app immediately, so apps can't slip past it while verification is pending.

### Privacy
- Reverse-DNS lookups are Warden's only network traffic. They go to the DNS server the Mac already uses and can be switched off in Settings.

## [1.0.0] - 2026-09-30

### Added
- Menu bar app with Live, Disk, Purge, Alerts and Settings tabs.
- Live process list with CPU, memory and disk-write rate; kill, whitelist and reveal actions.
- Disk tab: free space with a 24-hour graph, top writers since reset, a folder-size browser, a "Usual suspects" scan and Time Machine snapshot info.
- Purge: kills everything except Apple system binaries, system extensions, whitelisted apps and their children. Root processes are opt-in and ask for the admin password.
- Whitelist that matches apps by bundle ID plus Apple-verified signing team, with exact-path, folder-prefix and loose `*substring` rules.
- Alerts for big writes by one process, fast free-space drops and a nearly full disk, sent as notifications and written to a rotating log.
- Enforce mode, which quits non-whitelisted apps as soon as they launch.
- Start at login (asked on first run), single-instance guard, hardened runtime.
- Universal (Apple Silicon + Intel) builds and a test suite.

[1.1.0]: https://github.com/hcohm/Warden/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/hcohm/Warden/releases/tag/v1.0.0
