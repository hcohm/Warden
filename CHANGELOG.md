# Changelog

All notable changes to Warden are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

Warden is in **alpha**: anything may still change between releases. The app itself reports the base version (for example `0.1.0`), because macOS version fields can't carry an `-alpha` suffix.

> **Renumbered on 2026-09-30:** the first two releases were originally published as 1.0.0 and 1.1.0. They are now 0.1.0-alpha.1 and 0.1.0-alpha.2 to reflect that Warden is pre-release software. One commit message in the history still says "(1.1)"; it refers to 0.1.0-alpha.2.

## [Unreleased]

### Added
- **Flags** on processes worth a second look, shown as coloured chips in Purge and explained in the process detail view:
  - suspicious: unsigned, executable deleted while running, runs from a temp/Downloads/cache/hidden folder;
  - bloat: a helper still running after its app was closed, updaters, idle for 3+ days;
  - permissions: root, listening on a network-facing port, and macOS privacy grants (Full Disk Access, Accessibility, Screen Recording, Input Monitoring, Camera, Microphone, …) read from the TCC databases.
- Purge selection tools: **All**, **None**, **Flagged**, and **select by regex** against name and path.
- Purge sorting by flags, name, memory, CPU or age, and a **Flagged only** filter.
- `--dump` lists each candidate's flags.
- Tests for selection, every flag rule, listener parsing and the TCC reader (50 checks in total).

### Changed
- **Nothing in Purge is ticked by default.** Previously apps and background processes started ticked.
- Standalone executables (not only app bundles) now get their signature checked, in the background and cached the same way. Like bundles, they're protected from Purge until the check finishes.

### Fixed
- **Kill confirmations didn't work.** The Purge confirmation (and the one for killing a macOS system process from Live) opened as a system dialog that never became active inside the menu bar popup: its button stayed grey and clicking it just hid the popup. Confirmations are now a card inside the popup.
- Regex `^` and `$` match per line, so a pattern can anchor to the path as well as the name.

## [0.1.0-alpha.2] - 2026-09-30

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

## [0.1.0-alpha.1] - 2026-09-30

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

[Unreleased]: https://github.com/hcohm/Warden/compare/v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/hcohm/Warden/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/hcohm/Warden/tree/v0.1.0-alpha.1
