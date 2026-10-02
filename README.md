# Warden 👁

> **Alpha software.** Warden is pre-release: expect rough edges, and features may change between versions. See [CHANGELOG.md](CHANGELOG.md).

**A menu bar process monitor and killer for macOS that shows which processes are filling your disk, which files they write, and who they talk to on the network.**

Warden sits in your menu bar as a small eye. Click it to see what's running, what's using CPU and memory, which processes are writing to disk and which files they're writing, which apps are connecting where, and how much space you have left. One button kills everything that isn't Apple's or on your whitelist. It warns you when something writes several gigabytes, uploads a lot, or when free space starts disappearing.

Think *Activity Monitor, simplified*, plus a monitor-only *Little Snitch* for disk and network activity. Everything happens on your Mac: no telemetry, no accounts. The only network traffic Warden causes is optional reverse-DNS lookups to show host names.

- Native Swift/SwiftUI, a single ~1 MB app with no dependencies
- Apple Silicon and Intel, macOS 14 Sonoma or later
- Samples every 2 seconds and uses about 2% of one CPU core (measured while a game was hammering the disk)

---

## What it does

### Live
Every process on the system with CPU, memory and **current disk-write rate**. You can sort by any of them, filter by name, path or pid, or show only your own processes. Right-click a row to quit it, force-kill it, whitelist it, reveal it in Finder or copy its path. Killing a macOS system process asks for confirmation first.

### Process details
Click any process in Live or Network to see:
- **Files open for writing right now**, with their sizes and how fast they're growing.
- **Files written in the last 10 minutes**, with how much each grew.
- **Network connections**, with remote host, port and bytes in and out.

### Disk
- **Where writes are landing**: the folders that grew most in the last 10 minutes, with the processes writing there.
- Free space, including purgeable space, with a 24-hour graph and 1h/24h change.
- **Top writers**: the processes that wrote the most bytes since you last reset the list. It survives restarts. This is the answer to *"what the hell keeps eating my disk"*.
- **Folder browser**: click through Home, `~/Library`, `/Applications`, `/Library`, `/private/var` or the whole disk to see what's big.
- **Usual suspects**: one click sizes the usual culprits, such as Xcode DerivedData, simulators, Docker, OrbStack, Ollama, LM Studio, npm, cargo, Homebrew, iOS backups, caches, Downloads and Trash.
- Shows local Time Machine snapshots that are holding space.

### Network
- Every app with open connections, with live download and upload rates, or total traffic since the last reset.
- **New destinations**: a log of the first time each app talks to a new address, Little Snitch style. On first launch Warden learns what's already connected instead of flooding the log.
- Host names via reverse DNS, which you can switch off in Settings to see raw IPs only.
- **Monitoring only.** Warden can't block connections; see Roadmap.

### Purge
Kills everything except:
- Apple system binaries (`/System`, `/usr` except `/usr/local`, `/bin`, `/sbin`, …) and system extensions. launchd restarts these immediately, and killing some of them ends your session.
- Anything on your whitelist, **and anything started by something on your whitelist**. Whitelisting your terminal also keeps the shells and tools running inside it alive.

Candidates are grouped into **Apps**, **Background** processes and **Root / other users**. **Nothing is ticked until you tick it.** To pick quickly:
- **All / None / Flagged** buttons, plus **select by regex** against the name and path (case-insensitive; `^/Applications/` anchors to the path).
- **Sort** by flags, name, memory, CPU or age, and show **Flagged only**.
- Double-click a row for its details.

Killing root processes asks for your password through the standard macOS prompt.

### Stop autostart and Block
Killing isn't enough for apps that come straight back. Many register a launchd agent, the way Perplexity's `perplexityd` does, so macOS restarts them, and helpers and apps often relaunch each other. Use the **⋯** menu on a Purge row, the right-click menu in Live, or the buttons in a process's details:

- **Stop autostart:** switches off the app's launchd jobs and its login item (`launchctl disable` + `bootout`, which persists across reboots) and quits it now. You can still open it yourself.
- **Block:** the same, and Warden also kills it **whenever it shows up**, however it was started. It also switches off any new launchd job it finds behind it.

A block covers the whole app, helpers included. Whitelisted and macOS system processes can never be blocked. Root daemons are switched off through the admin password prompt; Warden never asks for your password in the background. Everything is listed under **Stopped & blocked** in Purge, and × undoes it by re-enabling the jobs (they start again at next login or when you open the app).

### Flags
Warden marks processes worth a second look. Hover a flag for the reason, or open the process for the full explanation. They're heuristics, not verdicts.

| Kind | Flag | Meaning |
|---|---|---|
| Suspicious (red) | Unsigned | No valid signature from an Apple-issued certificate. Normal for your own builds and Homebrew/pip tools. |
| | Binary deleted | Still running, but its executable is gone from disk. |
| | Runs from temp / Downloads / cache / hidden folder | Installed apps rarely run from there; malware and leftover installers often do. |
| Bloat (orange) | *App* isn't open | A helper that keeps running after its app was closed. |
| | Updater | A background updater. |
| | Idle since *date* | Running for 3+ days without using CPU, disk or network. |
| Permissions (purple) | Root | Full administrator rights. |
| | Listens on :*port* | Accepts connections from other machines. Loopback-only ports aren't flagged. |
| | Full Disk Access, Accessibility, Screen Recording, Input Monitoring, Camera, Microphone, … | Granted in Privacy & Security. Reading these needs Warden to have **Full Disk Access**. |

### Alerts
You get a macOS notification, plus an entry in the Alerts tab and in `~/Library/Logs/Warden.log`, when:

| Trigger | Default |
|---|---|
| A single process writes a lot | ≥ 3 GB within 10 min |
| Free space drops fast | ≥ 5 GB within 10 min (names the top recent writers) |
| Disk is nearly full | < 15 GB free |
| An app uploads a lot | ≥ 1 GB within 10 min |
| An app connects somewhere new | off by default; the Network tab always lists it |

All thresholds can be changed in Settings. The menu bar icon turns into a warning triangle while you have unseen alerts, and into a drive icon while the system is writing more than 100 MB/s.

### Enforce mode (off by default)
Quits any app that isn't on your whitelist as soon as it launches. It covers apps only, not background processes, and uses the same rules as Purge.

---

## Install

1. Download a zip from the newest release on the [**Releases**](../../releases) page:
   - `Warden-universal.zip`: runs on any Mac (recommended)
   - `Warden-arm64.zip`: Apple Silicon (M1 and later) only
   - `Warden-x86_64.zip`: Intel only
2. Unzip it and move `Warden.app` to `/Applications` or `~/Applications`.
3. **First launch:** Warden is ad-hoc signed, not notarized, so macOS blocks it the first time. Either:
   - open it, then go to **System Settings › Privacy & Security** and click **Open Anyway**, or
   - run `xattr -dr com.apple.quarantine /Applications/Warden.app` in Terminal.
4. Warden asks whether it should start at login. Look for the 👁 in the menu bar.

> **Can't see the icon?** On notched MacBooks with a crowded menu bar, macOS hides extra icons behind the notch. Quit a few menu bar apps, or hold ⌘ and drag icons to make room.

### Recommended: Full Disk Access
Without it, the Disk tab can't size some protected folders (Mail, Messages, other apps' containers). Go to **Settings › Open Full Disk Access settings**, then add Warden.

## Build from source

Requires Xcode or the Command Line Tools (Swift 5.9+).

```sh
git clone https://github.com/hcohm/Warden.git
cd Warden
./build.sh               # build universal app, install to ~/Applications, launch
./build.sh --no-install  # build into build/ only
./build.sh --release     # also produce dist/*.zip + SHA256SUMS.txt
```

### Dry run
See what a purge would kill without killing anything:

```sh
~/Applications/Warden.app/Contents/MacOS/Warden --dump
```

Each line shows the group, pid, path and any flags.

---

## Whitelist rules

Add entries in the Purge tab, with **Choose App…**, or with the Whitelist button on any row.

| You enter | What it matches |
|---|---|
| `Spotify`, `com.spotify.client`, or **Choose App…** | That app and its helpers, by **bundle ID + Apple-verified signing team**. An app that copies the name or bundle ID doesn't match. |
| `/opt/homebrew/bin/node` | Exactly that executable |
| `/opt/homebrew/` | Anything under that folder (trailing `/`) |
| `*node` | Any path containing `node`. **Loose**, shown in orange. |

Unsigned apps are matched by bundle ID plus their exact location, and are shown as loose too.

**Default whitelist** (only apps that are actually installed): Claude, iTerm, Ghostty, 1Password, Karabiner-Elements and its services. Apple apps such as Terminal and Finder are always protected anyway.

---

## Safety model

Warden kills things, so it's built to be hard to misuse or trick:

- **No stale or recycled PIDs.** A process is identified by its pid, start time and executable path. All three are checked again right before any signal. For root kills the check runs inside the admin shell, and only digits and a validated timestamp ever reach that shell.
- **Purge kills what you confirmed.** The confirmation dialog freezes the list, and exactly that list is killed.
- **No surprise SIGKILL.** Without **Force**, apps get a normal quit (so they can prompt to save) and other processes get `SIGTERM`. Anything still alive afterwards is reported, not force-killed.
- **The whitelist can't be spoofed.** Signing teams are read only from intact signatures that chain to Apple, so a self-signed look-alike doesn't match.
- **Hardened runtime.** Other processes can't inject code into Warden to borrow its Full Disk Access.
- **No root component.** Warden runs as you. The only privileged action is a root kill that you confirmed, through the macOS password prompt.
- **Clean logs.** Control characters in process names are stripped before they reach alerts or the log.
- **Minimal network use.** Warden's only network traffic is reverse-DNS lookups for host names. They go to the DNS server your Mac already uses, and Settings can turn them off.

### Tests

```sh
./tests/run.sh
```

This builds the real sources into a throwaway bundle and runs the full suite. It covers identity and pid-reuse handling, rejection of look-alike apps, signature-cache invalidation, injection attempts against the root-kill script, whitelist parsing, system-path rules, log cleaning, hung-tool timeouts, `nettop` parsing (IPv6, odd process names) and attribution of file writes to the process that made them. The tests only spawn and kill their own dummy processes.

---

## Limitations

- **File attribution is best-effort.** Writes are credited to a process when it has the file open for writing while Warden looks, which reliably catches long-running writers. Brief open-write-close writes, and anything by root processes, show up in *Where writes are landing* by folder, but without a process name.
- **No write stats for root processes.** macOS only reports per-process disk I/O for your own processes unless you're root. Warden still shows CPU and memory for root processes, and the free-space-drop alert catches what they write. A signed root helper is planned (see Roadmap).
- **Very short-lived processes are missed.** A process that starts and exits between two 2-second samples doesn't appear in the per-process stats. The free-space-drop alert still catches its writes.
- **Top writers counts bytes written, not space kept.** A process that writes and deletes temp files still ranks high. It shows who is wearing out your SSD, not only who is filling it.
- **CPU % comes from `ps`,** which reports a smoothed average rather than an instant value.
- **Not notarized yet,** hence the Gatekeeper step above.

## Roadmap

- [ ] Developer ID signing and notarization
- [ ] Optional root helper, registered with `SMAppService` and signed, for per-process write stats of system daemons
- [ ] Connection blocking and allow/deny rules via a Network Extension content filter (needs Apple's entitlement)
- [ ] Exact per-file write attribution for every process via Endpoint Security (needs Apple's entitlement)
- [ ] Per-process write history graphs

## Uninstall

1. If start at login is on, turn it off in **Settings**. Then quit Warden with the ⏻ button.
2. Delete `Warden.app`.
3. Optionally remove its data:
   ```sh
   rm -rf ~/Library/Application\ Support/Warden ~/Library/Logs/Warden.log*
   defaults delete local.warden.app
   ```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
