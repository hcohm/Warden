# Warden 👁

**A menu bar process monitor and killer for macOS that also tells you which processes are filling your disk.**

Warden sits in your menu bar as a small eye. Click it to see what's running, what's using CPU and memory, which processes are writing to disk and how much space you have left. One button kills everything that isn't Apple's or on your whitelist. It warns you when something writes several gigabytes, or when free space starts disappearing.

Think *Activity Monitor, simplified*, plus a bit of *Little Snitch* for local disk activity instead of network traffic. Everything happens on your Mac: no network access, no telemetry, no accounts.

- Native Swift/SwiftUI, a single ~1 MB app with no dependencies
- Apple Silicon and Intel, macOS 14 Sonoma or later
- Uses about 0.1% CPU while idle and samples every 2 seconds

---

## What it does

### Live
Every process on the system with CPU, memory and **current disk-write rate**. You can sort by any of them, filter by name, path or pid, or show only your own processes. Right-click a row to quit it, force-kill it, whitelist it, reveal it in Finder or copy its path. Killing a macOS system process asks for confirmation first.

### Disk
- Free space, including purgeable space, with a 24-hour graph and 1h/24h change.
- **Top writers**: the processes that wrote the most bytes since you last reset the list. It survives restarts. This is the answer to *"what the hell keeps eating my disk"*.
- **Folder browser**: click through Home, `~/Library`, `/Applications`, `/Library`, `/private/var` or the whole disk to see what's big.
- **Usual suspects**: one click sizes the usual culprits, such as Xcode DerivedData, simulators, Docker, OrbStack, Ollama, LM Studio, npm, cargo, Homebrew, iOS backups, caches, Downloads and Trash.
- Shows local Time Machine snapshots that are holding space.

### Purge
Kills everything except:
- Apple system binaries (`/System`, `/usr` except `/usr/local`, `/bin`, `/sbin`, …) and system extensions. launchd restarts these immediately, and killing some of them ends your session.
- Anything on your whitelist, **and anything started by something on your whitelist**. Whitelisting your terminal also keeps the shells and tools running inside it alive.

Candidates are grouped into **Apps**, **Background** processes and **Root / other users**. Root processes, and processes whose path can't be read, start unticked. Killing root processes asks for your password through the standard macOS prompt.

### Alerts
You get a macOS notification, plus an entry in the Alerts tab and in `~/Library/Logs/Warden.log`, when:

| Trigger | Default |
|---|---|
| A single process writes a lot | ≥ 3 GB within 10 min |
| Free space drops fast | ≥ 5 GB within 10 min (names the top recent writers) |
| Disk is nearly full | < 15 GB free |

All thresholds can be changed in Settings. The menu bar icon turns into a warning triangle while you have unseen alerts, and into a drive icon while the system is writing more than 100 MB/s.

### Enforce mode (off by default)
Quits any app that isn't on your whitelist as soon as it launches. It covers apps only, not background processes, and uses the same rules as Purge.

---

## Install

1. Download a zip from [**Releases**](../../releases/latest):
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

`KILL` rows are ticked by default in Purge. `opt-in` rows (root or unidentified) are not.

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
- **No network access.** Warden never makes a network connection.

### Tests

```sh
./tests/run.sh
```

This builds the real sources into a throwaway bundle and runs 26 checks. They cover identity and pid-reuse handling, rejection of look-alike apps, injection attempts against the root-kill script, whitelist parsing, system-path rules, log cleaning and hung-tool timeouts. The tests only spawn and kill their own dummy processes.

---

## Limitations

- **No write stats for root processes.** macOS only reports per-process disk I/O for your own processes unless you're root. Warden still shows CPU and memory for root processes, and the free-space-drop alert catches what they write. A signed root helper is planned (see Roadmap).
- **Very short-lived processes are missed.** A process that starts and exits between two 2-second samples doesn't appear in the per-process stats. The free-space-drop alert still catches its writes.
- **Top writers counts bytes written, not space kept.** A process that writes and deletes temp files still ranks high. It shows who is wearing out your SSD, not only who is filling it.
- **CPU % comes from `ps`,** which reports a smoothed average rather than an instant value.
- **Not notarized yet,** hence the Gatekeeper step above.

## Roadmap

- [ ] Developer ID signing and notarization
- [ ] Optional root helper, registered with `SMAppService` and signed, for per-process write stats of system daemons
- [ ] Per-process write history graphs

## Uninstall

1. If start at login is on, turn it off in **Settings**. Then quit Warden with the ⏻ button.
2. Delete `Warden.app`.
3. Optionally remove its data:
   ```sh
   rm -rf ~/Library/Application\ Support/Warden ~/Library/Logs/Warden.log*
   defaults delete local.warden.app
   ```

## License

[MIT](LICENSE)
