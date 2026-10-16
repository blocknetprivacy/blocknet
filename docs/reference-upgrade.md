<p align="center">
  <img src="blocknet.png" width="128" height="128" alt="Blocknet">
</p>

<h1 align="center">Blocknet</h1>

<p align="center">
  A client for running Blocknet cores.<br>
  <img src="https://img.shields.io/badge/blocknet-Mainnet-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/blocknet-Testnet-00aaff?style=flat-square&labelColor=000">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version--aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/license-BSD--3--Clause-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-aaff00?style=flat-square&labelColor=000">
</p>

## Version Management & Upgrades

Blocknet manages core versions like a package manager. You can install multiple versions side by side, switch between them, and upgrade running cores without manual file juggling.

Core binaries are stored in `~/.config/bnt/cores/<version>/` (Windows: `C:\Users\<you>\.config\bnt\cores\<version>\`) and downloaded from [github.com/blocknetprivacy/core/releases](https://github.com/blocknetprivacy/core/releases).

---

### Listing available versions

```
blocknet list
```

This fetches all releases from GitHub and shows what's available, what's installed, and what's in use:

```
# Versions

  Version  Date           Status
  ────────────────────────────────────────────
  nightly  Mar 14, 2026   [testnet]
  v0.8.0   Mar 08, 2026   [mainnet]
  v0.7.0   Mar 03, 2026
  v0.6.0   Feb 27, 2026   installed
  v0.5.3   Feb 25, 2026
  v0.5.2   Feb 21, 2026
```

- **[mainnet]** / **[testnet]**: this version is in use by an enabled network. If both mainnet and testnet are enabled on the same version, both tags show (e.g. `[mainnet] [testnet]`). Disabled networks are not shown.
- **installed**: downloaded locally but not assigned to any enabled network.
- Dimmed dates are versions available on GitHub but not installed.
- The nightly row shows the date of the current nightly build.

---

### Installing a version

```
blocknet install <version>
```

Downloads a core binary for your platform and stores it locally.

```
blocknet install latest         # resolves to newest stable tag (e.g. v0.8.0)
blocknet install v0.7.0         # specific version
blocknet install nightly        # install the current nightly build
```

- `latest` is resolved to the actual tag before downloading. If that tag is already installed, it's skipped.
- `nightly` always re-downloads because it's a rolling build.
- A tag that is not a release is refused: `error: version v9.9.9 not found (run blocknet list)`.
- Version names must be plain tags such as `v0.7.0`, `latest` or `nightly`. Names with path separators or `..`, or longer than 64 characters, are refused with `error: invalid version "../x": use a tag like v0.7.0, latest or nightly`.
- The download's SHA-256 checksum is verified, and the binary is extracted from a `.zip` archive (e.g. `blocknet-core-arm64-macos-0.8.0.zip`) automatically. If install fails, see [install fails with "no binary for your platform"](troubleshooting.md#blocknet-install-fails-with-no-binary-for-your-platform).

---

### Uninstalling a version

```
blocknet uninstall <version>
```

Removes the version directory from `~/.config/bnt/cores/<version>/`.

A version that a configured core uses is refused, whether that core is enabled or not and whether it is pinned to the version or tracks it through `latest` or `nightly`:

```
blocknet uninstall v0.8.0
error: v0.8.0 is in use by mainnet. Switch to another version first with blocknet use <version> mainnet
```

Switch the core to another version with [`blocknet use`](#choosing-which-version-to-run) first.

---

### Choosing which version to run

```
blocknet use <version> [mainnet|testnet]
```

Sets which core version a network should run. The version must already be installed (this includes `nightly`); otherwise `use` stops with `error: v0.7.0 is not installed (run blocknet install v0.7.0)`. `latest` is always accepted.

```
blocknet use v0.8.0             # all cores use v0.8.0
blocknet use v0.7.0 testnet     # only testnet uses v0.7.0
blocknet use latest             # all cores track latest
blocknet use nightly mainnet    # mainnet runs nightly builds
```

```
blocknet use v0.7.0 testnet

# Use

  ✓ testnet set to v0.7.0
  Restart running cores to use it
```

The version is saved to [`config.json`](reference-config.md). The change takes effect next time the core [starts](reference-blocknet.md#blocknet-start-mainnettestnet) (or [restarts](reference-blocknet.md#blocknet-restart-mainnettestnet)).

---

### Pinning

When you set a core to a specific version like `v0.7.0`, that core is **pinned**. A pinned core is protected from automatic upgrades: `blocknet upgrade` will skip it.

This is useful when you need stability on a specific version, or you're testing something on an older release.

To unpin a core and return it to tracking the latest release:

```
blocknet use latest
blocknet use latest mainnet
```

The special values `latest` and `nightly` are not considered pinned.

---

### Upgrading

```
blocknet upgrade
```

This is the one-command path for keeping your cores current:

1. Upgrades blocknet itself if a new release is out (see [Automatic upgrades](#automatic-upgrades)).
2. Checks GitHub for the latest stable release.
3. Downloads it if not already installed.
4. Stops and restarts any running cores set to `latest`.
5. If a core uses `nightly`, checks the nightly build and downloads it if it changed. Running nightly cores restart onto the new build.
6. Pinned cores are left untouched.

```
blocknet upgrade

# Upgrade

  Checking for new releases...
  Latest: v0.9.0 (Mar 15, 2026)
  Downloading blocknet-core-arm64-macos-0.9.0.zip
  [██████████████████████████████] 100% 12.4 MB
  ✓ Checksum verified
  ✓ Installed v0.9.0
  Restarting mainnet core with v0.9.0...
  ✓ mainnet core running (pid 54321)
```

If the latest version is already installed, the command reports that (`v0.9.0 is already installed`) and exits. If no cores are running, it installs the binary and tells you to restart when ready.

---

### Cleaning up old versions

```
blocknet cleanup
```

Removes all installed core versions that aren't assigned to any network. After several upgrades, old versions accumulate in `~/.config/bnt/cores/`, and cleanup reclaims that disk space.

Versions currently assigned in config for mainnet or testnet (including resolved `latest` and `nightly`) are always kept.

```
blocknet cleanup

# Cleanup

  ✓ Removed v0.5.0
  ✓ Removed v0.6.0
  Cleaned up 2 versions
```

---

### Automatic upgrades

Automatic upgrades are always on. blocknet checks for new releases every time you run `blocknet start` or `blocknet status`, and from the OS scheduler, subject to `check_interval`:

```json
{
  "check_interval": "24h"
}
```

- `check_interval`: minimum time between checks. Accepts Go duration strings: `"1h"`, `"12h"`, `"24h"`, `"168h"` (1 week).

blocknet upgrades itself first. It downloads the new release from [blocknetprivacy/blocknet](https://github.com/blocknetprivacy/blocknet/releases), checks its SHA-256, and replaces its own binary. The new version runs from the next command. Builds made with plain `go build` have no version and never upgrade themselves.

When a new core release is found, the binary is downloaded and installed. If a managed core set to `latest` is already running, blocknet restarts it to apply the new version. Cores set to `nightly` follow the nightly build instead, and restart only when that build changes. If not running, the new version is used on the next start/restart. Pinned cores are never touched.

The last check time is stored in `~/.config/bnt/.last_upgrade_check`. If less than `check_interval` has passed since the last check, the check is skipped silently.

#### OS scheduler integration

On macOS and Linux, blocknet installs a background scheduler entry (a launchd plist on macOS, a systemd timer on Linux, a crontab line on Android in Termux) to run `blocknet upgrade --nocolor` automatically on a schedule derived from `check_interval` (with platform minimums/rounding). On Windows it uses Task Scheduler. On Android, Termux needs cron first: `pkg install cronie termux-services` and `sv-enable crond`.

The scheduler is managed automatically:

- **When you run `blocknet start`**, blocknet installs or updates the scheduler entry. If the interval has changed since the last run, the scheduler is reinstalled with the new interval.

You can remove the scheduler entry manually:

```
# macOS: remove the launchd plist
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.blocknet.upgrade.plist
rm ~/Library/LaunchAgents/com.blocknet.upgrade.plist

# Linux: remove the systemd timer
systemctl --user disable --now blocknet-upgrade.timer

# Android (Termux): remove the crontab line
crontab -l | grep -v blocknet-upgrade | crontab -
```

The next `blocknet start` puts it back.

---

### Nightly builds

Nightly is a rolling release published under the `nightly` release tag in [blocknetprivacy/core](https://github.com/blocknetprivacy/core). It is intended for testing unreleased changes.

```
blocknet install nightly
blocknet use nightly testnet
```

**Nightly is not a stable release.** It's useful for testing unreleased features, but carries risks:

- Not guaranteed to work or be stable.
- May contain breaking changes, consensus bugs, or incomplete features.
- Has a non-zero risk of fund loss.
- Reinstalling nightly always re-downloads. Automatic upgrades compare the published SHA-256 with the installed build and download only when it changed.

If you're not specifically testing something, use a stable tagged release.

---

### How version resolution works

When a core starts, blocknet resolves its configured version to an actual installed binary:

| Config value | Resolution |
|---|---|
| `"latest"` | Scans `~/.config/bnt/cores/` for the highest semver tag (e.g. `v0.8.0`). Fails if no versions are installed. |
| `"nightly"` | Uses `~/.config/bnt/cores/nightly/`. Fails if nightly is not installed. |
| `"v0.7.0"` | Uses `~/.config/bnt/cores/v0.7.0/`. Fails if that version is not installed. |

If resolution fails, [`blocknet start`](reference-blocknet.md#blocknet-start-mainnettestnet) returns an error. Install the version first with [`blocknet install`](reference-blocknet.md#blocknet-install-version). See [version not installed](troubleshooting.md#blocknet-start-says-version-is-not-installed) for details.

---

### Upgrade flow diagram

```
blocknet upgrade
    │
    ├── fetch latest release from GitHub
    │
    ├── already installed? ──yes──> done
    │         │
    │         no
    │         │
    ├── download + extract binary
    │
    ├── for each running core:
    │       │
    │       ├── pinned? ──yes──> skip
    │       │      │
    │       │      no
    │       │      │
    │       ├── stop core
    │       ├── start core with new binary
    │       └── write new PID
    │
    └── done
```

---

### File layout

```
~/.config/bnt/cores/
├── v0.8.0/
│   └── blocknet-core-arm64-macos      # or amd64-linux, etc.
├── v0.7.0/
│   └── blocknet-core-arm64-macos
├── nightly/
│   └── blocknet-core-arm64-macos
└── ...
```

Binary names follow the pattern `blocknet-core-<arch>-<os>` where:
- `<arch>` is `arm64` or `amd64`
- `<os>` is `macos`, `linux`, or `windows`

On Windows, the binary has an `.exe` extension (e.g. `blocknet-core-amd64-windows.exe`). The correct binary for your platform is selected automatically during download.
