<p align="center">
  <img src="blocknet.png" width="128" height="128" alt="Blocknet">
</p>

<h1 align="center">Blocknet</h1>

<p align="center">
  A client for running Blocknet cores.<br>
  <img src="https://img.shields.io/badge/blocknet-Mainnet-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/blocknet-Testnet-ff00aa?style=flat-square&labelColor=000">
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
  version      date               status
  ──────────────────────────────────────────────────
  nightly      latest             [testnet]
  v0.8.0       Mar 08, 2026       [mainnet]
  v0.7.0       Mar 03, 2026
  v0.6.0       Feb 27, 2026       installed
  v0.5.3       Feb 25, 2026
  v0.5.2       Feb 21, 2026
```

- **[mainnet]** / **[testnet]** — this version is in use by an enabled network. If both mainnet and testnet are enabled on the same version, both tags show (e.g. `[mainnet] [testnet]`). Disabled networks are not shown.
- **installed** — downloaded locally but not assigned to any enabled network.
- Dimmed entries are available on GitHub but not installed.

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
- The binary is extracted from a `.zip` archive (e.g. `blocknet-core-arm64-macos-0.8.0.zip`) automatically. If install fails, see [install fails with "no asset found"](troubleshooting.md#blocknet-install-fails-with-no-asset-found).

---

### Uninstalling a version

```
blocknet uninstall <version>
```

Removes the version directory from `~/.config/bnt/cores/<version>/`. Does not affect running cores — stop them first if they're using this version.

---

### Choosing which version to run

```
blocknet use <version> [mainnet|testnet]
```

Sets which core version a network should run.

```
blocknet use v0.8.0             # all cores use v0.8.0
blocknet use v0.7.0 testnet     # only testnet uses v0.7.0
blocknet use latest             # all cores track latest
blocknet use nightly mainnet    # mainnet runs nightly builds
```

The version is saved to [`config.json`](reference-config.md). The change takes effect next time the core [starts](reference-blocknet.md#blocknet-start-mainnettestnet) (or [restarts](reference-blocknet.md#blocknet-restart-mainnettestnet)).

---

### Pinning

When you set a core to a specific version like `v0.7.0`, that core is **pinned**. A pinned core is protected from automatic upgrades — `blocknet upgrade` will skip it.

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

1. Checks GitHub for the latest stable release.
2. Downloads it if not already installed.
3. Stops and restarts any running cores that are unpinned (`latest` or `nightly`).
4. Pinned cores are left untouched.

```
blocknet upgrade

# Upgrade

  Checking for new releases...
  Latest: v0.9.0 (Mar 15, 2026)
  Downloading...
  ████████████████████████████████ 100% (12.4 MB)
  ✓ Installed v0.9.0
  Restarting mainnet core with v0.9.0...
  ✓ mainnet core running (pid 54321)
```

If the latest version is already installed, the command reports that and exits. If no cores are running, it installs the binary and tells you to restart when ready.

---

### Cleaning up old versions

```
blocknet cleanup
```

Removes all installed core versions that aren't assigned to any network. After several upgrades, old versions accumulate in `~/.config/bnt/cores/` — cleanup reclaims that disk space.

Versions currently assigned in config for mainnet or testnet (including resolved `latest` and `nightly`) are always kept.

```
blocknet cleanup

  Removed v0.5.0
  Removed v0.6.0
  Cleaned up 2 version(s)
```

---

### Automatic upgrades

Set [`auto_upgrade`](reference-config.md#top-level-fields) in your [config](reference-config.md) to have blocknet download new releases automatically:

```json
{
  "auto_upgrade": true,
  "check_interval": "24h"
}
```

- `auto_upgrade` — when `true`, blocknet checks for new releases every time you run `blocknet start` or `blocknet status`, subject to `check_interval`.
- `check_interval` — minimum time between checks. Accepts Go duration strings: `"1h"`, `"12h"`, `"24h"`, `"168h"` (1 week).

When a new release is found, the binary is downloaded and installed. If a managed core is already running on an unpinned version (`latest` or `nightly`), blocknet may restart it immediately to apply the new version. If not running, the new version is used on the next start/restart. Pinned cores are never touched.

The last check time is stored in `~/.config/bnt/.last_upgrade_check`. If less than `check_interval` has passed since the last check, the check is skipped silently.

#### OS scheduler integration

On macOS and Linux, blocknet installs a background scheduler entry (a launchd plist on macOS, a systemd timer on Linux) to run `blocknet upgrade` automatically on a schedule derived from `check_interval` (with platform minimums/rounding). On Windows it uses Task Scheduler.

The scheduler is managed automatically:

- **When you run `blocknet start` with `auto_upgrade: true`** — blocknet installs or updates the scheduler entry. If the interval has changed since the last run, the scheduler is reinstalled with the new interval.
- **When you set `auto_upgrade: false`** — blocknet stops managing auto-upgrade checks. Remove any existing scheduler entry manually (commands below), or toggle `auto_upgrade` back to `true` and run `blocknet start` once so blocknet can reconcile scheduler state.

You can disable the scheduler without changing the config by removing the entry manually:

```
# macOS — remove the launchd plist
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.blocknet.upgrade.plist
rm ~/Library/LaunchAgents/com.blocknet.upgrade.plist

# Linux — remove the systemd timer
systemctl --user disable --now blocknet-upgrade.timer
```

To disable permanently, set `auto_upgrade: false` in your config so `blocknet start` doesn't reinstall it.

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
- Reinstalling nightly always re-downloads — there is no version check since the binary changes constantly.

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
