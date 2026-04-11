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


## What is a Blocknet core?

A Blocknet core is the daemon that runs the Blocknet network node. It handles the blockchain, peer-to-peer networking, wallet, mining, and exposes an HTTP API. The core runs headless in the background — it has no interactive interface of its own. This program (`blocknet`) manages core instances: installing them, starting and stopping them, upgrading them, and providing the interactive shell that talks to them over their API.

You can run two cores simultaneously — one for mainnet and one for testnet — each fully isolated with its own data directory, wallet, ports, and chain database.

Core binaries are published at [github.com/blocknetprivacy/core](https://github.com/blocknetprivacy/core).

## What is attach?

`blocknet attach` opens an interactive shell session connected to a running core. It gives you a `> ` prompt where you can check your balance, send funds, manage mining, view peers, and more. Most commands are sent to the core over its HTTP API; a few are local shell helpers such as `help`, `about`, `license`, `save`, and `quit`.

Attach does not affect the core's lifecycle — closing the shell (with `quit` or Ctrl-C) leaves the core running. You can attach and detach as many times as you want.

See [reference-core.md](reference-core.md) for the full list of interactive commands available inside attach.

---

## Command Reference

All commands follow the format `blocknet <command> [args]`.

Running `blocknet` with no arguments shows the [status](#blocknet-status) of all configured cores.

---

### Lifecycle

#### `blocknet start [mainnet|testnet]`

Starts one or more core daemons as background processes. If no network is specified, starts all cores marked `enabled` in the [config](reference-config.md).

Before starting, `blocknet` validates the config and prints warnings for issues like port conflicts between mainnet and testnet, missing API addresses, or pinned versions that aren't installed. If [`auto_upgrade`](reference-config.md#top-level-fields) is enabled, it also checks for new releases (respecting `check_interval`) and downloads any available updates.

Each core is spawned as a detached process that survives after `blocknet` exits. The core's PID is written to `~/.config/bnt/core.<network>.pid`. If a core is already running, it is skipped with a message.

After spawning, `blocknet` waits up to 30 seconds for the core's API to become reachable before returning. If start hangs, see the [troubleshooting guide](troubleshooting.md#blocknet-start-hangs).

**Disabled cores:** If you explicitly name a disabled core (`blocknet start mainnet` when mainnet is disabled), `blocknet` will tell you the core is disabled and prompt you to enable it first rather than attempting to start:

```
blocknet start mainnet
  mainnet is disabled — run blocknet enable mainnet first
```

This is intentional — a disabled core won't auto-start, and an explicit start would override that intent silently. Enable the core first, then start it. See [`blocknet enable`](#blocknet-enable-mainnettestnet) and [Starting a disabled core](troubleshooting.md#starting-a-disabled-core).

```
blocknet start                 # start all enabled cores
blocknet start mainnet         # start mainnet only
blocknet start testnet         # start testnet only
```

#### `blocknet stop [mainnet|testnet]`

Stops one or more running cores. On macOS/Linux, the core receives a SIGTERM for graceful shutdown. On Windows, the process is terminated directly. If no network is specified, stops all running cores.

Waits up to 15 seconds for a graceful shutdown. If the process doesn't exit, it is killed.

```
blocknet stop                  # stop all running cores
blocknet stop mainnet          # stop mainnet only
```

#### `blocknet restart [mainnet|testnet]`

Stops then starts the specified core(s). Equivalent to `blocknet stop` followed by `blocknet start`.

```
blocknet restart mainnet
```

#### `blocknet enable <mainnet|testnet>`

Marks a core for auto-start. When `blocknet start` is run without arguments, [enabled cores](reference-config.md#general) are started automatically.

```
blocknet enable testnet
```

#### `blocknet disable <mainnet|testnet>`

Removes a core from auto-start. The core retains its configuration, but `blocknet start` skips disabled cores (even when explicitly named) until you re-enable with `blocknet enable <network>`.

```
blocknet disable testnet
```

#### `blocknet status`

Shows the state of all configured cores: running or stopped, enabled or disabled, and live stats (height, peers, sync state) for running cores.

```
blocknet status

# mainnet [running] [enabled]
  Version: v0.8.0 (latest)
  Height:   14207
  Peers:    8
  Syncing:  false
  API:      127.0.0.1:8332

# testnet [stopped] [disabled]
  Version: latest
```

---

### Interactive

#### `blocknet attach [mainnet|testnet]`

Opens an interactive CLI session against a running core. If only one core is enabled and no network is specified, it attaches to that one. If both are enabled, defaults to mainnet.

All wallet and daemon commands are available inside the session. Type `help` for a list, or `help <command>` for detailed usage. Type `quit` to exit.

The core is not affected when the attach session ends. If attach can't connect, see the [troubleshooting guide](troubleshooting.md#blocknet-attach-says-core-is-not-reachable).

```
blocknet attach                # attach to the only enabled core, or mainnet
blocknet attach testnet        # attach to testnet
```

See [reference-core.md](reference-core.md) for the full list of interactive commands.

#### `blocknet logs [mainnet|testnet]`

Tails the core's log file and follows new output in real time. Shows the last few kilobytes of existing output, then streams new lines as they're written. Press Ctrl-C to stop following.

If no network is specified, defaults to mainnet.

```
blocknet logs                  # follow mainnet log
blocknet logs testnet          # follow testnet log
```

Log files live at `~/.config/bnt/mainnet.log` and `testnet.log` (Windows: `C:\Users\<you>\.config\bnt\`). See [Where are the log files?](troubleshooting.md#where-are-the-log-files) for more.

---

### Version Management

#### `blocknet list`

Fetches all releases from `github.com/blocknetprivacy/core` and shows which versions are installed locally and which are in use.

```
blocknet list

# Versions

  version      date               status
  ──────────────────────────────────────────────────
  nightly      latest             [testnet]
  v0.8.0       Mar 08, 2026       [mainnet]
  v0.7.0       Mar 03, 2026
  v0.6.0       Feb 27, 2026       installed
```

- **[mainnet]** / **[testnet]** — this version is in use by an enabled network. If both mainnet and testnet are enabled on the same version, both tags show (e.g. `[mainnet] [testnet]`). Disabled networks are not shown.
- **installed** — downloaded but not assigned to any enabled network
- Dimmed entries are available but not installed

#### `blocknet install <version>`

Downloads a core binary and stores it in `~/.config/bnt/cores/<version>/`. See the [Version Management & Upgrades](reference-upgrade.md) guide for details on versioning, pinning, and nightly builds.

`latest` resolves to the newest stable release tag. `nightly` always re-downloads since it's a [rolling build](reference-upgrade.md#nightly-builds).

```
blocknet install latest         # resolves to e.g. v0.8.0
blocknet install v0.7.0
blocknet install nightly
```

#### `blocknet uninstall <version>`

Removes a core version from local storage.

```
blocknet uninstall v0.6.0
```

#### `blocknet use <version> [mainnet|testnet]`

Sets which core version to run. Without a network argument, applies to all cores.

A core set to a specific version is [pinned](reference-upgrade.md#pinning) — `blocknet upgrade` will not change it. Use `blocknet use latest` to return to tracking the newest release.

```
blocknet use v0.8.0             # all cores use v0.8.0
blocknet use v0.7.0 testnet     # only testnet uses v0.7.0
blocknet use latest             # track latest for all
blocknet use nightly mainnet    # mainnet runs nightly
```

#### `blocknet upgrade`

Checks for the latest stable release and downloads it if not already installed. If a new version was downloaded, running cores on unpinned versions (`latest` or `nightly`) are restarted onto it.

Pinned cores are left untouched.

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

#### `blocknet cleanup`

Removes all installed core versions that are not currently assigned to any network. Useful for reclaiming disk space after several upgrades.

```
blocknet cleanup

  Removed v0.5.0
  Removed v0.6.0
  Cleaned up 2 version(s)
```

Versions in use by mainnet or testnet (including resolved `latest` and `nightly`) are kept. See [Version Management & Upgrades](reference-upgrade.md) for more on how versions are managed.

---

### Maintenance

#### `blocknet setup`

An interactive first-run wizard that walks you through setting up your node. The wizard is split into a basic flow and an optional advanced section so you can get running quickly without wading through settings you don't need.

```
blocknet setup
```

**Basic flow** — asked every time:

1. **Existing config check** — if a config already exists, setup shows what's in it (mainnet/testnet status, API addresses, auto-upgrade on/off) and asks if you want to start fresh. Default is no.
2. **Auto-updates** — "Keep your node updated automatically?" When enabled, blocknet downloads and applies new core releases for you.
3. **Download** — if no core binary is installed, offers to download the latest one with a live progress bar.
4. **Start** — offers to start your node immediately.
5. **Shell shortcut** — on macOS/Linux, offers to set up the `bnt` shortcut, add blocknet to your PATH, and enable tab completion.

**Advanced flow** — opt-in at the end:

After the basics, setup asks "Want to configure advanced settings?" (default: no). If you say yes, it walks through:

- **Testnet** — enable a separate test network where coins have no value.
- **API addresses** — change the mainnet/testnet API ports (defaults are `127.0.0.1:8332` and `127.0.0.1:18332`). Addresses are validated before saving.

**Input handling** — setup accepts casual responses. `yes`, `yeah`, `sure`, `ok`, `yep` all work for yes. `no`, `nah`, `nope`, `skip` all work for no. Pressing Enter accepts the default. This applies throughout the wizard.

Safe to run at any time, but if you choose the "Start now?" step it may start cores (and auto-upgrade checks may restart unpinned running cores). You can also configure everything manually via [`blocknet config`](#blocknet-config) or by editing `config.json` directly (see [Configuration Reference](reference-config.md)).

#### `blocknet watchdog [mainnet|testnet]`

Monitors running cores by polling the `/api/health` endpoint every 5 seconds. If a core fails 3 consecutive health checks (15 seconds unresponsive), the watchdog automatically runs `blocknet stop` and `blocknet start` to restart it.

If no network is specified, watches all enabled cores. Only one watchdog can run at a time.

The watchdog is stopped automatically when you run `blocknet stop` or `blocknet disable`, so it won't fight with intentional shutdowns.

When the watchdog is active, `blocknet status` shows a `[monitored]` tag on each watched core.

```
blocknet watchdog                 # watch all enabled cores
blocknet watchdog mainnet         # watch mainnet only

# status output with watchdog running:
# mainnet [running] [enabled] [monitored]
```

Run it in the background with `blocknet watchdog &`, in a tmux/screen session, or via your system's service manager.

#### `blocknet doctor`

Runs a series of diagnostic checks and reports issues. Checks include:

- Config directory and file existence and validity
- Config validation (port conflicts, shared directories, missing API addresses, pinned versions not installed)
- Data and wallet directories
- Installed core versions and binaries
- Port availability for stopped cores
- Running process status and stale pidfiles
- Cookie file readability for running cores

```
blocknet doctor

  ✓ Config directory exists (~/.config/bnt)
  ✓ Config file found
  ✓ Config validation passed
  ✓ mainnet core binary exists (v0.8.0)
  ✓ mainnet API port 127.0.0.1:8332 is available
  · testnet core is not running

  All checks passed
```

If something is wrong, `doctor` tells you what to do about it. This is the recommended first step when [troubleshooting](troubleshooting.md).

#### `blocknet completions <bash|zsh|fish>`

Generates shell completion scripts for tab-completing command names and arguments.

```
# bash — add to ~/.bashrc
eval "$(blocknet completions bash)"

# zsh — add to ~/.zshrc
eval "$(blocknet completions zsh)"

# fish — add to ~/.config/fish/config.fish
blocknet completions fish | source
```

---

### Configuration

#### `blocknet config`

Prints the current configuration as JSON. See the [Configuration Reference](reference-config.md) for the full schema, defaults, and examples.

```
blocknet config
```

The config file lives at `~/.config/bnt/config.json`. It supports `//` and `#` [line comments](reference-config.md#comments).

#### `blocknet version`

Prints the version string.

```
blocknet version

# blocknet 
```

#### `blocknet help`

Prints the command summary.

```
blocknet help
```

---

### File Layout

All data lives under the config directory. The path depends on your platform:

| Platform | Default path |
|---|---|
| macOS / Linux | `~/.config/bnt/` |
| Windows | `C:\Users\<you>\.config\bnt\` |

```
<config dir>/
├── config.json              Configuration (see reference-config.md)
├── cores/                   Installed binaries (see reference-upgrade.md)
│   ├── v0.8.0/
│   │   └── blocknet-core-<arch>-<os>
│   ├── nightly/
│   │   └── blocknet-core-<arch>-<os>
│   └── ...
├── data/
│   ├── mainnet/             Chain database, cookie, checkpoints
│   └── testnet/
├── wallets/                 Wallet backups (see reference-wallet.md)
├── core.mainnet.pid         Running core PID (mainnet)
├── core.testnet.pid         Running core PID (testnet)
├── watchdog.pid             Running watchdog PID + monitored networks
├── mainnet.log              Core stdout/stderr (mainnet)
└── testnet.log              Core stdout/stderr (testnet)
```

The base directory can be overridden with the `BNT_CONFIG_DIR` environment variable.

---

### Environment Variables

| Variable | Description |
|---|---|
| `BNT_CONFIG_DIR` | Override the config directory (default: `~/.config/bnt` on macOS/Linux, `C:\Users\<you>\.config\bnt` on Windows) |
| `NO_COLOR` | Disable colored output when set to any value (see [no-color.org](https://no-color.org)). Equivalent to `--nocolor`. |

### Flags

These flags can be placed anywhere on the command line:

| Flag | Description |
|---|---|
| `--nocolor` / `--no-color` | Disable colored output for all commands. Also respected via the `NO_COLOR` environment variable. |
