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


## What is a Blocknet core?

A Blocknet core is the daemon that runs the Blocknet network node. It handles the blockchain, peer-to-peer networking, wallet, mining, and exposes an HTTP API. The core runs headless in the background and has no interactive interface of its own. This program (`blocknet`) manages core instances: installing them, starting and stopping them, upgrading them, and providing the interactive shell that talks to them over their API.

You can run two cores simultaneously (one for mainnet and one for testnet), each fully isolated with its own data directory, wallet, ports, and chain database.

Core binaries are published at [github.com/blocknetprivacy/core](https://github.com/blocknetprivacy/core).

## What is attach?

`blocknet attach` opens an interactive shell session connected to a running core. It gives you a `> ` prompt where you can check your balance, send funds, manage mining, view peers, and more. Most commands are sent to the core over its HTTP API; a few are local shell helpers such as `help`, `about`, `license`, and `quit`.

Attach does not affect the core's lifecycle: closing the shell (with `quit`, Ctrl-D or Ctrl-C) leaves the core running. You can attach and detach as many times as you want.

See [reference-core.md](reference-core.md) for the full list of interactive commands available inside attach.

---

## Command Reference

All commands follow the format `blocknet <command> [args]`. A command given more arguments than it takes is refused with its usage line:

```
blocknet enable mainnet extra
error: too many arguments: extra (usage: blocknet enable <mainnet|testnet>)
```

Running `blocknet` with no arguments shows the [status](#blocknet-status) of all configured cores.

---

### Lifecycle

#### `blocknet start [mainnet|testnet]`

Starts one or more core daemons as background processes. If no network is specified, starts all cores marked `enabled` in the [config](reference-config.md).

Before starting, `blocknet` validates the config and prints warnings for issues like port conflicts between mainnet and testnet, missing API addresses, or pinned versions that aren't installed. It also checks for new releases of blocknet and the core (respecting [`check_interval`](reference-config.md#top-level-fields)) and installs any available updates.

Each core is spawned as a detached process that survives after `blocknet` exits. The core's PID is written to `~/.config/bnt/core.<network>.pid`. If a core is already running, it is skipped with a message.

After spawning, `blocknet` waits for the core's API to become reachable before returning. It waits as long as the core keeps working (a cold start can take a while) and gives up if the core exits or makes no progress for 2 minutes. If start hangs, see the [troubleshooting guide](troubleshooting.md#blocknet-start-hangs).

```
blocknet start mainnet

# Start

  Starting mainnet core (v0.8.0)...
  ✓ mainnet running (pid 54321, api 127.0.0.1:8332)
```

If a running [watchdog](#blocknet-watchdog-mainnettestnet) stopped watching a core because you ran `blocknet stop <network>`, `blocknet start <network>` puts that core back on its watch list.

**Disabled cores:** If you explicitly name a disabled core (`blocknet start testnet` when testnet is disabled), `blocknet` tells you the core is disabled and asks you to enable it first rather than starting it:

```
blocknet start testnet

# Start

  testnet is disabled. Run blocknet enable testnet first.
```

This is intentional: a disabled core won't auto-start, and an explicit start would override that intent silently. Enable the core first, then start it. See [`blocknet enable`](#blocknet-enable-mainnettestnet) and [Starting a disabled core](troubleshooting.md#starting-a-disabled-core).

```
blocknet start                 # start all enabled cores
blocknet start mainnet         # start mainnet only
blocknet start testnet         # start testnet only
```

#### `blocknet stop [mainnet|testnet]`

Stops one or more running cores. On macOS/Linux, the core receives a SIGTERM for graceful shutdown. On Windows, the process is terminated directly. If no network is specified, stops all running cores.

Waits up to 15 seconds for a graceful shutdown. If the process doesn't exit, it is killed.

```
blocknet stop

# Stop

  mainnet core stopped
```

With no cores running, it prints `No cores running`. Naming a core that is not running prints `mainnet core not running`.

`blocknet stop <network>` takes only that network off a running [watchdog](#blocknet-watchdog-mainnettestnet)'s watch list; the watchdog keeps watching the other one. When no network is left to watch (for example after `blocknet stop` with no network), the watchdog stops.

```
blocknet stop                  # stop all running cores
blocknet stop mainnet          # stop mainnet only
```

#### `blocknet restart [mainnet|testnet]`

Stops then starts the specified core(s), under a `# Restart` heading. A running watchdog keeps watching a restarted core.

```
blocknet restart mainnet
```

#### `blocknet enable <mainnet|testnet>`

Marks a core for auto-start. When `blocknet start` is run without arguments, [enabled cores](reference-config.md#general) are started automatically. A network is required.

```
blocknet enable testnet

# Enable

  ✓ testnet enabled
```

#### `blocknet disable <mainnet|testnet>`

Removes a core from auto-start. The core retains its configuration, but `blocknet start` skips disabled cores (even when explicitly named) until you re-enable with `blocknet enable <network>`. A running watchdog stops watching the disabled core. A network is required.

```
blocknet disable testnet

# Disable

  ✓ testnet disabled
```

#### `blocknet status`

Shows the state of all configured cores: running, unresponsive or stopped, enabled or disabled, and live stats (height, peers, sync state) for running cores.

```
blocknet status

# mainnet [running] [enabled]

  Version:  v0.8.0 (latest)
  Height:   14207
  Peers:    8
  Syncing:  no
  API:      127.0.0.1:8332

# testnet [stopped] [disabled]

  Version:  v0.8.0 (latest)
```

A pinned core shows its version as `v0.7.0 (pinned)`.

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

Tails the core's log file and follows new output in real time. Shows the last few kilobytes of existing output, then streams new lines as they're written. If the log file is truncated or replaced, it starts again from the top of the new file. Press Ctrl-C to stop following.

If no network is specified, it follows the only enabled core, or mainnet when both or neither are enabled.

```
blocknet logs                  # follow the only enabled core's log, or mainnet's
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

  Version  Date           Status
  ────────────────────────────────────────────
  nightly  Mar 14, 2026   [testnet]
  v0.8.0   Mar 08, 2026   [mainnet]
  v0.7.0   Mar 03, 2026
  v0.6.0   Feb 27, 2026   installed
```

- **[mainnet]** / **[testnet]**: this version is in use by an enabled network. If both mainnet and testnet are enabled on the same version, both tags show (e.g. `[mainnet] [testnet]`). Disabled networks are not shown.
- **installed**: downloaded but not assigned to any enabled network
- Dimmed dates are versions that are available but not installed
- The nightly row shows the date of the current nightly build

#### `blocknet install <version>`

Downloads a core binary and stores it in `~/.config/bnt/cores/<version>/`. See the [Version Management & Upgrades](reference-upgrade.md) guide for details on versioning, pinning, and nightly builds.

`latest` resolves to the newest stable release tag. `nightly` always re-downloads since it's a [rolling build](reference-upgrade.md#nightly-builds). A tag that is not a release is refused with `error: version v9.9.9 not found (run blocknet list)`. A version name must be a plain tag such as `v0.7.0`; names with path separators or `..` are refused.

```
blocknet install latest         # resolves to e.g. v0.8.0
blocknet install v0.7.0
blocknet install nightly
```

#### `blocknet uninstall <version>`

Removes a core version from local storage.

```
blocknet uninstall v0.6.0

# Uninstall

  ✓ Removed v0.6.0
```

A version that a configured core uses (pinned, or what its `latest` or `nightly` resolves to, enabled or not) is not removed:

```
error: v0.8.0 is in use by mainnet. Switch to another version first with blocknet use <version> mainnet
```

#### `blocknet use <version> [mainnet|testnet]`

Sets which core version to run. Without a network argument, applies to all cores.

The version must be installed, including `nightly`; otherwise it is refused with `error: v0.7.0 is not installed (run blocknet install v0.7.0)`. `latest` is always accepted.

A core set to a specific version is [pinned](reference-upgrade.md#pinning), so `blocknet upgrade` will not change it. Use `blocknet use latest` to return to tracking the newest release.

```
blocknet use v0.8.0             # all cores use v0.8.0
blocknet use v0.7.0 testnet     # only testnet uses v0.7.0
blocknet use latest             # track latest for all
blocknet use nightly mainnet    # mainnet runs nightly
```

```
blocknet use latest testnet

# Use

  ✓ testnet set to latest
  Restart running cores to use it
```

#### `blocknet upgrade`

Upgrades blocknet itself, then checks for the latest stable release and downloads it if not already installed. If a new version was downloaded, running cores set to `latest` are restarted onto it. If a core uses `nightly`, it also checks the nightly build and restarts nightly cores when the build changed.

Pinned cores are left untouched.

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

#### `blocknet cleanup`

Removes all installed core versions that are not currently assigned to any network. Useful for reclaiming disk space after several upgrades.

```
blocknet cleanup

# Cleanup

  ✓ Removed v0.5.0
  ✓ Removed v0.6.0
  Cleaned up 2 versions
```

Versions in use by mainnet or testnet (including resolved `latest` and `nightly`) are kept. See [Version Management & Upgrades](reference-upgrade.md) for more on how versions are managed.

---

### Maintenance

#### `blocknet setup`

An interactive first-run wizard that walks you through setting up your node. It needs an interactive terminal: run from a script or with input piped in, it stops with `error: setup needs an interactive terminal`.

```
blocknet setup
```

The wizard goes through these steps:

1. **Current config**: if a config already exists, setup shows what's in it (mainnet/testnet enabled or disabled, with API addresses) and uses those values as the current answers.
2. **Advanced settings**: "Configure advanced settings?" (default: yes). If you say yes, it walks through:
   - **Testnet**: enable a separate test network where coins have no value, its API address (default `127.0.0.1:18332`) and its block explorer (default `127.0.0.1:18080`).
   - **Mainnet**: the API address (default `127.0.0.1:8332`) and the block explorer (default `127.0.0.1:8080`).
   - **Sync**: whether to save a checkpoint every 100 blocks (default: no).

   Addresses are validated; an invalid one prints a warning and keeps the current value.
3. **Config**: saves `config.json` and schedules automatic upgrades.
4. **Core**: if no core binary is installed, offers to download the latest one with a live progress bar.
5. **Shell**: on macOS/Linux with bash, zsh or fish, offers to set up the `bnt` shortcut, add blocknet to your PATH, and enable tab completion.
6. **Start**: if a core is installed, offers to start your node immediately.

**Input handling**: setup accepts casual responses. `yes`, `yeah`, `sure`, `ok`, `yep` all work for yes. `no`, `nah`, `nope`, `skip` all work for no. Pressing Enter accepts the default. This applies throughout the wizard. Press Ctrl-D at any prompt to cancel; setup prints `Setup cancelled` and lists anything it had already done (such as saving the config).

Safe to run at any time, but if you choose the "Start your node now?" step it may start cores (and auto-upgrade checks may restart unpinned running cores). You can also configure everything manually via [`blocknet config`](#blocknet-config) or by editing `config.json` directly (see [Configuration Reference](reference-config.md)).

#### `blocknet watchdog [mainnet|testnet]`

Monitors cores by polling the `/api/health` endpoint every 5 seconds. If the core process is gone (crashed), the watchdog runs `blocknet start` for it right away. If the process is alive but its API does not answer, the watchdog leaves it alone as long as it is still using CPU or disk (a slow startup); only when it has made no progress for 2 minutes does it run `blocknet stop` and `blocknet start` to restart it.

If no network is specified, watches all enabled cores. Only one watchdog can run at a time.

The watchdog follows your commands, so it won't fight with intentional shutdowns: `blocknet stop <network>` and `blocknet disable <network>` take that network off its watch list, and `blocknet start <network>` puts a stopped one back. When nothing is left to watch (for example after `blocknet stop` with no network), the watchdog stops. It also rereads the config, and stops watching a core that has been disabled.

When the watchdog is active, `blocknet status` shows a `[monitored]` tag on each watched core.

```
blocknet watchdog                 # watch all enabled cores
blocknet watchdog mainnet         # watch mainnet only

  Watchdog monitoring: mainnet testnet (every 5s)

# status output with watchdog running:
# mainnet [running] [enabled] [monitored]
```

Run it in the background with `blocknet watchdog &`, in a tmux/screen session, or via your system's service manager.

#### `blocknet doctor`

Runs a series of diagnostic checks and reports issues. It only reads: it changes nothing on disk. Checks include:

- Config directory and file existence and validity
- Config validation (port conflicts, shared directories, missing API addresses, pinned versions not installed)
- Installed core versions, data and wallet directories, wallet files and their permissions
- Core binaries, API address binding, and port availability for stopped cores
- Running process status and stale pidfiles
- Cookie file and API health for running cores, and the loaded wallet
- Mainnet checkpoints compared with bntpool (it reports missing or out-of-date checkpoints; `blocknet start` downloads them)
- Whether the watchdog is running

```
blocknet doctor

# Config

  ✓ Config directory    /Users/you/.config/bnt
  ✓ Config file         /Users/you/.config/bnt/config.json
  ✓ Config check        no problems found
  ✓ Core versions       1 version installed
  ✓ Wallets directory   /Users/you/.config/bnt/wallets
  · Wallet files        none in the wallets directory

# Mainnet

  · Data directory      will be created on first start (/Users/you/.config/bnt/data/mainnet)
  · Wallet file         none yet (/Users/you/.config/bnt/wallets/blocknet-mainnet.wallet.dat)
  ✓ Core binary         v0.8.0
  ✓ API port            127.0.0.1:8332 is free
  · Core process        not running
  ! Checkpoints         missing
    → Run 'blocknet start mainnet' to download them

# Testnet

  · Data directory      will be created on first start (/Users/you/.config/bnt/data/testnet)
  · Wallet file         none yet (/Users/you/.config/bnt/wallets/blocknet-testnet.wallet.dat)
  · Core process        not running

# System

  ! Watchdog            not running

  ✓ All checks passed (2 warnings)
```

`✓` is a passed check, `·` is information, `!` is a warning worth a look, and `✗` is an issue. Every `✗` counts as an issue; when there are any, the last line reads `✗ 1 issue found` (or `✗ 3 issues found`) instead. If something is wrong, `doctor` tells you what to do about it on the `→` line below. This is the recommended first step when [troubleshooting](troubleshooting.md).

#### `blocknet completions <bash|zsh|fish>`

Generates shell completion scripts for tab-completing command names (including `watchdog` and `completions`), networks, versions and shells. The scripts complete the `bnt` shortcut too. Run without a shell, it prints these instructions.

```
# bash: add to ~/.bashrc
eval "$(blocknet completions bash)"

# zsh: add to ~/.zshrc
eval "$(blocknet completions zsh)"

# fish: add to ~/.config/fish/config.fish
blocknet completions fish | source
```

For zsh you can also save the output as `_blocknet` in a folder on `$fpath`.

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

# blocknet v1.1.0
```

A build made with plain `go build` prints `blocknet dev`.

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
├── wallets/                 Wallet files and backups (see reference-wallet.md)
├── core.mainnet.pid         Running core PID (mainnet)
├── core.testnet.pid         Running core PID (testnet)
├── watchdog.pid             Running watchdog PID + monitored networks
├── peer.txt                 This node's addresses, written by export-peer
├── mainnet.log              Core stdout/stderr (mainnet)
└── testnet.log              Core stdout/stderr (testnet)
```

The base directory can be overridden with the `BNT_CONFIG_DIR` environment variable.

---

### Colors

Output uses one set of colors: green for mainnet and success, cyan for testnet and information, amber for warnings, pink for errors, and gray for secondary text. Color is turned off when output goes to a pipe or a file, when `NO_COLOR` is set, or with `--nocolor`.

### Environment Variables

| Variable | Description |
|---|---|
| `BNT_CONFIG_DIR` | Override the config directory (default: `~/.config/bnt` on macOS/Linux, `C:\Users\<you>\.config\bnt` on Windows) |
| `NO_COLOR` | Disable colored output when set to any non-empty value (see [no-color.org](https://no-color.org)). Equivalent to `--nocolor`. |

### Flags

These flags can be placed anywhere on the command line:

| Flag | Description |
|---|---|
| `--nocolor` / `--no-color` | Disable colored output for all commands. Also respected via the `NO_COLOR` environment variable. |
