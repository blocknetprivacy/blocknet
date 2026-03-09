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
  <img src="https://img.shields.io/badge/version-1.0.0-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/license-BSD--3--Clause-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-aaff00?style=flat-square&labelColor=000">
</p>

## Configuration Reference

Blocknet stores its configuration at `~/.config/bnt/config.json` (Windows: `C:\Users\<you>\.config\bnt\config.json`). If the file doesn't exist, sensible defaults are used. You can run `blocknet start` without creating a config file first, but you still need at least one installed core version.

### Comments

The config file supports `//` and `#` line comments. These are stripped before parsing, so you can annotate the file without breaking JSON syntax.

```json
{
  // this is a comment
  "auto_upgrade": true,
  # this is also a comment
  "check_interval": "24h"
}
```

URLs inside strings (e.g. `"https://example.com"`) are preserved — the comment stripper respects JSON string boundaries.

### Viewing the current config

```
blocknet config
```

This prints the active configuration as JSON, including defaults for any fields you haven't set.

---

## Full Schema

### Top-level fields

| Field | Type | Default | Description |
|---|---|---|---|
| `auto_upgrade` | bool | `true` | Automatically check for new core releases. When enabled, `blocknet start` and `blocknet status` check for new releases (respecting `check_interval` below) and download the binary if one is available. If a managed core is already running on an unpinned version (`latest` or `nightly`), blocknet may restart it to apply the new version immediately; otherwise the new version is used on next start/restart. Pinned cores are never affected. Set to `false` to disable checks. See [Automatic upgrades](reference-upgrade.md#automatic-upgrades). |
| `check_interval` | string | `"24h"` | How often to check for new core releases. Accepts Go duration strings: `"1h"`, `"30m"`, `"24h"`, `"168h"` (1 week), etc. |
| `cores` | object | *(see below)* | Per-network core configuration. Keys are `"mainnet"` and `"testnet"`. |

### Core configuration (`cores.mainnet` / `cores.testnet`)

Each network has its own configuration block. All fields are optional — omitted fields use their default value.

#### General

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | mainnet: `true`, testnet: `false` | Auto-start this core when `blocknet start` is run without arguments. Disabled cores are skipped by `start` (including explicit `blocknet start testnet`) until re-enabled with `blocknet enable <network>`. |
| `version` | string | `"latest"` | Core version to run. Accepts `"latest"` (track newest stable release), `"nightly"` ([rolling build from master](reference-upgrade.md#nightly-builds)), or a specific tag like `"v0.7.0"`. A specific tag [pins](reference-upgrade.md#pinning) the core — `blocknet upgrade` won't change it. |

#### Paths

| Field | Type | Default | Description |
|---|---|---|---|
| `data_dir` | string | `""` | Chain database and node state directory. When empty, defaults to `~/.config/bnt/data/mainnet/` (or `testnet/`). On Windows: `C:\Users\<you>\.config\bnt\data\mainnet\`. Set an absolute path to store chain data elsewhere (e.g. a larger disk). |
| `wallet_file` | string | `""` | Path to the wallet file to auto-load on startup. When empty, no wallet is loaded automatically — use the [`load`](reference-core.md#load) command in [attach mode](reference-core.md). Can be set manually or via the `load` command's "save to config" prompt. See [Auto-loading on startup](reference-wallet.md#auto-loading-on-startup). |

#### Sync

| Field | Type | Default | Description |
|---|---|---|---|
| `full_sync` | bool | `false` | Bypass checkpoint sync and download all blocks from peers. Slower but independently verifies the entire chain from genesis. |
| `save_checkpoints` | bool | `false` | Write a checkpoint record every 100 blocks. These checkpoints let future syncs skip verified ranges. |

#### Network

| Field | Type | Default | Description |
|---|---|---|---|
| `listen` | string | `""` | P2P listen address. When empty, uses the network default — mainnet `:28080`, testnet `:38080`. Set to a specific address/port to override (e.g. `"0.0.0.0:28080"`). |
| `seed` | bool | `false` | Run as a seed node with persistent p2p identity. Seed nodes help new nodes discover peers. |
| `p2p_max_inbound` | int | `0` | Maximum inbound peer connections. `0` means use the core's default. |
| `p2p_max_outbound` | int | `0` | Maximum outbound peer connections. `0` means use the core's default. |
| `p2p_whitelist_peers` | string[] | `[]` | Peer IDs that are exempt from bans. |
| `p2p_whitelist_file` | string | `""` | Path to a JSON file containing peer IDs exempt from bans. |

#### Services

| Field | Type | Default | Description |
|---|---|---|---|
| `api_addr` | string | mainnet: `"127.0.0.1:8332"`, testnet: `"127.0.0.1:18332"` | HTTP API listen address. The API is how blocknet communicates with the core. Setting this to empty disables API-dependent features (`attach` and live core stats in `status`). Binding to `127.0.0.1` restricts access to localhost — **do not bind to `0.0.0.0` unless you understand the security implications**. |
| `explorer_addr` | string | `""` | Block explorer listen address. When set, the core serves a web-based block explorer at this address. Empty means disabled. |

---

## Example config

This is the full default config with all fields shown:

```json
{
  "auto_upgrade": true,
  "check_interval": "24h",
  "cores": {
    "mainnet": {
      "enabled": true,
      "version": "latest",
      "data_dir": "",
      "wallet_file": "",
      "full_sync": false,
      "save_checkpoints": false,
      "listen": "",
      "seed": false,
      "api_addr": "127.0.0.1:8332",
      "explorer_addr": "",
      "p2p_max_inbound": 0,
      "p2p_max_outbound": 0,
      "p2p_whitelist_peers": [],
      "p2p_whitelist_file": ""
    },
    "testnet": {
      "enabled": false,
      "version": "latest",
      "data_dir": "",
      "wallet_file": "",
      "full_sync": false,
      "save_checkpoints": false,
      "listen": "",
      "seed": false,
      "api_addr": "127.0.0.1:18332",
      "explorer_addr": "",
      "p2p_max_inbound": 0,
      "p2p_max_outbound": 0,
      "p2p_whitelist_peers": [],
      "p2p_whitelist_file": ""
    }
  }
}
```

---

## Common configurations

### Run both mainnet and testnet

```json
{
  "cores": {
    "mainnet": {
      "enabled": true,
      "api_addr": "127.0.0.1:8332"
    },
    "testnet": {
      "enabled": true,
      "api_addr": "127.0.0.1:18332"
    }
  }
}
```

### Pin testnet to a specific version

```json
{
  "cores": {
    "mainnet": {
      "enabled": true,
      "version": "latest"
    },
    "testnet": {
      "enabled": true,
      "version": "v0.7.0"
    }
  }
}
```

`blocknet upgrade` will upgrade mainnet but leave testnet on v0.7.0. See [Pinning](reference-upgrade.md#pinning) for more on how this works.

### Auto-load a wallet on startup

```json
{
  "cores": {
    "mainnet": {
      "enabled": true,
      "wallet_file": "/Users/you/.config/bnt/wallets/main.wallet.dat"
    }
  }
}
```

This can also be set interactively — the [`load`](reference-core.md#load) command in attach mode asks if you want to save your choice to config. See [Wallet Management](reference-wallet.md) for the full wallet lifecycle.

### Store chain data on a different disk

```json
{
  "cores": {
    "mainnet": {
      "enabled": true,
      "data_dir": "/mnt/blocknet/mainnet"
    }
  }
}
```

### Seed node (no wallet, maximum peers)

```json
{
  "cores": {
    "mainnet": {
      "enabled": true,
      "seed": true,
      "listen": "0.0.0.0:28080",
      "p2p_max_inbound": 128,
      "p2p_max_outbound": 16
    }
  }
}
```

---

## How config maps to core flags

Each config field is translated to a core command-line flag when the core is started. The table below shows the mapping:

| Config field | Core flag |
|---|---|
| *(testnet network)* | `--testnet` |
| `api_addr` | `--api <addr>` |
| `data_dir` | `--data <dir>` |
| `wallet_file` | `--wallet <path>` |
| `listen` | `--listen <addr>` |
| `seed` | `--seed` |
| `explorer_addr` | `--explorer <addr>` |
| `full_sync` | `--full-sync` |
| `save_checkpoints` | `--save-checkpoints` |
| `p2p_max_inbound` | `--p2p-max-inbound <N>` |
| `p2p_max_outbound` | `--p2p-max-outbound <N>` |
| `p2p_whitelist_peers` | `--p2p-whitelist-peer <id>` (repeated) |
| `p2p_whitelist_file` | `--p2p-whitelist <path>` |

The `--data` flag is always passed, even when `data_dir` is empty (it resolves to the default `~/.config/bnt/data/<network>/` or `C:\Users\<you>\.config\bnt\data\<network>\` on Windows). The `--no-version-check` flag is always appended — the core's built-in version check is disabled because blocknet handles upgrades.

> **Windows note:** Use forward slashes or backslashes in `data_dir` and `wallet_file` paths — both work. Example: `"data_dir": "D:\\blocknet\\mainnet"` or `"data_dir": "D:/blocknet/mainnet"`.
