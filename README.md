<p align="center">
  <img src="blocknet.png" width="128" height="128" alt="Blocknet">
</p>

<h1 align="center">Blocknet</h1>

<p align="center">
  A client for running Blocknet cores.<br><br>
  <img src="https://img.shields.io/badge/blocknet-Mainnet-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/blocknet-Testnet-ff00aa?style=flat-square&labelColor=000">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/license-BSD--3--Clause-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-aaff00?style=flat-square&labelColor=000">
</p>

## What is this?

This program helps you install, upgrade and manage [Blocknet cores](https://github.com/blocknetprivacy/core). 

## Quick start
1. [Download Blocknet](https://github.com/blocknetprivacy/blocknet/releases/latest)
2. Run `blocknet setup` — the [setup wizard](docs/reference-blocknet.md#blocknet-setup) walks you through everything
3. Or do it manually: `blocknet install latest` then `blocknet start`
4. Optional: open the [interactive shell](docs/reference-core.md) with `blocknet attach mainnet`

> **Windows users:** The binary is `blocknet.exe`. Use `blocknet.exe setup`, etc. All other commands and documentation apply the same way.

## Build instructions
1. [Install Go](https://go.dev)
2. Clone [this repository](https://github.com/blocknetprivacy/blocknet)
3. In the Blocknet repository's folder, run `go build`, you may need `go mod tidy` first.

Note: The build process doesn't generate any text output, only a `blocknet` or `blocknet.exe` in the same directory.

## Documentation

- [Command Reference](docs/reference-blocknet.md) — all `blocknet` commands (start, stop, install, upgrade, logs, doctor, etc.)
- [Shell Reference](docs/reference-core.md) — all commands inside `blocknet attach`
- [Configuration Reference](docs/reference-config.md) — full config.json schema, defaults, and examples
- [Wallet Management](docs/reference-wallet.md) — loading, passwords, backups, recovery, and security
- [Version Management & Upgrades](docs/reference-upgrade.md) — installing, pinning, upgrading, cleanup, and nightly builds
- [Troubleshooting & FAQ](docs/troubleshooting.md) — common issues and how to fix them