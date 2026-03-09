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

## Troubleshooting & FAQ

> **Start here:** Run [`blocknet doctor`](reference-blocknet.md#blocknet-doctor) first. It checks your config, installed versions, ports, pidfiles, and running processes in one command and tells you exactly what's wrong.

---

### `blocknet start` hangs

**Symptom:** `blocknet start mainnet` prints "Starting mainnet core..." and never returns.

**Cause:** Blocknet waits up to 30 seconds for the core's API to become reachable. If the core crashes on startup or the API address is wrong, the wait times out.

**Fix:**
1. Check the log for errors — the easiest way is [`blocknet logs mainnet`](reference-blocknet.md#blocknet-logs-mainnettestnet) (or `testnet`). You can also read the file directly:
   - macOS/Linux: `~/.config/bnt/mainnet.log` (or `testnet.log`)
   - Windows: `C:\Users\<you>\.config\bnt\mainnet.log`
2. Verify the core binary exists:
   ```
   # macOS/Linux
   ls -la ~/.config/bnt/cores/v0.8.0/

   # Windows (PowerShell)
   dir $env:USERPROFILE\.config\bnt\cores\v0.8.0\
   ```
3. Make sure the [`api_addr`](reference-config.md#services) in your config isn't already in use by another process.
4. Try running the core binary directly to see its output:
   ```
   # macOS/Linux
   ~/.config/bnt/cores/v0.8.0/blocknet-core-arm64-macos --api 127.0.0.1:8332

   # Windows (PowerShell)
   & "$env:USERPROFILE\.config\bnt\cores\v0.8.0\blocknet-core-amd64-windows.exe" --api 127.0.0.1:8332
   ```

If the core ran fine before and now hangs, a stale `api.cookie` file may be the cause. Blocknet deletes the old cookie before starting, but if that fails (permissions issue), the health check can't authenticate. Remove it manually:
```
# macOS/Linux
rm ~/.config/bnt/data/mainnet/api.cookie

# Windows (PowerShell)
Remove-Item $env:USERPROFILE\.config\bnt\data\mainnet\api.cookie
```

---

### Starting a disabled core

**Symptom:** `blocknet start mainnet` prints `mainnet is disabled — run blocknet enable mainnet first` and exits without starting anything.

**Cause:** The core you named explicitly has `enabled: false` in the [config](reference-config.md). Disabled means "do not auto-start" — but blocknet also won't let you start it explicitly without opting back in, to make the disabled state intentional and visible.

**Fix:** Enable the core, then start it:
```
blocknet enable mainnet
blocknet start mainnet
```

Or if you want to run it temporarily without permanently enabling it, you can manually edit the config, start, then disable again. See [`blocknet enable`](reference-blocknet.md#blocknet-enable-mainnettestnet) for details.

---

### `blocknet start` says "no cores enabled"

**Symptom:** `error: no cores enabled in config — enable one or specify a network`

**Cause:** No cores have `enabled: true` in the [config](reference-config.md). By default, mainnet is enabled and testnet is disabled.

**Fix:** Either run [`blocknet setup`](reference-blocknet.md#blocknet-setup) to configure from scratch, or enable a core manually:
```
blocknet enable mainnet
blocknet start
```
or:
```
blocknet enable mainnet
blocknet start mainnet
```

---

### `blocknet start` says version is not installed

**Symptom:** `error: mainnet: no cores installed (run 'blocknet install <version>')`

**Cause:** No core binaries have been downloaded yet. The config says `"version": "latest"` but there's nothing in `~/.config/bnt/cores/`.

**Fix:** Install a version first, or run [`blocknet setup`](reference-blocknet.md#blocknet-setup) which handles this for you:
```
blocknet install latest
blocknet start
```

---

### `blocknet attach` says "core is not reachable"

**Symptom:** `error: mainnet core is not reachable at 127.0.0.1:8332`

**Cause:** The core process isn't running, or it's running on a different port than what's in the config.

**Fix:**
1. Check if the core is running:
   ```
   blocknet status
   ```
2. If it shows `[stopped]`, start it:
   ```
   blocknet start mainnet
   ```
3. If it shows `[running]` but attach still fails, the [`api_addr`](reference-config.md#services) in your config might not match what the core is actually listening on. Check the config:
   ```
   blocknet config
   ```

---

### "wallet is locked"

**Symptom:** Most commands in attach mode return "wallet is locked".

**Cause:** The wallet was locked (either manually via `lock` or by the core on startup). While locked, only `unlock`, `load`, `unload`, `help`, and `quit` work.

**Fix:**
```
> unlock
Password: ********
# Unlocked
```

See [Locking and unlocking](reference-wallet.md#locking-and-unlocking) for more details.

---

### `load` says "no wallet files found"

**Symptom:** The `load` command doesn't find any wallet files to choose from.

**Cause:** There are no `.wallet.dat` files in any of the [scanned directories](reference-wallet.md#where-wallet-files-live).

**Fix:**
- If you have a wallet file somewhere else, choose "Enter a custom path" and type the full path.
- If you're starting fresh, choose "Create a new wallet".
- If you previously had wallets, check `~/.config/bnt/wallets/` (Windows: `C:\Users\<you>\.config\bnt\wallets\`) — blocknet backs up loaded wallets there automatically.

---

### Can't switch wallets

**Symptom:** You loaded a wallet and now want to load a different one, but `load` says "A wallet is already loaded."

**Cause:** The core only supports one wallet loaded at a time.

**Fix:** Use [`unload`](reference-core.md#unload) to release the current wallet, then `load` a different one — no restart needed:
```
> unload
# Unloaded
  Wallet unloaded. Use 'load' to open another.
> load
```

Alternatively, restart the core:
```
blocknet restart mainnet
blocknet attach mainnet
> load
```

If you want a specific wallet to load automatically on each start, set [`wallet_file`](reference-config.md#paths) in the config or say "yes" when `load` asks to save the path.

---

### Port already in use

**Symptom:** Core fails to start with an "address already in use" error in the log.

**Cause:** Another process (or another core instance) is already bound to the same port.

**Fix:**
1. Check what's using the port:
   ```
   # macOS/Linux
   lsof -i :8332

   # Windows (PowerShell or CMD)
   netstat -ano | findstr :8332
   ```
2. If it's a leftover core process, stop it:
   ```
   blocknet stop mainnet
   ```
3. If another program is using the port, change the [`api_addr`](reference-config.md#services) in your config to a different port.

Default ports:
| Network | P2P | API |
|---|---|---|
| Mainnet | 28080 | 8332 |
| Testnet | 38080 | 18332 |

---

### Sync is slow or stuck

**Symptom:** The wallet balance doesn't update, or `outputs` shows the scanner is behind chain height.

**Cause:** The wallet's output scanner hasn't caught up to the chain tip yet. This is normal after importing a wallet or starting fresh — the scanner has to process every block.

**Fix:**
1. Check sync progress:
   ```
   > outputs
   # Outputs
     No outputs found yet.
     Wallet scan is still catching up (1200/14207).
     Try: sync
   ```
2. Trigger a rescan:
   ```
   > sync
   ```
3. Wait. Scanning is CPU-bound and takes time proportional to chain height.

If the core itself is behind (few peers, chain height not increasing), check connectivity:
```
> peers
```
If you have 0 peers, the core can't find the network. Check your firewall and internet connection.

---

### `blocknet install` fails with "no asset found"

**Symptom:** `error: release v0.5.0 does not include a binary for your platform (blocknet-core-arm64-macos)`

**Cause:** The release doesn't have a binary for your platform. This is expected for early releases before multi-platform builds were added, or if the CI build failed for that version.

**Fix:**
- Try a newer version: `blocknet install latest`
- See what's available: `blocknet list`
- Check the [releases page](https://github.com/blocknetprivacy/core/releases) directly to see which platforms are available.
- If you're on an unusual architecture, you may need to build from source.

---

### Stale pidfile / "already running" but it's not

**Symptom:** `blocknet start mainnet` says "mainnet already running (pid 12345)" but the core isn't actually running.

**Cause:** The core crashed or was killed externally without cleaning up its pidfile. [`blocknet doctor`](reference-blocknet.md#blocknet-doctor) detects this automatically.

**Fix:**
```
blocknet stop mainnet
blocknet start mainnet
```

`blocknet stop` detects stale pidfiles and cleans them up. If that doesn't work, remove the pidfile manually:
```
# macOS/Linux
rm ~/.config/bnt/core.mainnet.pid

# Windows (PowerShell)
Remove-Item $env:USERPROFILE\.config\bnt\core.mainnet.pid
```

---

### Wrong balance / missing transactions

**Symptom:** Your balance is lower than expected or recent transactions aren't showing up.

**Cause:** The wallet scanner may not have processed all blocks yet, especially after an import or a long time offline.

**Fix:**
1. Check scan progress vs chain height:
   ```
   > outputs
   ```
   Compare `Wallet scan is still catching up (X/Y)` values (`X` = scanned height, `Y` = chain height).
2. Trigger a full rescan:
   ```
   > sync
   ```
3. Wait for the scan to complete — it processes blocks sequentially.

If the balance is still wrong after a full scan, your wallet file may be corrupted. [Recover from your seed](reference-wallet.md#recovery-from-seed) to create a fresh wallet.

---

### How do I move my data to another disk?

Set the [`data_dir`](reference-config.md#paths) in your config to point to the new location:

```json
{
  "cores": {
    "mainnet": {
      "data_dir": "/mnt/external/blocknet/mainnet"
    }
  }
}
```

Then stop, move the data, and restart:
```
# macOS/Linux
blocknet stop mainnet
mv ~/.config/bnt/data/mainnet/* /mnt/external/blocknet/mainnet/
blocknet start mainnet

# Windows (PowerShell)
blocknet.exe stop mainnet
Move-Item $env:USERPROFILE\.config\bnt\data\mainnet\* D:\blocknet\mainnet\
blocknet.exe start mainnet
```

---

### How do I back up my wallet?

Blocknet automatically copies loaded wallets to `~/.config/bnt/wallets/` (Windows: `C:\Users\<you>\.config\bnt\wallets\`) when you use the [`load`](reference-core.md#load) command. You can also manually copy your `.wallet.dat` file.

The safest backup is your **12-word recovery seed** — with it, you can recreate the wallet on any machine. See [Viewing your recovery seed](reference-wallet.md#viewing-your-recovery-seed).

---

### How do I disable automatic upgrades?

Set [`auto_upgrade`](reference-config.md#top-level-fields) to `false` in your config:

```json
{
  "auto_upgrade": false
}
```

You can still upgrade manually with [`blocknet upgrade`](reference-blocknet.md#blocknet-upgrade) whenever you're ready.

---

### How do I run both mainnet and testnet?

[Enable](reference-blocknet.md#blocknet-enable-mainnettestnet) both in the config:

```
blocknet enable mainnet
blocknet enable testnet
blocknet start
```

Each core runs in its own process with isolated data, wallet, and ports. Attach to each one separately:

```
blocknet attach mainnet
blocknet attach testnet
```

See [Different wallets per network](reference-wallet.md#different-wallets-per-network) for wallet setup.

---

### Where are the log files?

Core stdout/stderr is captured to log files in the config directory:

| Platform | Path |
|---|---|
| macOS/Linux | `~/.config/bnt/mainnet.log` and `testnet.log` |
| Windows | `C:\Users\<you>\.config\bnt\mainnet.log` and `testnet.log` |

The easiest way to view logs is [`blocknet logs mainnet`](reference-blocknet.md#blocknet-logs-mainnettestnet) (or `testnet`), which tails the file and follows new output in real time.

These files are appended to on each start — they grow over time. You can safely delete or truncate them while the core is stopped.

---

### How do I completely reset everything?

**Step 1: Back up your wallets first.**

```
# macOS/Linux
mkdir -p ~/blocknet-backup
cp ~/.config/bnt/wallets/*.wallet.dat ~/blocknet-backup/

# Windows (PowerShell)
mkdir $env:USERPROFILE\blocknet-backup -Force
Copy-Item $env:USERPROFILE\.config\bnt\wallets\*.wallet.dat $env:USERPROFILE\blocknet-backup\
```

Confirm the backup exists before continuing:
```
# macOS/Linux
ls ~/blocknet-backup/

# Windows (PowerShell)
dir $env:USERPROFILE\blocknet-backup\
```

You should see your `.wallet.dat` files listed. If the folder is empty, your wallets may be somewhere else — check the [wallet locations table](reference-wallet.md#where-wallet-files-live) before proceeding.

**Step 2: Stop all cores and delete the config directory.**

```
# macOS/Linux
blocknet stop
rm -rf ~/.config/bnt

# Windows (PowerShell)
blocknet.exe stop
Remove-Item -Recurse -Force $env:USERPROFILE\.config\bnt
```

This deletes your config, chain data, wallet backups, and installed core binaries. Your wallet backup in `~/blocknet-backup/` is safe.

Even with a wallet backup, you should also have your [12-word recovery seed](reference-wallet.md#viewing-your-recovery-seed) written down — it's the only way to recover if both the original and backup are lost.
