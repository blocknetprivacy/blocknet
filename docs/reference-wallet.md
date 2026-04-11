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

## Wallet Management

This guide covers how wallets work with Blocknet: loading, passwords, backups, recovery, and using different wallets across networks.

---

### How wallets work

A Blocknet wallet is a single `.wallet.dat` file that contains your private keys, transaction history, and output scanner state. The core daemon manages the wallet — blocknet just tells the core which wallet file to open.

Wallets are password-protected by default. The password encrypts the spend key at rest. You set the password when creating or importing a wallet, and enter it when loading.

Each core instance can have one wallet loaded at a time. If you're running both mainnet and testnet, each core uses a separate wallet file.

---

### Loading a wallet

After [starting a core](reference-blocknet.md#blocknet-start-mainnettestnet), [attach](reference-blocknet.md#blocknet-attach-mainnettestnet) to it and use the [`load`](reference-core.md#load) command:

```
blocknet attach mainnet
> load
```

The `load` command:

1. Scans several directories for `.wallet.dat` files:
   - `~/.config/bnt/wallets/` (Windows: `C:\Users\<you>\.config\bnt\wallets\`) — blocknet's managed wallet backups
   - `~/.config/blocknet/mainnet/` (or `testnet/`) — legacy core wallet location
   - Your home directory (`~/` or `C:\Users\<you>\` on Windows)
   - The core's data directory
   - Your current working directory

2. Presents a numbered list of found wallets, plus options to enter a custom path or create a new wallet.

3. Prompts for your wallet password.

4. Loads the wallet into the running core and saves the wallet path to config for [auto-loading](#auto-loading-on-startup) on future starts.

```
> load

# Load Wallet
  Found wallet files:
  1) /Users/you/.config/bnt/wallets/main.wallet.dat
  2) /Users/you/blocknet-mainnet.wallet.dat
  3) Enter a custom path
  4) Create a new wallet

  Choose: 1
  Password: ********

  Wallet loaded
  Address: 9PNo...
  Backup: /Users/you/.config/bnt/wallets/main.wallet.dat
```

If you choose "Create a new wallet", the core generates a fresh wallet with a new BIP39 seed:

```
  Choose: 4
  Wallet name (without extension):
> savings
  Password: ********

  Wallet created
  Address:  9PNo...
  Filename: savings.wallet.dat
```

Only one wallet can be loaded at a time. To switch wallets, use [`unload`](reference-core.md#unload) to release the current one and then `load` a different one — no restart needed.

---

### Auto-loading on startup

When you load or create a wallet, the path is saved to config automatically. The core will load that wallet every time it starts. You can also set it manually by editing [`config.json`](reference-config.md). See the [`wallet_file`](reference-config.md#paths) field in the Configuration Reference.

```json
{
  "cores": {
    "mainnet": {
      "wallet_file": "/Users/you/.config/bnt/wallets/main.wallet.dat"
    }
  }
}
```

This means `blocknet start` followed by `blocknet attach` will drop you straight into a ready wallet — no `load` step needed.

---

### Automatic backups

When you load a wallet from any location, blocknet copies it to `~/.config/bnt/wallets/`. On macOS/Linux, backups are written with `0600` permissions (owner read/write only). On Windows, standard user-level file permissions apply. This is a safety net — if the original file is deleted or corrupted, a backup exists in a known location.

Backups are not overwritten if a file with the same name already exists in the wallets directory.

---

### Wallet passwords

Every wallet has a password that encrypts the spend key. You need the password to:

- Load a wallet (`load`)
- Unlock the wallet (`unlock`)
- View your recovery seed (`seed`)
- Export view-only keys (`viewkeys`)
- Import a wallet from seed (`import`)
- Purge blockchain data (`purge`)

The password is never stored by blocknet. If you forget it, the only recovery path is your 12-word seed.

---

### Locking and unlocking

You can lock your wallet during an attach session to prevent any spending operations:

```
> lock
# Locked
```

While locked, most commands return "wallet is locked". Only `unlock`, `load`, `unload`, `help`, and `quit` work. To unlock:

```
> unlock
Password: ********
# Unlocked
```

Lock your wallet if you're stepping away from the terminal or leaving an attach session running unattended.

---

### Recovery from seed

If you need to recover a wallet (lost file, new machine, corrupted data), use the [`import`](reference-core.md#import) command in [attach mode](reference-core.md):

```
> import

# Import
  1) 12-word recovery seed
  2) spend-key/view-key (hex private keys)

  Choose [1/2]: 1
  Input the 12 words of your seed:
> abandon ability able about above absent absorb abstract absurd abuse access accident
  Input the name of this wallet:
> recovered.wallet.dat
  Password: ********

  name: recovered.wallet.dat
  address: 9PNo...
```

Key-based import (option 2) is not implemented in `blocknet attach`; use the core CLI directly with `--cli` if you need spend/view-key import.

After importing, the core will scan the blockchain for your outputs. This can take a while depending on chain height. Use [`sync`](reference-core.md#sync) to trigger a rescan if needed.

---

### Viewing your recovery seed

```
> seed

# Seed
  WARNING: Your recovery seed controls all funds.
  Anyone with this seed can steal your coins.
  Never share it. Never enter it online.

  Show recovery seed? [y/N]: y
  Password: ********

   1.abandon    2.ability    3.able       4.about
   5.above      6.absent     7.absorb     8.abstract
   9.absurd    10.abuse     11.access    12.accident

  Write these words down and store them safely.
  Recover with: import (option 1: recovery seed)
```

**Store your seed offline.** Write it on paper and keep it somewhere safe. Do not save it in a text file, notes app, or cloud storage. Anyone with these 12 words has full control of your funds. See also [How do I back up my wallet?](troubleshooting.md#how-do-i-back-up-my-wallet)

---

### Different wallets per network

Mainnet and testnet are fully isolated — each runs its own core process with its own wallet. You can (and should) use different wallet files for each:

```json
{
  "cores": {
    "mainnet": {
      "wallet_file": "/Users/you/.config/bnt/wallets/main.wallet.dat"
    },
    "testnet": {
      "wallet_file": "/Users/you/.config/bnt/wallets/test.wallet.dat"
    }
  }
}
```

Or just use [`load`](reference-core.md#load) in each attach session — [`blocknet attach mainnet`](reference-blocknet.md#blocknet-attach-mainnettestnet) and `blocknet attach testnet` operate independently.

---

### Where wallet files live

| Location | Windows equivalent | Purpose |
|---|---|---|
| `~/.config/bnt/wallets/` | `C:\Users\<you>\.config\bnt\wallets\` | Blocknet's managed backup directory. Wallets are copied here automatically when loaded. |
| `~/.config/blocknet/mainnet/` | `C:\Users\<you>\.config\blocknet\mainnet\` | Legacy location from older core versions. Scanned by `load`. |
| `~/.config/blocknet/testnet/` | `C:\Users\<you>\.config\blocknet\testnet\` | Legacy location (testnet). Scanned by `load`. |
| `~/` | `C:\Users\<you>\` | Home directory. Scanned by `load` in case wallets were saved there. |
| Core's `data_dir` | *(same)* | The chain data directory. Scanned by `load`. |
| Current working directory | *(same)* | Wherever you ran `blocknet` from. Scanned by `load`. |

---

### Security

- Wallet files are encrypted with your password. Without the password or seed, the file is unusable.
- On macOS/Linux, backups in `~/.config/bnt/wallets/` and the API cookie (`api.cookie`) are written with `0600` permissions (owner-only). On Windows, standard user-level file permissions apply — only your user account can access these files.
- Never expose the API port ([`api_addr`](reference-config.md#services)) to the public internet. Keep it bound to `127.0.0.1`.
- The [`sign`](reference-core.md#sign) command can prove wallet ownership without revealing keys. Use [`verify`](reference-core.md#verify) to check signatures from others.
