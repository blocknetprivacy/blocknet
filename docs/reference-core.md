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

## Interactive Command Reference

These commands are available inside `blocknet attach`, which opens an interactive shell connected to a running [Blocknet core](https://github.com/blocknetprivacy/core). The core is the daemon that runs the blockchain node, wallet, miner, and peer-to-peer network. Most commands below are sent to the core over its HTTP API; a few are local shell helpers (for example `help`, `about`, `license`, `save`, and `quit`).

Closing the shell (`quit` or Ctrl-C) does not stop the core. See [reference-blocknet.md](reference-blocknet.md) for the commands that manage core lifecycle (start, stop, install, upgrade, etc.).

### Command Summary

#### Wallet
| Command | Description |
|---|---|
| `load` | Load or create a wallet |
| `unload` | Unload the current wallet |
| `balance` | Show wallet balance |
| `address` | Show receiving address |
| `send <addr> <amt> [memo]` | Send funds with optional memo |
| `sign` | Sign a message with your spend key |
| `verify` | Verify a signed message against an address |
| `history` | Show transaction history |
| `outputs` | Show wallet outputs (spent and unspent) |
| `seed` | Show wallet recovery seed (careful!) |
| `import` | Create wallet file from seed or spend/view keys |
| `viewkeys` | Export view-only keys |
| `lock` | Lock wallet |
| `unlock` | Unlock wallet |
| `prove <txid>` | Generate payment proof |
| `audit` | Check wallet for burned outputs |
| `save` | Save wallet to disk |
| `sync` | Rescan blocks for outputs |

#### Daemon
| Command | Description |
|---|---|
| `status` | Show node and wallet status |
| `explore <id>` | Look up a block, transaction, or mempool |
| `mempool` | Show mempool statistics |
| `peers` | List connected peers |
| `banned` | List banned peers |
| `export-peer` | Export peer addresses to peer.txt |
| `mining` | Manage mining |
| `certify` | Check chain integrity (difficulty + timestamps) |
| `purge` | Delete all blockchain data (cannot be undone) |
| `version` | Print version |
| `about` | About this software |
| `license` | Show license |
| `quit` | Exit (saves automatically) |
| `help <command>` | Show detailed help for a command |

---

### Detailed Command Reference

---

#### `load`

Loads or creates a wallet in the running core. See the [Wallet Management](reference-wallet.md) guide for the full story on loading, backups, auto-load, and recovery.

**Use this when:**
you just started the core and need to open your wallet, or you want to create a new one.

**Example — loading an existing wallet:**
```
> load
  Found wallet files:
  1) /Users/you/.config/bnt/wallets/main.wallet.dat
  2) /Users/you/blocknet-mainnet.wallet.dat
  3) Enter a custom path
  4) Create a new wallet

  Choose: 1
  Password: ********

  Wallet loaded
  Address: 9PNo...
```

**Example — creating a new wallet:**
```
> load
  ...
  4) Create a new wallet

  Choose: 4
  Wallet name (without extension):
> savings
  Password: ********

  Wallet created
  Address:  9PNo...
  Filename: savings.wallet.dat
```

**Notes:**
- Only one wallet can be loaded per core session. Use [`unload`](#unload) to switch wallets, then `load` again.
- The selected wallet path is saved to config automatically so future starts [auto-load](reference-wallet.md#auto-loading-on-startup) it via the `--wallet` flag. See the [Configuration Reference](reference-config.md#paths) for the `wallet_file` field.

---

#### `unload`

Unloads the currently loaded wallet from the core, releasing all in-memory key material. The core returns to the same state as before `load` was called — all wallet commands return an error until a wallet is loaded again.

**Use this when:**
you want to switch wallets without restarting the core.

**Example:**
```
> unload

# Unloaded
  Wallet unloaded. Use 'load' to open another.
```

**Notes:**
- Works even if the wallet is locked.
- After unloading, use [`load`](#load) to open a different wallet.

---

#### `balance`

**Aliases:** `bal`, `b`

Shows your spendable coins, pending coins, and total.

**Use this when:**
you want to know how much you can spend right now.

**Example:**
```
> bal

# Balance
  spendable:  12.5 BNT
  confirming: 1 BNT
  total:      13.5 BNT
  outputs:    9 unspent, 5 spent
```

---

#### `address`

**Aliases:** `addr`, `a`

Shows your receive address to share with someone paying you.

**Use this when:**
someone asks where to send you coins.

**Example:**
```
> addr

# Address

  9PNoFCqUa7K8e5JfV2Hs3TBt7kMzRGkPxJ4xVmn5cFb...

  Get a short name like @name or $name at https://blocknet.id
```

**Example — view-only wallet:**
```
> addr

# Address

  9PNoFCqUa7K8e5JfV2Hs3TBt7kMzRGkPxJ4xVmn5cFb...
  (view-only wallet — cannot send or sign)

  Get a short name like @name or $name at https://blocknet.id
```

---

#### `send`

```
send <address> <amount> [memo|hex:<memo_hex>]
```

Sends BNT to another wallet, optionally with a note.

**Use this when:**
you need to pay someone now.

**Example:**
```
> send @rock 100 "hello"

# Send

  Send 100 BNT to @rock?
  Fee:     0.00015 BNT
  Change:  12.49985 BNT
  Memo:    hello
  Confirm [y/N]: y
  Sent: 9f0b...
  Explorer: https://explorer.blocknetcrypto.com/tx/9f0b...
```

**Notes:**
- You can send whole numbers or fractions (example: `1` or `1.25` BNT).
- Memos with spaces are supported.
- Short names can be used as `@name` or `$name`.
- `send all` sends your entire spendable balance.
- Pasting a `blocknet://` URI or `bntpay.com/` link auto-parses as a send.

---

#### `sign`

Signs a message so you can prove wallet ownership.

**Use this when:**
a service asks you to prove this wallet is yours.

**Example:**
```
> sign
  Enter the text to sign, press ENTER when you're done.

> prove wallet ownership

# Sign
  8f2d... (signature hex)
```

**Notes:**
- View-only wallets cannot sign.
- Message should be short (up to about 1,000 characters).

---

#### `verify`

Checks if a signature really came from an address.

**Use this when:**
you received a signed message and need to trust it.

**Example:**
```
> verify
  Enter the address:
> 9PNo...
  Enter the message that was signed:
> prove wallet ownership
  Enter the signature (hex):
> 8f2d...

# Signature is VALID
```

**Notes:**
- Signature must be pasted exactly as produced by `sign`.

---

#### `history`

**Aliases:** `hist`, `h`

Shows incoming transactions, oldest to newest.

**Use this when:**
you need to review recent wallet activity.

**Example:**
```
> hist

# History
  block 14200 IN  72.325 BNT  coinbase  c7f2e1d3...
  block 14205 IN  1.25 BNT    regular   a1b2c3d4...
```

---

#### `outputs`

**Aliases:** `outs`, `out`

```
outputs [spent|unspent|pending] [index]
outputs tx <txid>
outputs tx <txid>:<index>
```

Shows outputs your wallet owns, with status and drill-down details.

**Use this when:**
you want to inspect spendable/spent/pending outputs.

**Example:**
```
> outputs unspent

# Outputs
  #1  unspent     regular  conf: 217
      amount: 7.5 BNT
      block:  13990  tx: c7f2e1d3...:1
  #2  unspent     coinbase conf: 7
      amount: 72.325 BNT
      block:  14200  tx: a1b2c3d4...:0
```

```
> outputs 1

# Outputs
  #1
    status:       unspent
    amount:       7.5 BNT
    type:         regular
    confirmations:217
    block:        13990
    tx output:    c7f2e1d3...:1
    one-time pub: ...
    commitment:   ...
```

**Notes:**
- Use filters: `spent`, `unspent`, `pending`.
- Use an index to see one output's details (example: `outputs 3`).
- `outputs tx <txid>` shows all owned outputs in that tx.

---

#### `seed`

Shows your 12-word recovery seed after warning prompts. See [Viewing your recovery seed](reference-wallet.md#viewing-your-recovery-seed) for important security guidance.

**Use this when:**
you are backing up wallet recovery words.

**Example:**
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

**Notes:**
- Anyone with this seed can spend your funds.

---

#### `import`

Creates a new wallet file from a seed phrase. See [Recovery from seed](reference-wallet.md#recovery-from-seed) for the full recovery workflow.

**Use this when:**
you need to load an existing wallet into this node.

**Example:**
```
> import

# Import
  1) 12-word recovery seed
  2) spend-key/view-key (hex private keys)

  Choose [1/2]: 1
  Input the 12 words of your seed:
> abandon ability able about above absent absorb abstract absurd abuse access accident
  Input the name of this wallet:
> restored.wallet.dat
  Password: ********

  name: restored.wallet.dat
  address: 9PNo...
```

**Notes:**
- Option 2 (spend-key/view-key) is not implemented in `blocknet attach`; use the core CLI directly with `--cli` for key-based import.

---

#### `viewkeys`

Exports your view-only keys (spend public, view private, view public).

**Use this when:**
you want watch-only access on another machine.

**Example:**
```
> viewkeys

# View Keys
  WARNING: Your view private key lets anyone see all incoming funds.
  Never share it unless you understand the implications.

  Export view-only keys? [y/N]: y
  Password: ********

  spend public key:  abc123...
  view private key:  def456...
  view public key:   789abc...

  To create a view-only wallet on another machine, use these keys
  with the import command (option 2: spend-key/view-key).
```

**Notes:**
- Requires password confirmation.
- The view private key lets anyone see all incoming funds — share it carefully.

---

#### `prove`

```
prove <txid>
```

Generates a proof that you sent a transaction by revealing the transaction's one-time key.

**Use this when:**
someone needs proof of payment.

**Example:**
```
> prove a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2

# Prove
  txid:    a1b2c3d4e5f6...f0a1b2
  tx key:  deadbeef0123...

  Share this tx key with the recipient so they can verify you sent the transaction.
```

**Notes:**
- Share the tx key with the recipient so they can verify the payment.

---

#### `audit`

Scans wallet outputs for duplicate key images (burned funds detection).

**Use this when:**
you suspect a key derivation issue burned some outputs.

**Example:**
```
> audit

# Audit
  Scanning wallet outputs for duplicate key images...
  Total outputs:      42
  Unique key images:  42

  No duplicate key images found. Wallet is clean.
```

**Notes:**
- A clean audit means no burned funds.
- Duplicates indicate permanently unspendable outputs from a historical self-send bug.

---

#### `lock`

Locks wallet actions that require your password. See [Locking and unlocking](reference-wallet.md#locking-and-unlocking) for details on what's blocked while locked.

**Use this when:**
you are stepping away from your terminal.

**Example:**
```
> lock

# Locked
```

---

#### `unlock`

Unlocks wallet actions after password confirmation.

**Use this when:**
you get a "wallet is locked" error.

**Example:**
```
> unlock
Password: ********

# Unlocked
```

---

#### `save`

The core daemon saves the wallet automatically.

**Use this when:**
you want to confirm wallet state is persisted.

**Example:**
```
> save

# Saved
  Wallet is saved automatically by the core daemon.
```

---

#### `sync`

**Aliases:** `scan`

Rescans the blockchain for wallet outputs. This is not peer-to-peer sync — it scans blocks that are already downloaded, looking for outputs that belong to your wallet.

**Use this when:**
your wallet balance looks wrong or you're missing transactions. See [Sync is slow or stuck](troubleshooting.md#sync-is-slow-or-stuck) if the scanner isn't catching up.

**Example:**
```
> sync

# Sync
  Scanning for wallet outputs...
  Scanned 7 blocks to height 14207
  Outputs found: 1
  Outputs spent: 0
```

**Example — already up to date:**
```
> sync

# Sync
  Scanning for wallet outputs...
  Wallet is up to date at height 14207.
```

---

#### `status`

Shows node health and wallet summary in one screen.

**Use this when:**
you need a quick "is everything healthy?" check.

**Example:**
```
> status

# Node
  Peer ID:     12D3KooW...
  Peers:       8
  Height:      14207
  Best Hash:   0000c3a5b7e2d1f4
  Syncing:     false

# Wallet
  Type:        Full
  Balance:     12.5 BNT + 1 BNT pending
  Outputs:     9 unspent / 14 total
  Address:     9PNo...
```

---

#### `peers`

Lists currently connected peers.

**Use this when:**
you need to confirm network connectivity.

**Example:**
```
> peers

# Peers (8)
  12D3KooWBLUP...
    /ip4/192.168.1.5/tcp/28080
  12D3KooWNoUc...
    /ip4/10.0.0.2/tcp/28080
  ...
```

---

#### `banned`

Shows peers that were banned and why.

**Use this when:**
you suspect peer filtering or connectivity issues.

**Example:**
```
> banned

# Banned (1)
  12D3KooWXyz...
    addr:   /ip4/...
    reason: repeated bad blocks
    count:  3x, expires in 2h30m
```

---

#### `export-peer`

Writes connected peer addresses to `peer.txt`.

**Use this when:**
you want another node to connect to known peers.

**Example:**
```
> export-peer

# Export
  8 peer addresses written to peer.txt
  Share this file or its contents with other nodes.
```

---

#### `mining`

```
mining
mining start
mining stop
mining threads <N>
```

Controls local mining and how many CPU threads mining uses.

**Use this when:**
you want to mine, stop mining, or tune CPU/RAM use.

**Example:**
```
> mining start

# Mining
  Started

> mining threads 4

# Mining
  Threads set to 4 (~8GB RAM)

> mining

# Mining — active (2m31s)
  Hashrate:     12.50 H/s
  Total hashes: 1893

> mining stop

# Mining
  Stopped
```

**Notes:**
- Roughly 2GB RAM per thread.
- Thread aliases: `threads`, `thread`, `t`.

---

#### `explore`

**Aliases:** `exp`

```
explore <height>
explore <hash>
explore mempool
```

Look up a block by height, a block or transaction by 64-character hex hash, or view mempool statistics. A single command for inspecting chain data without leaving the terminal.

**Use this when:**
you want to inspect a block, look up a transaction, or check what's in the mempool.

**Example — block by height:**
```
> explore 14207

# Block 14207
  Hash:          0000c3a5b7e2d1f489a1bc37e5d204f8c612aa9b33e7f04d12b8a9e6c7f50321
  Previous:      0000a1f38e2bc9d7a436ef21c87b3d4e59a0f1b267e3c9d58a2b41f6e7083c19
  Merkle Root:   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  Time:          2025-02-05 22:02:00 UTC
  Difficulty:    100000
  Nonce:         847291
  Reward:        72.325093035 BNT
  Confirmations: 1

  Transactions (2):
    cb  c7f2e1d3...abcdef  0 in → 1 out  fee: —
        a1b2c3d4...f0a1b2  1 in → 2 out  fee: 0.00015 BNT

  https://explorer.blocknetcrypto.com/block/14207
```

**Example — transaction by hash:**
```
> explore a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2

# Transaction
  Hash:          a1b2c3d4e5f6...f0a1b2
  Status:        confirmed (block 14205)
  Confirmations: 3
  Fee:           0.00015 BNT
  Inputs:        1
  Outputs:       2

  https://explorer.blocknetcrypto.com/tx/a1b2c3d4...f0a1b2
```

**Notes:**
- A 64-char hex hash is tried as a block hash first, then as a transaction hash.
- Numeric input is always treated as a block height.
- `explore mempool` is equivalent to the [`mempool`](#mempool) command.

---

#### `mempool`

Shows mempool statistics and lists pending transactions.

**Use this when:**
you want to see what's waiting to be mined.

**Example:**
```
> mempool

# Mempool
  Transactions: 5
  Size:         8.2 KB
  Fee (min):    0.0001 BNT
  Fee (max):    0.00025 BNT
  Fee (avg):    0.000146 BNT

  Pending:
    1)  1 in → 2 out  fee: 0.00012 BNT
    2)  1 in → 1 out  fee: 0.0001 BNT
    ...
```

**Notes:**
- Shortcut for `explore mempool`.
- Shows up to 25 pending transactions.
- When the mempool is empty, prints "Empty — no pending transactions".

---

#### `certify`

Verifies chain integrity by checking difficulty, timestamps, and block linkage.

**Use this when:**
you suspect corruption or strange chain behavior.

**Example:**
```
> certify

# Certify
  Verifying chain integrity (difficulty, timestamps, linkage)...
  Chain height: 14207
  Chain is clean. No violations found.
```

**Notes:**
- Arithmetic-only check — does not re-hash blocks.
- May take a moment on long chains.

---

#### `purge`

Deletes local chain data but keeps your wallet and funds.

**Use this when:**
chain is stuck/corrupted and regular sync cannot recover.

**Example:**
```
> purge

# Purge
  This will delete all blockchain data.
  Your wallet will NOT be deleted.
  This action CANNOT be undone.

  Confirm purge? [y/N]: y
  Password: ********
  Blockchain data purged. Core will shut down.
```

**Notes:**
- Your wallet file and money are not deleted.
- Requires password confirmation.

---

#### `version`

Prints the Blocknet version.

**Example:**
```
> version

# Version 
```

---

#### `about`

Shows project info and upstream links.

**Example:**
```
> about

# About
  Blocknet v
  Zero-knowledge money. Made in USA.

  BSD 3-Clause License
  Copyright (c) 2026, Blocknet Privacy

  https://blocknetcrypto.com
  https://explorer.blocknetcrypto.com
  https://github.com/blocknetprivacy
```

---

#### `license`

Prints the full software license text.

---

#### `quit`

**Aliases:** `exit`, `q`

Exits the attach session. The core keeps running.
