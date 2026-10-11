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

## Interactive Command Reference

These commands are available inside `blocknet attach`, which opens an interactive shell connected to a running [Blocknet core](https://github.com/blocknetprivacy/core). The core is the daemon that runs the blockchain node, wallet, miner, and peer-to-peer network. Most commands below are sent to the core over its HTTP API; a few are local shell helpers (for example `help`, `about`, `license`, and `quit`).

Closing the shell (`quit` or Ctrl-C) does not stop the core. See [reference-blocknet.md](reference-blocknet.md) for the commands that manage core lifecycle (start, stop, install, upgrade, etc.).

Type `help` inside attach for the command list, or `help <command>` for usage, short names, an example and notes. A command given more arguments than it takes is refused with its usage line, for example `Too many arguments: x (usage: balance)`.

### Command Summary

#### Wallet
| Command | Description |
|---|---|
| `load` | Loads a wallet file into the core, or creates one |
| `unload` | Unloads the current wallet |
| `balance` | Shows the wallet balance |
| `address` | Shows the receive address |
| `send <addr> <amt> [memo]` | Sends BNT, with an optional memo |
| `send <addr> all [memo]` | Sends the whole spendable balance |
| `sign` | Signs a message with your spend key |
| `verify` | Checks a signed message against an address |
| `history` | Shows incoming and outgoing transactions |
| `outputs` | Shows wallet outputs (spent, unspent, pending) |
| `seed` | Shows the recovery seed (careful) |
| `import` | Creates a wallet from a seed, keys or view keys |
| `viewkeys` | Shows view keys and saves a view-only wallet |
| `lock` | Locks the wallet |
| `unlock` | Unlocks the wallet |
| `prove <txid>` | Shows a payment proof for a transaction |
| `audit` | Checks the wallet for burned outputs |
| `sync` | Rescans blocks for wallet outputs |

#### Daemon
| Command | Description |
|---|---|
| `status` | Shows node and wallet status |
| `explore <id>` | Looks up a block, a transaction or the mempool |
| `mempool` | Shows mempool statistics |
| `peers` | Lists connected peers |
| `banned` | Lists banned peers |
| `export-peer` | Writes this node's addresses to peer.txt |
| `mining` | Shows or controls mining (start, stop, threads) |
| `certify` | Checks chain integrity (difficulty, timestamps) |
| `save-checkpoints` | Writes checkpoints for known blocks to disk |
| `load-checkpoints` | Downloads or reloads checkpoints for faster sync |
| `purge` | Deletes all blockchain data (cannot be undone) |
| `version` | Shows the version |
| `about` | Shows information about this software |
| `license` | Shows the license |
| `quit` | Exits attach (the core keeps running) |
| `help <command>` | Shows detailed help for a command |

#### Short names
| Short name | Command |
|---|---|
| `bal`, `b` | `balance` |
| `addr`, `a` | `address` |
| `hist`, `h` | `history` |
| `outs`, `out` | `outputs` |
| `scan` | `sync` |
| `exp` | `explore` |
| `exit`, `q` | `quit` |
| `?` | `help` |

#### Locked wallet

While the wallet is locked, only the commands that need the wallet are refused with "Wallet is locked, use 'unlock' first": `balance`, `address`, `send`, `sign`, `history`, `outputs`, `seed`, `viewkeys`, `prove`, `audit` and `sync`. Node commands (`status`, `peers`, `explore` and the rest), `load`, `unload`, `lock`, `unlock`, `import`, `verify` and `purge` still work. When you attach to a core whose wallet is locked, the welcome screen shows `Wallet:  locked (use 'unlock')`.

---

### Detailed Command Reference

---

#### `load`

Loads a wallet file into the running core, or creates a new one. See the [Wallet Management](reference-wallet.md) guide for the full story on loading, backups, the saved wallet path, and recovery.

**Use this when:**
you just started the core and need to open your wallet.

**Example: loading an existing wallet:**
```
> load

# Load Wallet

  Wallet files in /home/username/.config/bnt/wallets:
  1) main.wallet.dat
  2) Enter a custom path
  3) Create a new wallet

  Choose: 1
  Password: ********

# Wallet Loaded

  Address: 9PNo...
```

**Example: creating a new wallet:**
```
> load
  ...
  3) Create a new wallet

  Choose: 3
  Wallet name (without extension):

> savings
  Password: ********
  Confirm password: ********

# Wallet Created

  Address:  9PNo...
  Filename: savings.wallet.dat
```

**Notes:**
- The core only loads wallet files from its own wallet folder (the folder of [`wallet_file`](reference-config.md#paths), by default `~/.config/bnt/wallets/`). A custom path in another folder is refused: copy the file into the wallet folder, then run `load` again.
- A new wallet asks for its password twice.
- The chosen wallet is saved to config as `wallet_file`, but the core does not open it at startup: run `load` after each start. See [Saved wallet path](reference-wallet.md#saved-wallet-path).
- Only one wallet can be loaded per core session. Use [`unload`](#unload) to switch wallets, then `load` again.

---

#### `unload`

Unloads the current wallet from the core. The core returns to the same state as before `load` was called: wallet commands return an error until a wallet is loaded again.

**Use this when:**
you want to switch wallets without restarting the core.

**Example:**
```
> unload

# Unloaded

  Wallet unloaded. Use 'load' to open another
```

**Notes:**
- Works even if the wallet is locked.
- After unloading, use [`load`](#load) to open a different wallet.

---

#### `balance`

**Short names:** `bal`, `b`

Shows your spendable, pending and total balance.

**Use this when:**
you want to know how much you can spend right now.

**Example:**
```
> bal

# Balance

  Spendable:   12.5 BNT
  Pending:     1 BNT
  Total:       13.5 BNT
  Outputs:     4 unspent, 2 spent
```

**Notes:**
- Pending coins are in a block but not yet spendable.
- Unconfirmed coins are still in the mempool (shown only when there are some).

---

#### `address`

**Short names:** `addr`, `a`

Shows your receive address to share with someone paying you.

**Use this when:**
someone asks where to send you coins.

**Example:**
```
> addr

# Address

  9PNo...

  Get a short name like @name or $name at https://blocknet.id
```

For a view-only wallet, a line `This wallet is view-only (watches incoming funds, cannot spend)` follows the address.

---

#### `send`

```
send <addr> <amt> [memo|hex:<memo_hex>]
send <addr> all [memo|hex:<memo_hex>]
```

Sends BNT to another wallet, optionally with a memo.

**Use this when:**
you need to pay someone now.

**Example input:**
```
> send @rock 100 "hello"
> send $rock 100
> send 9PNo... 1.25
> send 9PNo... 1 BNT
> send 9PNo... all
```

**Example output:**
```
# Send

  Resolved @rock -> 9PNo... ✓ verified

  Send 100 BNT to @rock?
  Fee:      0.0001 BNT
  Address:  9PNo...
  Memo:     hello
  Confirm [y/N]: y
  Sent:     9f0b...
  Explorer: https://explorer.blocknetcrypto.com/tx/9f0b...
```

**Notes:**
- Amounts can be whole numbers or fractions, up to 8 decimal places (example: `1` or `1.25`). A `BNT` after the amount is allowed (`send <addr> 1 BNT`). Zero, negative amounts and more than 8 decimal places are refused.
- Memos with spaces are supported.
- Short names can be used as `@name` or `$name`.
- `send <addr> all` sends your whole spendable balance minus the fee.
- A `bntpay.com` or `blocknet:` payment link can be pasted as a command.

---

#### `sign`

Signs a message so you can prove wallet ownership.

**Use this when:**
a service asks you to prove this wallet is yours.

**Example:**
```
> sign

# Sign

  Enter the text to sign, then press Enter

> prove wallet ownership

  8f2d... (signature hex)
```

**Notes:**
- View-only wallets cannot sign.
- The message can be up to 1024 bytes.

---

#### `verify`

Checks whether a signature really came from an address.

**Use this when:**
you received a signed message and need to trust it.

**Example:**
```
> verify

# Verify

  Enter the address:

> 9PNo...
  Enter the message that was signed:

> prove wallet ownership
  Enter the signature (hex):

> 8f2d...

# Signature is VALID
```

**Notes:**
- Paste the signature exactly as `sign` printed it.

---

#### `history`

**Short names:** `hist`, `h`

Shows incoming and outgoing transactions, oldest to newest.

**Use this when:**
you need to review recent wallet activity.

**Example:**
```
> hist

# History

  block 14200  IN   72.325 BNT  c7f2e1d3...  coinbase
  block 14251  OUT      10 BNT  9f0b4a11...
  mempool      OUT     2.5 BNT  51aa09c2...
```

**Notes:**
- Sends still in the mempool are listed last.

---

#### `outputs`

**Short names:** `outs`, `out`

```
outputs [spent|unspent|pending] [index]
outputs tx <txid>[:<index>]
```

Shows the outputs your wallet owns, with status and details.

**Use this when:**
you want to inspect spendable, spent or pending outputs.

**Example input:**
```
> outputs
> outputs unspent
> outputs pending 2
> outputs tx a1b2c3...d4e5:0
```

**Example output:**
```
# Outputs

  #1  unspent  coinbase  Confirmations: 120
      Amount: 72.325 BNT
      Block:  14200  Tx: c7f2e1d3...:0
```

**Notes:**
- Filters: `spent`, `unspent`, `pending`.
- An index shows one output's details (example: `outputs 3`).
- `outputs tx <txid>` shows every owned output in that transaction.

---

#### `seed`

Shows your 12-word recovery seed after a warning. See [Viewing your recovery seed](reference-wallet.md#viewing-your-recovery-seed) for important security guidance.

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

   1.abandon     2.ability     3.able        4.about
   5.above       6.absent      7.absorb      8.abstract
   9.absurd     10.abuse      11.access     12.accident

  Write these words down and store them safely
  Recover with: import (option 1: recovery seed)
```

**Notes:**
- Anyone with this seed can spend your funds.

---

#### `import`

Creates a new wallet file from a 12-word recovery seed, from spend and view private keys, or as view-only from a spend public key and view private key. See [Recovery from seed](reference-wallet.md#recovery-from-seed) for the full recovery workflow.

**Use this when:**
you need to load an existing wallet into this node.

**Example:**
```
> import

# Import

  1) 12-word recovery seed
  2) Spend key and view key (hex private keys)
  3) View-only (spend public key and view private key)

  Choose [1/2/3]: 1
  Input the 12 words of your seed:

> abandon ability able about above absent absorb abstract absurd abuse access accident
  Input the name of this wallet:

> restored
  Password: ********
  Confirm password: ********

# Wallet Imported

  Name:    restored.wallet.dat
  Address: 9PNo...
```

**Notes:**
- Private keys are read without echo.
- A view-only wallet watches incoming funds and cannot spend.
- The new wallet's password is asked twice.

---

#### `viewkeys`

Shows your view keys and saves a view-only wallet file.

**Use this when:**
you want watch-only access on another machine.

**Example:**
```
> viewkeys

# View Keys

  WARNING: Your view private key lets anyone see all incoming funds.
  Never share it unless you understand the implications.

  This shows your view keys and saves a wallet file that is
  view-only (watches incoming funds, cannot spend)

  Continue? [y/N]: y
  Wallet password: ********
  New password for the view-only wallet file: ********
  Confirm password: ********

  Spend Public Key: abc123...
  View Private Key: def456...
  View Public Key:  789abc...
  Saved To:         /home/username/.config/bnt/wallets/main.view.wallet.dat
```

**Notes:**
- The view-only wallet file uses its own password, not your main wallet password.
- The view private key lets anyone see all incoming funds.

---

#### `prove`

```
prove <txid>
```

Shows a key that proves you sent a transaction.

**Use this when:**
someone needs proof of payment.

**Example:**
```
> prove a1b2c3d4e5f6...

# Prove

  TxID:   a1b2c3d4e5f6...
  Tx Key: deadbeef0123...

  Share this tx key with the recipient so they can verify you sent the transaction
```

**Notes:**
- Works on both full and view-only wallets.
- Share the tx key with the recipient to prove payment.

---

#### `audit`

Scans wallet outputs for duplicate key images (burned funds).

**Use this when:**
you suspect a key derivation issue burned some outputs.

**Example:**
```
> audit

# Audit

  Scanning wallet outputs for duplicate key images...
  Total Outputs:     42
  Unique Key Images: 42

  ✓ No duplicate key images found. Wallet is clean
```

**Notes:**
- A clean audit means no burned funds.
- Duplicates are permanently unspendable outputs from a historical self-send bug.

---

#### `lock`

Locks the wallet so wallet commands need the password again. See [Locking and unlocking](reference-wallet.md#locking-and-unlocking).

**Use this when:**
you are stepping away from your terminal.

**Example:**
```
> lock

# Locked
```

**Notes:**
- Node commands such as `status`, `peers` and `explore` still work while locked. See [Locked wallet](#locked-wallet).

---

#### `unlock`

Unlocks the wallet after checking your password.

**Use this when:**
you get a "wallet is locked" error.

**Example:**
```
> unlock
  Password: ********

# Unlocked
```

---

#### `sync`

**Short names:** `scan`

Rescans the blockchain for wallet outputs. This is not peer-to-peer sync: it scans blocks that are already downloaded, looking for outputs that belong to your wallet.

**Use this when:**
the wallet looks behind the chain or is missing transactions. See [Sync is slow or stuck](troubleshooting.md#sync-is-slow-or-stuck) if the scanner isn't catching up.

**Example:**
```
> sync

# Sync

  Scanning for wallet outputs...
  Scanned 120 blocks to height 14320
  Outputs found: 2
```

**Example: already up to date:**
```
> sync

# Sync

  Scanning for wallet outputs...
  Wallet is up to date at height 14320
```

---

#### `status`

Shows node health and a wallet summary on one screen.

**Use this when:**
you need a quick "is everything healthy?" check.

**Example:**
```
> status

# Node

  Peer ID:     12D3KooW...
  Peers:       8
  Height:      2450
  Best Hash:   0000c3a5...
  Syncing:     no

# Wallet

  Type:        full
  Balance:     13.5 BNT
```

**Notes:**
- The wallet section is left out when no wallet is loaded or it is locked.

---

#### `peers`

Lists connected peers and their addresses.

**Use this when:**
you need to confirm network connectivity.

**Example:**
```
> peers

# Peers (8)

  12D3KooW...
    /ip4/203.0.113.5/tcp/28080
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

  12D3KooW...
    Reason: repeated bad blocks
    Count:  3x, expires in 1h 5m
```

---

#### `export-peer`

Writes this node's own addresses, including its public IP address, to `peer.txt` in the config folder (`~/.config/bnt/peer.txt`). The public IP address is found through api.ipify.org, ifconfig.me or icanhazip.com.

**Use this when:**
you want other nodes to connect to this node.

**Example:**
```
> export-peer

# Export

  Peer addresses written to /home/username/.config/bnt/peer.txt
  Share this file or its contents with other nodes

  Other nodes can connect with:
    /ip4/203.0.113.7/tcp/28080/p2p/12D3KooW...
    /ip4/192.168.1.20/tcp/28080/p2p/12D3KooW...
```

---

#### `mining`

```
mining
mining start
mining stop
mining threads [N]
```

Shows or controls local mining and how many CPU threads it uses.

**Use this when:**
you want to mine, stop mining, or tune CPU and RAM use.

**Example input:**
```
> mining start
> mining threads 4
> mining stop
```

**Example output (`mining`):**
```
# Mining

  Status:       active
  Running For:  12m
  Threads:      4
  Hashrate:     310.52 H/s
  Total Hashes: 223574
```

**Notes:**
- Roughly 2GB RAM per thread.
- Thread aliases: `threads`, `thread`, `t`.

---

#### `explore`

**Short names:** `exp`

```
explore <height>
explore <hash>
explore mempool
```

Looks up a block by height, a block or transaction by hash, or shows mempool stats.

**Use this when:**
you want to inspect chain data without leaving the terminal.

**Example input:**
```
> explore 14207
> explore 0000c3a5b7e2d1f4...50321
> explore mempool
```

**Example output:**
```
# Block 14207

  Hash:          0000c3a5...
  Previous:      0000a1f2...
  Confirmations: 12
```

**Notes:**
- A 64-char hex hash is tried as a block hash first, then as a tx hash.
- A number is always read as a block height.
- `explore mempool` is the same as the [`mempool`](#mempool) command.

---

#### `mempool`

Shows mempool statistics and pending transactions.

**Use this when:**
you want to see what is waiting to be mined.

**Example:**
```
> mempool

# Mempool

  Transactions: 5
  Size:         8.2 KB
  Fee (min):    0.0001 BNT
```

**Notes:**
- Shortcut for `explore mempool`.
- Shows up to 25 pending transactions.
- When the mempool is empty, prints "Empty: no pending transactions".

---

#### `certify`

Checks chain integrity (difficulty, timestamps, block linkage).

**Use this when:**
you suspect corruption or strange chain behavior.

**Example:**
```
> certify

# Certify

  Verifying chain integrity (difficulty, timestamps, linkage)...
  Chain Height: 125000
  ✓ Chain is clean. No violations found
```

**Notes:**
- Arithmetic-only check, no PoW re-hashing.
- May take a moment on long chains.

---

#### `save-checkpoints`

Writes checkpoints for known blocks to disk (every 100 blocks).

**Use this when:**
you want to publish checkpoints so nodes can fast-sync.

**Example:**
```
> save-checkpoints

# Save Checkpoints

  Wrote 3 checkpoints up to height 14200
```

**Notes:**
- Checkpoints let nodes skip proof-of-work re-verification below the checkpoint height.

---

#### `load-checkpoints`

Downloads or reloads checkpoints to enable faster sync.

**Use this when:**
you are syncing a fresh node and want to skip PoW re-verification.

**Example:**
```
> load-checkpoints

# Load Checkpoints

  Loaded 142 checkpoints (max height: 14200)
```

**Notes:**
- Only speeds up sync below the max checkpoint height.

---

#### `purge`

Deletes local chain data but keeps your wallet and funds.

**Use this when:**
the chain is stuck or corrupted and sync cannot recover.

**Example:**
```
> purge

# Purge

  This will delete all blockchain data
  Your wallet will NOT be deleted
  This action CANNOT be undone

  Confirm purge? [y/N]: y
  Password: ********
  Blockchain data purged. The core will shut down
```

**Notes:**
- Your wallet file and money are not deleted.
- Asks for your wallet password.
- Attach exits afterwards.

---

#### `version`

Shows the Blocknet version.

**Use this when:**
you are reporting bugs or checking for updates.

**Example:**
```
> version

# blocknet v1.1.0
```

---

#### `about`

Shows project info, links and third-party libraries.

**Example:**
```
> about

# About

  Blocknet v1.1.0
  Zero-knowledge money. Made in USA.

  BSD 3-Clause License
  Copyright (c) 2026, Blocknet Privacy

  https://blocknetcrypto.com
  https://explorer.blocknetcrypto.com
  https://github.com/blocknetprivacy

# Third-Party Libraries
  ...
```

---

#### `license`

Shows the full software license text.

**Example:**
```
> license

# License

  BSD 3-Clause License
  ...
```

---

#### `quit`

**Short names:** `exit`, `q`

Exits attach. The core keeps running. Quitting saves nothing and needs nothing saved: the core keeps the wallet on disk itself. Ctrl-D also exits.

**Notes:**
- To stop the core, run `blocknet stop` after quitting.
