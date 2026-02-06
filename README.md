# blocknet

Private digital currency. Stealth addresses, ring signatures, confidential transactions.

## specs

| | |
|---|---|
| algorithm | Argon2id (2GB) |
| block time | 5 min |
| supply | ~10M + 0.2/block tail |
| ring size | 16 (fixed) |
| addresses | stealth (dual-key) |
| amounts | Pedersen + Bulletproofs |
| signatures | CLSAG |
| hashing | SHA3-256 |

## build

Requires Go 1.22+ and Rust 1.75+.

### linux

```
sudo apt install build-essential
cd crypto-rs && cargo build --release
sudo cp target/release/libblocknet_crypto.so /usr/local/lib/
sudo ldconfig
cd .. && CGO_ENABLED=1 go build -o blocknet .
```

### macos

```
xcode-select --install
cd crypto-rs && cargo build --release
sudo cp target/release/libblocknet_crypto.dylib /usr/local/lib/
cd .. && CGO_ENABLED=1 go build -o blocknet .
```

### windows (msys2)

Install MSYS2 from https://www.msys2.org/, then in MINGW64 shell:

```
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-rust mingw-w64-x86_64-go
cd crypto-rs && cargo build --release
cd .. && CGO_ENABLED=1 go build -o blocknet.exe .
```

Place `blocknet_crypto.dll` from `crypto-rs/target/release/` alongside `blocknet.exe`.

## run

```
./blocknet
```

Commands:

```
status          node status
balance         wallet balance
address         receive address
send <addr> <n> send coins
mining start    start mining
mining stop     stop mining
seed            show recovery phrase
peers           list connected peers
help            list all commands
```

Flags:

```
--wallet <path>   wallet file (default: wallet.dat)
--data <path>     data directory (default: ./data)
--listen <addr>   p2p listen address (default: /ip4/0.0.0.0/tcp/28080)
--seed            run as seed node (persistent identity)
--daemon          headless mode (no interactive shell)
--recover         recover wallet from mnemonic
--viewonly        create view-only wallet
```

## privacy

Ring signatures with 16 decoys make the true sender indistinguishable.

One-time stealth addresses prevent linking transactions to recipients.

Pedersen commitments hide values. Bulletproofs prove validity without revealing amounts.

Dandelion++ obscures transaction origin on the network layer.

## license

BSD 3-Clause. See LICENSE.

