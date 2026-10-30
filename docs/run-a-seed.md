# Run a Seed Node

A seed node is the first node that a new Blocknet node connects to. New nodes ask seeds for other peers, then sync the chain. Seeds need a fixed address and a fixed identity, so new nodes can find them and check that they are the right node.

## What you need

- A server with a static public IPv4 address.
- A hostname with an A record that points to that address, for example `seed.example.com`. Nodes reach seeds over IPv4.
- Inbound TCP ports **28080** (P2P) and **28081** (peer ID) open in your firewall.
- Enough upload bandwidth. A busy seed can send several MB/s.

## Set it up

1. In `~/.config/bnt/config.json`, set `"seed": true` under `cores.mainnet`:

   ```json
   {
     "cores": {
       "mainnet": {
         "enabled": true,
         "version": "latest",
         "seed": true
       }
     }
   }
   ```

   Leave `listen` empty. The default, `/ip4/0.0.0.0/tcp/28080`, is correct. The peer ID port is always the P2P port plus 1, and nodes look for seeds only on 28080 and 28081.

2. Restart the core:

   ```sh
   blocknet restart mainnet
   ```

3. Check the peer ID port from another machine:

   ```sh
   curl http://seed.example.com:28081/
   ```

   It must print your peer ID, which starts with `12D3KooW`.

## Back up your identity key

In seed mode, the core creates an identity key the first time it starts and never changes it. Your peer ID comes from this key.

| System | Key file |
|---|---|
| Linux | `~/.config/blocknet/mainnet/identity.key` |
| macOS | `~/Library/Application Support/blocknet/mainnet/identity.key` |
| Windows | `%AppData%\blocknet\mainnet\identity.key` |

Keep a copy somewhere safe. From core v0.23.0, nodes only use a seed whose peer ID matches the one built into the core. If you lose the key, your seed stops being used until a new release has your new peer ID.

## Get listed

Send the maintainers:

- your hostname
- your public IPv4 address
- your peer ID

They add your seed to the core's seed list. Nodes start to use it after they upgrade to that release.

## Keep it current

Keep `version` set to `latest` so the seed upgrades itself. A seed on an old version can slow down new nodes.

## Testnet

A testnet seed uses ports **38080** and **38081**. It has its own identity key in the `testnet` folder next to the mainnet one.
