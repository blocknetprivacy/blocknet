package main

import (
	"fmt"
	"strings"
)

type helpEntry struct {
	usage         []string
	aliases       []string
	description   []string
	useWhen       []string
	exampleInput  []string
	exampleOutput []string
	notes         []string
}

func normalizeHelpTopic(topic string) string {
	switch strings.ToLower(topic) {
	case "load":
		return "load"
	case "unload":
		return "unload"
	case "help", "?":
		return "help"
	case "balance", "bal", "b":
		return "balance"
	case "address", "addr", "a":
		return "address"
	case "send":
		return "send"
	case "sign":
		return "sign"
	case "verify":
		return "verify"
	case "history", "hist", "h":
		return "history"
	case "outputs", "outs", "out":
		return "outputs"
	case "seed":
		return "seed"
	case "import":
		return "import"
	case "viewkeys":
		return "viewkeys"
	case "lock":
		return "lock"
	case "unlock":
		return "unlock"
	case "sync", "scan":
		return "sync"
	case "status":
		return "status"
	case "peers":
		return "peers"
	case "banned":
		return "banned"
	case "export-peer":
		return "export-peer"
	case "mining":
		return "mining"
	case "certify":
		return "certify"
	case "save-checkpoints":
		return "save-checkpoints"
	case "load-checkpoints":
		return "load-checkpoints"
	case "purge":
		return "purge"
	case "prove":
		return "prove"
	case "audit":
		return "audit"
	case "explore", "exp":
		return "explore"
	case "mempool":
		return "mempool"
	case "version":
		return "version"
	case "about":
		return "about"
	case "license":
		return "license"
	case "quit", "exit", "q":
		return "quit"
	default:
		return ""
	}
}

func helpCommandDetails() map[string]helpEntry {
	return map[string]helpEntry{
		"load": {
			usage:       []string{"load"},
			description: []string{"Loads a wallet file into the running core, or creates a new one."},
			useWhen:     []string{"you just started the core and need to open your wallet"},
			exampleInput: []string{
				"> load",
				"  Wallet files in /home/username/.config/bnt/wallets:",
				"  1) main.wallet.dat",
				"  2) Enter a custom path",
				"  3) Create a new wallet",
				"",
				"  Choose: 1",
				"  Password: ********",
			},
			exampleOutput: []string{"# Wallet Loaded", "", "  Address: 9PNo..."},
			notes: []string{
				"the core only loads wallet files from its own wallet folder",
				"a new wallet asks for its password twice",
				"the chosen wallet is saved to config as wallet_file, but the core does not open it at startup: run 'load' after each start",
			},
		},
		"unload": {
			usage:         []string{"unload"},
			description:   []string{"Unloads the current wallet from the core."},
			useWhen:       []string{"you want to switch wallets without restarting the core"},
			exampleInput:  []string{"> unload"},
			exampleOutput: []string{"# Unloaded", "", "  Wallet unloaded. Use 'load' to open another"},
			notes:         []string{"works even if the wallet is locked"},
		},
		"help": {
			usage:         []string{"help", "help <command>"},
			aliases:       []string{"?"},
			description:   []string{"Shows all commands, or detailed help for one command."},
			useWhen:       []string{"you are not sure what command to run next"},
			exampleInput:  []string{"> help send"},
			exampleOutput: []string{"# Help: send", "", "  Usage:", "    send <addr> <amt> [memo|hex:<memo_hex>]"},
		},
		"balance": {
			usage:         []string{"balance"},
			aliases:       []string{"bal", "b"},
			description:   []string{"Shows your spendable, pending and total balance."},
			useWhen:       []string{"you want to know how much you can spend right now"},
			exampleInput:  []string{"> bal"},
			exampleOutput: []string{"# Balance", "", "  Spendable:   12.5 BNT", "  Pending:     1 BNT", "  Total:       13.5 BNT", "  Outputs:     4 unspent, 2 spent"},
			notes: []string{
				"pending coins are in a block but not yet spendable",
				"unconfirmed coins are still in the mempool (shown only when there are some)",
			},
		},
		"address": {
			usage:         []string{"address"},
			aliases:       []string{"addr", "a"},
			description:   []string{"Shows your receive address to share with someone paying you."},
			useWhen:       []string{"someone asks where to send you coins"},
			exampleInput:  []string{"> addr"},
			exampleOutput: []string{"# Address", "", "  9PNo...", "", "  Get a short name like @name or $name at https://blocknet.id"},
		},
		"send": {
			usage:       []string{"send <addr> <amt> [memo|hex:<memo_hex>]", "send <addr> all [memo|hex:<memo_hex>]"},
			description: []string{"Sends BNT to another wallet, optionally with a memo."},
			useWhen:     []string{"you need to pay someone now"},
			exampleInput: []string{
				"> send @rock 100 \"hello\"",
				"> send $rock 100",
				"> send 9PNo... 1.25",
				"> send 9PNo... all",
			},
			exampleOutput: []string{
				"# Send",
				"",
				"  Resolved @rock -> 9PNo... ✓ verified",
				"",
				"  Send 100 BNT to @rock?",
				"  Fee:      0.0001 BNT",
				"  Address:  9PNo...",
				"  Memo:     hello",
				"  Confirm [y/N]: y",
				"  Sent:     9f0b...",
				"  Explorer: https://explorer.blocknetcrypto.com/tx/9f0b...",
			},
			notes: []string{
				"amounts can be whole numbers or fractions, up to 8 decimal places (example: 1 or 1.25)",
				"memos with spaces are supported",
				"short names can be used as @name or $name",
				"'send <addr> all' sends your whole spendable balance minus the fee",
				"a bntpay.com or blocknet: payment link can be pasted as a command",
			},
		},
		"sign": {
			usage:         []string{"sign"},
			description:   []string{"Signs a message so you can prove wallet ownership."},
			useWhen:       []string{"a service asks you to prove this wallet is yours"},
			exampleInput:  []string{"> sign", "> prove wallet ownership"},
			exampleOutput: []string{"  8f2d... (signature hex)"},
			notes:         []string{"view-only wallets cannot sign", "the message can be up to 1024 bytes"},
		},
		"verify": {
			usage:         []string{"verify"},
			description:   []string{"Checks whether a signature really came from an address."},
			useWhen:       []string{"you received a signed message and need to trust it"},
			exampleInput:  []string{"> verify", "  (then enter address, message, signature)"},
			exampleOutput: []string{"# Signature is VALID"},
			notes:         []string{"paste the signature exactly as sign printed it"},
		},
		"history": {
			usage:       []string{"history"},
			aliases:     []string{"hist", "h"},
			description: []string{"Shows incoming and outgoing transactions, oldest to newest."},
			useWhen:     []string{"you need to review recent wallet activity"},
			exampleInput: []string{
				"> hist",
			},
			exampleOutput: []string{
				"# History",
				"",
				"  block 14200  IN   72.325 BNT  c7f2e1d3...  coinbase",
				"  block 14251  OUT      10 BNT  9f0b4a11...",
				"  mempool      OUT     2.5 BNT  51aa09c2...",
			},
			notes: []string{"sends still in the mempool are listed last"},
		},
		"outputs": {
			usage:       []string{"outputs [spent|unspent|pending] [index]", "outputs tx <txid>[:<index>]"},
			aliases:     []string{"outs", "out"},
			description: []string{"Shows the outputs your wallet owns, with status and details."},
			useWhen:     []string{"you want to inspect spendable, spent or pending outputs"},
			exampleInput: []string{
				"> outputs",
				"> outputs unspent",
				"> outputs pending 2",
				"> outputs tx a1b2c3...d4e5:0",
			},
			exampleOutput: []string{
				"# Outputs",
				"",
				"  #1  unspent  coinbase  Confirmations: 120",
				"      Amount: 72.325 BNT",
				"      Block:  14200  Tx: c7f2e1d3...:0",
			},
			notes: []string{
				"filters: spent, unspent, pending",
				"an index shows one output's details (example: outputs 3)",
				"'outputs tx <txid>' shows every owned output in that transaction",
			},
		},
		"seed": {
			usage:         []string{"seed"},
			description:   []string{"Shows your 12-word recovery seed after a warning."},
			useWhen:       []string{"you are backing up wallet recovery words"},
			exampleInput:  []string{"> seed"},
			exampleOutput: []string{"# Seed", "", "  WARNING: Your recovery seed controls all funds.", "  Anyone with this seed can steal your coins.", "  Never share it. Never enter it online.", "", "  Show recovery seed? [y/N]:"},
			notes:         []string{"anyone with this seed can spend your funds"},
		},
		"import": {
			usage:         []string{"import"},
			description:   []string{"Creates a new wallet file from a 12-word recovery seed, from spend and view private keys, or as view-only from a spend public key and view private key."},
			useWhen:       []string{"you need to load an existing wallet into this node"},
			exampleInput:  []string{"> import", "  Choose [1/2/3]: 1"},
			exampleOutput: []string{"# Import", "", "  1) 12-word recovery seed", "  2) Spend key and view key (hex private keys)", "  3) View-only (spend public key and view private key)"},
			notes:         []string{"private keys are read without echo", "a view-only wallet watches incoming funds and cannot spend"},
		},
		"viewkeys": {
			usage:        []string{"viewkeys"},
			description:  []string{"Shows your view keys and saves a view-only wallet file."},
			useWhen:      []string{"you want watch-only access on another machine"},
			exampleInput: []string{"> viewkeys", "  Continue? [y/N]: y", "  Wallet password: ", "  New password for the view-only wallet file: ", "  Confirm password: "},
			exampleOutput: []string{
				"  Spend Public Key: abc123...",
				"  View Private Key: def456...",
				"  View Public Key:  789abc...",
				"  Saved To:         /home/username/.config/bnt/wallets/main.view.wallet.dat",
			},
			notes: []string{"the view-only wallet file uses its own password, not your main wallet password", "the view private key lets anyone see all incoming funds"},
		},
		"prove": {
			usage:         []string{"prove <txid>"},
			description:   []string{"Shows a key that proves you sent a transaction."},
			useWhen:       []string{"someone needs proof of payment"},
			exampleInput:  []string{"> prove a1b2c3d4e5f6..."},
			exampleOutput: []string{"# Prove", "", "  TxID:   a1b2c3d4e5f6...", "  Tx Key: deadbeef0123..."},
			notes:         []string{"works on both full and view-only wallets", "share the tx key with the recipient to prove payment"},
		},
		"audit": {
			usage:         []string{"audit"},
			description:   []string{"Scans wallet outputs for duplicate key images (burned funds)."},
			useWhen:       []string{"you suspect a key derivation issue burned some outputs"},
			exampleInput:  []string{"> audit"},
			exampleOutput: []string{"# Audit", "", "  Scanning wallet outputs for duplicate key images...", "  Total Outputs:     42", "  Unique Key Images: 42", "", "  ✓ No duplicate key images found. Wallet is clean"},
			notes:         []string{"a clean audit means no burned funds", "duplicates are permanently unspendable outputs from a historical self-send bug"},
		},
		"lock": {
			usage:         []string{"lock"},
			description:   []string{"Locks the wallet so wallet commands need the password again."},
			useWhen:       []string{"you are stepping away from your terminal"},
			exampleInput:  []string{"> lock"},
			exampleOutput: []string{"# Locked"},
			notes:         []string{"node commands such as status, peers and explore still work while locked"},
		},
		"unlock": {
			usage:         []string{"unlock"},
			description:   []string{"Unlocks the wallet after checking your password."},
			useWhen:       []string{"you get a 'wallet is locked' error"},
			exampleInput:  []string{"> unlock", "  Password: ********"},
			exampleOutput: []string{"# Unlocked"},
		},
		"sync": {
			usage:         []string{"sync"},
			aliases:       []string{"scan"},
			description:   []string{"Rescans the blockchain for wallet outputs."},
			useWhen:       []string{"the wallet looks behind the chain or is missing transactions"},
			exampleInput:  []string{"> sync"},
			exampleOutput: []string{"# Sync", "", "  Scanning for wallet outputs...", "  Scanned 120 blocks to height 14320", "  Outputs found: 2"},
		},
		"status": {
			usage:       []string{"status"},
			description: []string{"Shows node health and a wallet summary on one screen."},
			useWhen:     []string{"you need a quick 'is everything healthy?' check"},
			exampleInput: []string{
				"> status",
			},
			exampleOutput: []string{
				"# Node",
				"",
				"  Peer ID:     12D3KooW...",
				"  Peers:       8",
				"  Height:      2450",
				"  Best Hash:   0000c3a5...",
				"  Syncing:     no",
				"",
				"# Wallet",
				"",
				"  Type:        full",
				"  Balance:     13.5 BNT",
			},
			notes: []string{"the wallet section is left out when no wallet is loaded or it is locked"},
		},
		"peers": {
			usage:         []string{"peers"},
			description:   []string{"Lists connected peers and their addresses."},
			useWhen:       []string{"you need to confirm network connectivity"},
			exampleInput:  []string{"> peers"},
			exampleOutput: []string{"# Peers (8)", "", "  12D3KooW...", "    /ip4/203.0.113.5/tcp/28080"},
		},
		"banned": {
			usage:         []string{"banned"},
			description:   []string{"Shows peers that were banned and why."},
			useWhen:       []string{"you suspect peer filtering or connectivity issues"},
			exampleInput:  []string{"> banned"},
			exampleOutput: []string{"# Banned (1)", "", "  12D3KooW...", "    Reason: repeated bad blocks", "    Count:  3x, expires in 1h 5m"},
		},
		"export-peer": {
			usage:         []string{"export-peer"},
			description:   []string{"Writes this node's own addresses, including its public IP address, to peer.txt in the config folder."},
			useWhen:       []string{"you want other nodes to connect to this node"},
			exampleInput:  []string{"> export-peer"},
			exampleOutput: []string{"# Export", "", "  Peer addresses written to /home/username/.config/bnt/peer.txt"},
		},
		"mining": {
			usage:       []string{"mining", "mining start", "mining stop", "mining threads [N]"},
			description: []string{"Shows or controls local mining and how many CPU threads it uses."},
			useWhen:     []string{"you want to mine, stop mining, or tune CPU and RAM use"},
			exampleInput: []string{
				"> mining start",
				"> mining threads 4",
				"> mining stop",
			},
			exampleOutput: []string{"# Mining", "", "  Status:       active", "  Running For:  12m", "  Threads:      4", "  Hashrate:     310.52 H/s", "  Total Hashes: 223574"},
			notes: []string{
				"roughly 2GB RAM per thread",
				"thread aliases: threads, thread, t",
			},
		},
		"explore": {
			usage:       []string{"explore <height>", "explore <hash>", "explore mempool"},
			aliases:     []string{"exp"},
			description: []string{"Looks up a block by height, a block or transaction by hash, or shows mempool stats."},
			useWhen:     []string{"you want to inspect chain data without leaving the terminal"},
			exampleInput: []string{
				"> explore 14207",
				"> explore 0000c3a5b7e2d1f4...50321",
				"> explore mempool",
			},
			exampleOutput: []string{"# Block 14207", "", "  Hash:          0000c3a5...", "  Previous:      0000a1f2...", "  Confirmations: 12"},
			notes: []string{
				"a 64-char hex hash is tried as a block hash first, then as a tx hash",
				"a number is always read as a block height",
			},
		},
		"mempool": {
			usage:         []string{"mempool"},
			description:   []string{"Shows mempool statistics and pending transactions."},
			useWhen:       []string{"you want to see what is waiting to be mined"},
			exampleInput:  []string{"> mempool"},
			exampleOutput: []string{"# Mempool", "", "  Transactions: 5", "  Size:         8.2 KB", "  Fee (min):    0.0001 BNT"},
			notes:         []string{"shortcut for 'explore mempool'"},
		},
		"certify": {
			usage:         []string{"certify"},
			description:   []string{"Checks chain integrity (difficulty, timestamps, block linkage)."},
			useWhen:       []string{"you suspect corruption or strange chain behavior"},
			exampleInput:  []string{"> certify"},
			exampleOutput: []string{"# Certify", "", "  Verifying chain integrity (difficulty, timestamps, linkage)...", "  Chain Height: 125000", "  ✓ Chain is clean. No violations found"},
			notes:         []string{"arithmetic-only check, no PoW re-hashing", "may take a moment on long chains"},
		},
		"save-checkpoints": {
			usage:         []string{"save-checkpoints"},
			description:   []string{"Writes checkpoints for known blocks to disk (every 100 blocks)."},
			useWhen:       []string{"you want to publish checkpoints so nodes can fast-sync"},
			exampleInput:  []string{"> save-checkpoints"},
			exampleOutput: []string{"# Save Checkpoints", "", "  Wrote 3 checkpoints up to height 14200"},
			notes:         []string{"checkpoints let nodes skip proof-of-work re-verification below the checkpoint height"},
		},
		"load-checkpoints": {
			usage:         []string{"load-checkpoints"},
			description:   []string{"Downloads or reloads checkpoints to enable faster sync."},
			useWhen:       []string{"you are syncing a fresh node and want to skip PoW re-verification"},
			exampleInput:  []string{"> load-checkpoints"},
			exampleOutput: []string{"# Load Checkpoints", "", "  Loaded 142 checkpoints (max height: 14200)"},
			notes:         []string{"only speeds up sync below the max checkpoint height"},
		},
		"purge": {
			usage:         []string{"purge"},
			description:   []string{"Deletes local chain data but keeps your wallet and funds."},
			useWhen:       []string{"the chain is stuck or corrupted and sync cannot recover"},
			exampleInput:  []string{"> purge", "  Confirm purge? [y/N]: y", "  Password: ********"},
			exampleOutput: []string{"  Blockchain data purged. The core will shut down"},
			notes:         []string{"your wallet file and money are not deleted", "asks for your wallet password", "attach exits afterwards"},
		},
		"version": {
			usage:         []string{"version"},
			description:   []string{"Shows the Blocknet version."},
			useWhen:       []string{"you are reporting bugs or checking for updates"},
			exampleInput:  []string{"> version"},
			exampleOutput: []string{"# blocknet v1.2.1"},
		},
		"about": {
			usage:         []string{"about"},
			description:   []string{"Shows project info, links and third-party libraries."},
			useWhen:       []string{"you want project details"},
			exampleInput:  []string{"> about"},
			exampleOutput: []string{"# About", "", "  Blocknet v1.2.1"},
		},
		"license": {
			usage:         []string{"license"},
			description:   []string{"Shows the full software license text."},
			useWhen:       []string{"you need license details"},
			exampleInput:  []string{"> license"},
			exampleOutput: []string{"# License", "", "  BSD 3-Clause License"},
		},
		"quit": {
			usage:        []string{"quit"},
			aliases:      []string{"exit", "q"},
			description:  []string{"Exits attach. The core keeps running."},
			useWhen:      []string{"you are done"},
			exampleInput: []string{"> q"},
			notes:        []string{"to stop the core, run 'blocknet stop' after quitting"},
		},
	}
}

// helpRow is one line of the command overview.
type helpRow struct{ cmd, desc string }

var helpWalletRows = []helpRow{
	{"load", "Loads a wallet file into the core, or creates one"},
	{"unload", "Unloads the current wallet"},
	{"balance", "Shows the wallet balance"},
	{"address", "Shows the receive address"},
	{"send <addr> <amt> [memo]", "Sends BNT, with an optional memo"},
	{"send <addr> all [memo]", "Sends the whole spendable balance"},
	{"sign", "Signs a message with your spend key"},
	{"verify", "Checks a signed message against an address"},
	{"history", "Shows incoming and outgoing transactions"},
	{"outputs", "Shows wallet outputs (spent, unspent, pending)"},
	{"seed", "Shows the recovery seed (careful)"},
	{"import", "Creates a wallet from a seed, keys or view keys"},
	{"viewkeys", "Shows view keys and saves a view-only wallet"},
	{"lock", "Locks the wallet"},
	{"unlock", "Unlocks the wallet"},
	{"prove <txid>", "Shows a payment proof for a transaction"},
	{"audit", "Checks the wallet for burned outputs"},
	{"sync", "Rescans blocks for wallet outputs"},
}

var helpDaemonRows = []helpRow{
	{"status", "Shows node and wallet status"},
	{"explore <id>", "Looks up a block, a transaction or the mempool"},
	{"mempool", "Shows mempool statistics"},
	{"peers", "Lists connected peers"},
	{"banned", "Lists banned peers"},
	{"export-peer", "Writes this node's addresses to peer.txt"},
	{"mining", "Shows or controls mining (start, stop, threads)"},
	{"certify", "Checks chain integrity (difficulty, timestamps)"},
	{"save-checkpoints", "Writes checkpoints for known blocks to disk"},
	{"load-checkpoints", "Downloads or reloads checkpoints for faster sync"},
	{"purge", "Deletes all blockchain data (cannot be undone)"},
	{"version", "Shows the version"},
	{"about", "Shows information about this software"},
	{"license", "Shows the license"},
	{"quit", "Exits attach (the core keeps running)"},
}

var helpAliasRows = []helpRow{
	{"bal, b", "balance"},
	{"addr, a", "address"},
	{"hist, h", "history"},
	{"outs, out", "outputs"},
	{"scan", "sync"},
	{"exp", "explore"},
	{"exit, q", "quit"},
	{"?", "help"},
}

func (s *AttachSession) cmdHelp(args []string) error {
	green, _, _, _, _, reset := Palette(s.noColor)

	if len(args) > 0 {
		if err := ExtraArgs(args, 1, "help [command]"); err != nil {
			return err
		}
		topic := normalizeHelpTopic(args[0])
		entry, ok := helpCommandDetails()[topic]
		if topic == "" || !ok {
			return fmt.Errorf("unknown command: %s (type 'help' for commands)", args[0])
		}

		section := func(label string, lines []string, bullet bool) {
			if len(lines) == 0 {
				return
			}
			fmt.Printf("\n  %s%s%s:\n", green, label, reset)
			for _, line := range lines {
				switch {
				case line == "":
					fmt.Println()
				case bullet:
					fmt.Printf("    %s-%s %s\n", green, reset, line)
				default:
					fmt.Printf("    %s\n", line)
				}
			}
		}

		fmt.Printf("\n%s\n", SectionHead("Help: "+topic, s.noColor))
		section("Usage", entry.usage, false)
		if len(entry.aliases) > 0 {
			section("Short names", []string{strings.Join(entry.aliases, ", ")}, false)
		}
		section("What it does", entry.description, false)
		section("Use this when", entry.useWhen, false)
		section("Example input", entry.exampleInput, false)
		section("Example output", entry.exampleOutput, false)
		section("Notes", entry.notes, true)
		return nil
	}

	width := 0
	for _, rows := range [][]helpRow{helpWalletRows, helpDaemonRows, helpAliasRows} {
		for _, r := range rows {
			width = max(width, len(r.cmd))
		}
	}
	printRows := func(head string, rows []helpRow) {
		fmt.Printf("\n%s\n\n", SectionHead(head, s.noColor))
		for _, r := range rows {
			fmt.Printf("  %s  %s\n", PadRight(r.cmd, width), r.desc)
		}
	}
	printRows("Wallet", helpWalletRows)
	printRows("Daemon", helpDaemonRows)
	printRows("Short Names", helpAliasRows)
	fmt.Println()
	fmt.Println("  Type 'help <command>' for details. Example: help send")
	return nil
}
