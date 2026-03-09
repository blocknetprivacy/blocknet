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
	case "save":
		return "save"
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

func helpCommandDetails(noColor bool) map[string]helpEntry {
	blocknetIDURL := "https://blocknet.id"
	if !noColor {
		blocknetIDURL = "\033[4m\033[38;2;170;255;0mhttps://blocknet.id\033[0m"
	}

	return map[string]helpEntry{
		"load": {
			usage:         []string{"load"},
			description:   []string{"Loads a wallet file into the running core."},
			useWhen:       []string{"you just started the core and need to open your wallet"},
			exampleInput:  []string{"> load", "  1) /home/username/.config/blocknet/mainnet/main.wallet.dat", "  2) Enter a custom path", "  3) Create a new wallet", "  Choose: 1", "  Password: ********"},
			exampleOutput: []string{"  Wallet loaded", "  Address: 9PNo...", "  Save wallet path to config for auto-load? [y/N]: y"},
			notes:         []string{"saving to config makes future starts auto-load this wallet"},
		},
		"unload": {
			usage:       []string{"unload"},
			description: []string{"Unloads the currently loaded wallet from the core."},
			useWhen:     []string{"you want to switch wallets without restarting the core"},
			exampleInput:  []string{"> unload"},
			exampleOutput: []string{"# Unloaded", "  Wallet unloaded. Use 'load' to open another."},
			notes:         []string{"works even if the wallet is locked"},
		},
		"help": {
			usage:         []string{"help", "help <command>"},
			aliases:       []string{"?"},
			description:   []string{"Shows all commands or detailed help for one command."},
			useWhen:       []string{"you are not sure what command to run next"},
			exampleInput:  []string{"> help send"},
			exampleOutput: []string{"# Help — send", "  What it does:", "    Sends BNT to another wallet, optionally with a note."},
		},
		"balance": {
			usage:         []string{"balance"},
			aliases:       []string{"bal", "b"},
			description:   []string{"Shows your spendable coins, pending coins, and total."},
			useWhen:       []string{"you want to know how much you can spend right now"},
			exampleInput:  []string{"> bal"},
			exampleOutput: []string{"# Balance", "  spendable:  12.5 BNT", "  confirming: 1 BNT", "  total:      13.5 BNT"},
		},
		"address": {
			usage:         []string{"address"},
			aliases:       []string{"addr", "a"},
			description:   []string{"Shows your receive address to share with someone paying you."},
			useWhen:       []string{"someone asks where to send you coins"},
			exampleInput:  []string{"> addr"},
			exampleOutput: []string{"# Address", "  9PNo..."},
			notes:         []string{"Get a short name like @name or $name at " + blocknetIDURL},
		},
		"send": {
			usage:       []string{"send <addr> <amt> [memo|hex:<memo_hex>]"},
			description: []string{"Sends BNT to another wallet, optionally with a note."},
			useWhen:     []string{"you need to pay someone now"},
			exampleInput: []string{
				"> send @rock 100 \"hello\"",
				"> send $rock 100",
				"> send bnt1qxy... 1.25",
			},
			exampleOutput: []string{"Sent: 9f0b...", "Explorer: https://explorer.blocknetcrypto.com/tx/9f0b..."},
			notes: []string{
				"you can send whole numbers or fractions (example: 1 or 1.25 BNT)",
				"memos with spaces are supported",
				"short names can be used as @name or $name",
				"'send all' sends your entire spendable balance",
			},
		},
		"sign": {
			usage:         []string{"sign"},
			description:   []string{"Signs a message so you can prove wallet ownership."},
			useWhen:       []string{"a service asks you to prove this wallet is yours"},
			exampleInput:  []string{"> sign", "  (then type: prove wallet ownership)"},
			exampleOutput: []string{"# Sign", "  8f2d... (signature hex)"},
			notes:         []string{"view-only wallets cannot sign", "message should be short (up to about 1,000 characters)"},
		},
		"verify": {
			usage:         []string{"verify"},
			description:   []string{"Checks if a signature really came from an address."},
			useWhen:       []string{"you received a signed message and need to trust it"},
			exampleInput:  []string{"> verify", "  (then enter address, message, signature)"},
			exampleOutput: []string{"# Signature is VALID"},
			notes:         []string{"signature must be pasted exactly as produced by sign"},
		},
		"history": {
			usage:         []string{"history"},
			aliases:       []string{"hist", "h"},
			description:   []string{"Shows incoming transactions, oldest to newest."},
			useWhen:       []string{"you need to review recent wallet activity"},
			exampleInput:  []string{"> hist"},
			exampleOutput: []string{"# History", "  block 14200 IN  72.325 BNT  coinbase  c7f2e1d3..."},
		},
		"outputs": {
			usage:       []string{"outputs [spent|unspent|pending] [index]", "outputs tx <txid>", "outputs tx <txid>:<index>"},
			aliases:     []string{"outs", "out"},
			description: []string{"Shows outputs your wallet owns, with status and drill-down details."},
			useWhen:     []string{"you want to inspect spendable/spent/pending outputs"},
			exampleInput: []string{
				"> outputs",
				"> outputs unspent",
				"> outputs pending 2",
				"> outputs tx a1b2c3...d4e5",
			},
			notes: []string{
				"use filters: spent, unspent, pending",
				"use an index to see one output's details (example: outputs 3)",
				"`outputs tx <txid>` shows all owned outputs in that tx",
			},
		},
		"seed": {
			usage:         []string{"seed"},
			description:   []string{"Shows your 12-word recovery seed after warning prompts."},
			useWhen:       []string{"you are backing up wallet recovery words"},
			exampleInput:  []string{"> seed"},
			exampleOutput: []string{"# Seed", "  WARNING: Your recovery seed controls all funds.", "  Show recovery seed? [y/N]:"},
			notes:         []string{"anyone with this seed can spend your funds"},
		},
		"import": {
			usage:         []string{"import"},
			description:   []string{"Creates a new wallet file from a seed phrase."},
			useWhen:       []string{"you need to load an existing wallet into this node"},
			exampleInput:  []string{"> import", "  Choose [1/2]: 1"},
			exampleOutput: []string{"# Import", "  1) 12-word recovery seed", "  2) spend-key/view-key"},
		},
		"viewkeys": {
			usage:         []string{"viewkeys"},
			description:   []string{"Exports your view-only keys (spend public, view private, view public)."},
			useWhen:       []string{"you want watch-only access on another machine"},
			exampleInput:  []string{"> viewkeys", "  Export view-only keys? [y/N]: y", "  Password: "},
			exampleOutput: []string{"# View Keys", "  spend public key:  abc123...", "  view private key:  def456...", "  view public key:   789abc..."},
			notes:         []string{"requires password confirmation", "view private key lets anyone see all incoming funds"},
		},
		"prove": {
			usage:         []string{"prove <txid>"},
			description:   []string{"Generates a proof that you sent a transaction."},
			useWhen:       []string{"someone needs proof of payment"},
			exampleInput:  []string{"> prove a1b2c3d4e5f6..."},
			exampleOutput: []string{"# Prove", "  txid:    a1b2c3d4e5f6...", "  tx key:  deadbeef0123..."},
			notes:         []string{"works on both full and view-only wallets", "share the tx key with the recipient to prove payment"},
		},
		"audit": {
			usage:         []string{"audit"},
			description:   []string{"Scans wallet outputs for duplicate key images (burned funds detection)."},
			useWhen:       []string{"you suspect a key derivation issue burned some outputs"},
			exampleInput:  []string{"> audit"},
			exampleOutput: []string{"# Audit", "  Total outputs:      42", "  Unique key images:  42", "  No duplicate key images found. Wallet is clean."},
			notes:         []string{"a clean audit means no burned funds", "duplicates indicate permanently unspendable outputs from a historical self-send bug"},
		},
		"lock": {
			usage:         []string{"lock"},
			description:   []string{"Locks wallet actions that require your password."},
			useWhen:       []string{"you are stepping away from your terminal"},
			exampleInput:  []string{"> lock"},
			exampleOutput: []string{"# Locked"},
		},
		"unlock": {
			usage:         []string{"unlock"},
			description:   []string{"Unlocks wallet actions after password confirmation."},
			useWhen:       []string{"you get a 'wallet is locked' error"},
			exampleInput:  []string{"> unlock"},
			exampleOutput: []string{"Password: ", "# Unlocked"},
		},
		"save": {
			usage:         []string{"save"},
			description:   []string{"The core daemon saves the wallet automatically."},
			useWhen:       []string{"you want to confirm wallet state is persisted"},
			exampleInput:  []string{"> save"},
			exampleOutput: []string{"# Saved", "  Wallet is saved automatically by the core daemon."},
		},
		"sync": {
			usage:         []string{"sync"},
			aliases:       []string{"scan"},
			description:   []string{"Triggers a blockchain rescan for wallet outputs."},
			useWhen:       []string{"wallet looks behind chain height or missing transactions"},
			exampleInput:  []string{"> sync"},
			exampleOutput: []string{"# Sync", "  Sync triggered"},
		},
		"status": {
			usage:         []string{"status"},
			description:   []string{"Shows node health and wallet summary in one screen."},
			useWhen:       []string{"you need a quick 'is everything healthy?' check"},
			exampleInput:  []string{"> status"},
			exampleOutput: []string{"# Node", "  Peers: 8", "  Height: 2450", "# Wallet", "  Balance: 13.5 BNT"},
		},
		"peers": {
			usage:         []string{"peers"},
			description:   []string{"Lists currently connected peers."},
			useWhen:       []string{"you need to confirm network connectivity"},
			exampleInput:  []string{"> peers"},
			exampleOutput: []string{"# Peers (8)", "  12D3KooW..."},
		},
		"banned": {
			usage:         []string{"banned"},
			description:   []string{"Shows peers that were banned and why."},
			useWhen:       []string{"you suspect peer filtering or connectivity issues"},
			exampleInput:  []string{"> banned"},
			exampleOutput: []string{"# Banned (1)", "  12D3KooW...", "    reason: repeated bad blocks"},
		},
		"export-peer": {
			usage:         []string{"export-peer"},
			description:   []string{"Writes connected peer addresses to peer.txt."},
			useWhen:       []string{"you want another node to connect to known peers"},
			exampleInput:  []string{"> export-peer"},
			exampleOutput: []string{"# Export", "  Peer addresses written to peer.txt"},
		},
		"mining": {
			usage:       []string{"mining", "mining start", "mining stop", "mining threads <N>"},
			description: []string{"Controls local mining and how many CPU threads mining uses."},
			useWhen:     []string{"you want to mine, stop mining, or tune CPU/RAM use"},
			exampleInput: []string{
				"> mining start",
				"> mining threads 4",
				"> mining stop",
			},
			notes: []string{
				"roughly 2GB RAM per thread",
				"thread aliases: threads, thread, t",
			},
		},
		"explore": {
			usage:       []string{"explore <height>", "explore <hash>", "explore mempool"},
			aliases:     []string{"exp"},
			description: []string{"Look up a block by height, a block or transaction by hash, or view mempool stats."},
			useWhen:     []string{"you want to inspect chain data without leaving the terminal"},
			exampleInput: []string{
				"> explore 14207",
				"> explore 0000c3a5b7e2d1f4...50321",
				"> explore mempool",
			},
			notes: []string{
				"a 64-char hex hash is tried as a block hash first, then as a tx hash",
				"numeric input is always treated as a block height",
			},
		},
		"mempool": {
			usage:         []string{"mempool"},
			description:   []string{"Shows mempool statistics and pending transactions."},
			useWhen:       []string{"you want to see what's waiting to be mined"},
			exampleInput:  []string{"> mempool"},
			exampleOutput: []string{"# Mempool", "  Transactions: 5", "  Size:         8.2 KB", "  Fee (min):    0.0001 BNT"},
			notes:         []string{"shortcut for 'explore mempool'"},
		},
		"certify": {
			usage:         []string{"certify"},
			description:   []string{"Verifies chain integrity (difficulty, timestamps, block linkage)."},
			useWhen:       []string{"you suspect corruption or strange chain behavior"},
			exampleInput:  []string{"> certify"},
			exampleOutput: []string{"# Certify", "  Chain height: 125000", "  Chain is clean. No violations found."},
			notes:         []string{"arithmetic-only check, no PoW re-hashing", "may take a moment on long chains"},
		},
		"purge": {
			usage:         []string{"purge"},
			description:   []string{"Deletes local chain data but keeps your wallet and funds."},
			useWhen:       []string{"chain is stuck/corrupted and regular sync cannot recover"},
			exampleInput:  []string{"> purge", "  Confirm purge? [y/N]: y"},
			exampleOutput: []string{"# Purge", "  Blockchain data purged."},
			notes:         []string{"your wallet file and money are not deleted", "requires password confirmation"},
		},
		"version": {
			usage:         []string{"version"},
			description:   []string{"Prints the Blocknet version."},
			useWhen:       []string{"you are reporting bugs or checking for updates"},
			exampleInput:  []string{"> version"},
			exampleOutput: []string{"# Version 1.0.0"},
		},
		"about": {
			usage:         []string{"about"},
			description:   []string{"Shows project info and upstream links."},
			useWhen:       []string{"you want project metadata"},
			exampleInput:  []string{"> about"},
			exampleOutput: []string{"# About", "  Blocknet vX.Y.Z"},
		},
		"license": {
			usage:         []string{"license"},
			description:   []string{"Prints the full software license text."},
			useWhen:       []string{"you need legal/license details"},
			exampleInput:  []string{"> license"},
			exampleOutput: []string{"# License", "  BSD 3-Clause License ..."},
		},
		"quit": {
			usage:        []string{"quit"},
			aliases:      []string{"exit", "q"},
			description:  []string{"Exits the attach session."},
			useWhen:      []string{"you are done"},
			exampleInput: []string{"> q"},
		},
	}
}

func (s *AttachSession) cmdHelp(args []string) {
	if len(args) > 0 {
		topic := normalizeHelpTopic(args[0])
		if topic == "" {
			fmt.Printf("\n%s\n", ErrorHead("Help", s.noColor))
			fmt.Printf("  Unknown command: %s\n", args[0])
			fmt.Println("  Use 'help' to list available commands.")
			return
		}

		entry, ok := helpCommandDetails(s.noColor)[topic]
		if !ok {
			fmt.Printf("\n%s\n", ErrorHead("Help", s.noColor))
			fmt.Printf("  No detailed help available for: %s\n", topic)
			return
		}

		labelColor := "\033[38;2;170;255;0m"
		resetColor := "\033[0m"
		if s.noColor {
			labelColor, resetColor = "", ""
		}

		fmt.Printf("\n%s\n", SectionHead("Help — "+topic, s.noColor))
		if len(entry.aliases) > 0 {
			fmt.Printf("  %sShort name%s:\n", labelColor, resetColor)
			fmt.Printf("    %s\n\n", strings.Join(entry.aliases, ", "))
		}

		fmt.Printf("  %sWhat it does%s:\n", labelColor, resetColor)
		for _, line := range entry.description {
			fmt.Printf("    %s\n", line)
		}

		if len(entry.useWhen) > 0 {
			fmt.Printf("\n  %sUse this when%s:\n", labelColor, resetColor)
			for _, line := range entry.useWhen {
				fmt.Printf("    %s\n", line)
			}
		}
		if len(entry.exampleInput) > 0 {
			fmt.Printf("\n  %sExample input%s:\n", labelColor, resetColor)
			for _, line := range entry.exampleInput {
				fmt.Printf("    %s\n", line)
			}
		}
		if len(entry.exampleOutput) > 0 {
			fmt.Printf("\n  %sExample output%s:\n", labelColor, resetColor)
			for _, line := range entry.exampleOutput {
				fmt.Printf("    %s\n", line)
			}
		}
		if len(entry.notes) > 0 {
			fmt.Printf("\n  %sNotes%s:\n", labelColor, resetColor)
			for _, line := range entry.notes {
				fmt.Printf("    %s-%s %s\n", labelColor, resetColor, line)
			}
		}
		return
	}

	fmt.Printf(`
%s
  load              Load a wallet file into the core
  unload            Unload the current wallet
  balance           Show wallet balance
  address           Show receiving address
  send <addr> <amt> [memo|hex:<memo_hex>] Send funds with optional memo
  sign              Sign a message with your spend key
  verify            Verify a signed message against an address
  history           Show transaction history
  outputs           Show wallet outputs (spent and unspent)
  seed              Show wallet recovery seed (careful!)
  import            Create wallet file from seed or spend/view keys
  viewkeys          Export view-only keys
  lock              Lock wallet
  unlock            Unlock wallet
  prove <txid>      Generate payment proof
  audit             Check wallet for burned outputs
  save              Save wallet to disk
  sync              Rescan blocks for outputs

%s
  status            Show node and wallet status
  explore <id>      Look up a block, transaction, or mempool
  mempool           Show mempool statistics
  peers             List connected peers
  banned            List banned peers
  export-peer       Export peer addresses to peer.txt
  mining            Manage mining
  certify           Check chain integrity (difficulty + timestamps)
  purge             Delete all blockchain data (cannot be undone)
  version           Print version
  about             About this software
  license           Show license
  quit              Exit (saves automatically)
  help <command>    Show detailed help for a command

  Need more info on any command? Type: help <command>
  Example: help send
`, SectionHead("Wallet", s.noColor), SectionHead("Daemon", s.noColor))
}
