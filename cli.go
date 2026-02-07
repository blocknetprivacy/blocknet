package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"blocknet/wallet"

	"golang.org/x/term"
)

// CLI handles the interactive command-line interface
type CLI struct {
	daemon     *Daemon
	wallet     *wallet.Wallet
	scanner    *wallet.Scanner
	ctx        context.Context
	cancel     context.CancelFunc
	reader     *bufio.Reader
	locked     bool
	password   []byte
	startTime  time.Time
	daemonMode bool
	noColor    bool
	api        *APIServer
	apiAddr    string
}

// CLIConfig holds CLI configuration
type CLIConfig struct {
	WalletFile   string
	DataDir      string
	ListenAddrs  []string
	SeedNodes    []string
	Mining       bool
	MineThreads  int
	RecoverMode  bool   // If true, prompt for mnemonic to recover wallet
	SeedMode     bool   // If true, run as seed node with persistent identity
	DaemonMode   bool   // If true, run headless (no interactive prompts)
	ExplorerAddr string // HTTP address for block explorer (empty = disabled)
	APIAddr      string // API listen address (empty = disabled)
	NoColor      bool   // If true, disable colored output
}

// DefaultCLIConfig returns default CLI configuration
func DefaultCLIConfig() CLIConfig {
	return CLIConfig{
		WalletFile:  "wallet.dat",
		DataDir:     "./data",
		ListenAddrs: []string{"/ip4/0.0.0.0/tcp/28080"},
		SeedNodes:   DefaultSeedNodes,
		Mining:      false,
		MineThreads: 1,
	}
}

// NewCLI creates and initializes the CLI
func NewCLI(cfg CLIConfig) (*CLI, error) {
	ctx, cancel := context.WithCancel(context.Background())

	cli := &CLI{
		ctx:        ctx,
		cancel:     cancel,
		reader:     bufio.NewReader(os.Stdin),
		startTime:  time.Now(),
		daemonMode: cfg.DaemonMode,
		noColor:    cfg.NoColor,
	}

	// Check if wallet exists
	walletExists := fileExists(cfg.WalletFile)

	// Handle recovery mode
	var recoverMnemonic string
	if cfg.RecoverMode {
		if walletExists {
			cancel()
			return nil, fmt.Errorf("wallet already exists at %s - delete it first to recover", cfg.WalletFile)
		}

		fmt.Println("Wallet Recovery")
		fmt.Println("===============")
		fmt.Println("Enter your 12-word recovery seed (words separated by spaces):")
		fmt.Print("> ")

		line, err := cli.reader.ReadString('\n')
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to read mnemonic: %w", err)
		}
		recoverMnemonic = strings.TrimSpace(line)

		words := strings.Fields(recoverMnemonic)
		if len(words) != 12 {
			cancel()
			return nil, fmt.Errorf("expected 12 words, got %d", len(words))
		}

		if !wallet.ValidateMnemonic(recoverMnemonic) {
			cancel()
			return nil, fmt.Errorf("invalid mnemonic (checksum failed)")
		}

		fmt.Println("\nMnemonic validated! Creating recovered wallet...")
	}

	// Get password
	var password []byte
	var err error

	if walletExists {
		fmt.Printf("Opening wallet: %s\n", cfg.WalletFile)
		password, err = cli.promptPassword("Password: ")
	} else {
		if cfg.RecoverMode {
			fmt.Printf("Creating recovered wallet: %s\n", cfg.WalletFile)
		} else {
			fmt.Printf("Creating new wallet: %s\n", cfg.WalletFile)
		}
		password, err = cli.promptNewPassword()
	}
	if err != nil {
		cancel()
		return nil, fmt.Errorf("password error: %w", err)
	}
	cli.password = password

	// Create wallet config with crypto callbacks
	walletCfg := wallet.WalletConfig{
		GenerateStealthKeys: func() (*wallet.StealthKeys, error) {
			keys, err := GenerateStealthKeys()
			if err != nil {
				return nil, err
			}
			return &wallet.StealthKeys{
				SpendPrivKey: keys.SpendPrivKey,
				SpendPubKey:  keys.SpendPubKey,
				ViewPrivKey:  keys.ViewPrivKey,
				ViewPubKey:   keys.ViewPubKey,
			}, nil
		},
		DeriveStealthAddress: func(spendPub, viewPub [32]byte) (txPriv, txPub, oneTimePub [32]byte, err error) {
			output, err := DeriveStealthAddress(spendPub, viewPub)
			if err != nil {
				return txPriv, txPub, oneTimePub, err
			}
			return output.TxPrivKey, output.TxPubKey, output.OnetimePubKey, nil
		},
		CheckStealthOutput: func(txPub, outputPub, viewPriv, spendPub [32]byte) bool {
			return CheckStealthOutput(spendPub, viewPriv, txPub, outputPub)
		},
		DeriveSpendKey: func(txPub, viewPriv, spendPriv [32]byte) ([32]byte, error) {
			return DeriveStealthSpendKey(txPub, viewPriv, spendPriv)
		},
		DeriveOutputSecret: func(txPub, viewPriv [32]byte) ([32]byte, error) {
			return DeriveStealthSecret(txPub, viewPriv)
		},
		GenerateKeypairFromSeed: func(seed [32]byte) (priv, pub [32]byte, err error) {
			kp, err := GenerateRistrettoKeypairFromSeed(seed)
			if err != nil {
				return priv, pub, err
			}
			return kp.PrivateKey, kp.PublicKey, nil
		},
	}

	// Load, create, or recover wallet
	var w *wallet.Wallet
	if recoverMnemonic != "" {
		// Recovery mode: create new wallet from mnemonic
		w, err = wallet.NewWalletFromMnemonic(cfg.WalletFile, password, recoverMnemonic, walletCfg)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("recovery failed: %w", err)
		}
		fmt.Println("Wallet recovered successfully!")
		fmt.Println("Note: You will need to sync the blockchain to see your balance.")
	} else {
		w, err = wallet.LoadOrCreateWallet(cfg.WalletFile, password, walletCfg)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("wallet error: %w", err)
		}
	}
	cli.wallet = w
	cli.scanner = wallet.NewScanner(w, wallet.ScannerConfig{
		GenerateKeyImage: GenerateKeyImage,
	})

	// Create daemon config
	daemonCfg := DaemonConfig{
		DataDir:      cfg.DataDir,
		ListenAddrs:  cfg.ListenAddrs,
		SeedNodes:    cfg.SeedNodes,
		SeedMode:     cfg.SeedMode,
		ExplorerAddr: cfg.ExplorerAddr,
	}

	// Create daemon with wallet's stealth keys for mining rewards
	daemon, err := NewDaemon(daemonCfg, &StealthKeys{
		SpendPrivKey: w.Keys().SpendPrivKey,
		SpendPubKey:  w.Keys().SpendPubKey,
		ViewPrivKey:  w.Keys().ViewPrivKey,
		ViewPubKey:   w.Keys().ViewPubKey,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("daemon error: %w", err)
	}
	cli.daemon = daemon

	// Create API server if --api is set
	if cfg.APIAddr != "" {
		cli.api = NewAPIServer(daemon, w, cli.scanner, cfg.DataDir, password)
		cli.apiAddr = cfg.APIAddr
	}

	return cli, nil
}

// Run starts the CLI
func (c *CLI) Run() error {
	// Handle Ctrl+C gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		c.shutdown()
		os.Exit(0)
	}()

	// Start daemon
	fmt.Println("Connecting to network...")
	if err := c.daemon.Start(); err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// Check if wallet is ahead of chain (chain was reset/reorged)
	chainHeight := c.daemon.Chain().Height()
	walletHeight := c.wallet.SyncedHeight()
	if walletHeight > chainHeight {
		removed := c.wallet.RewindToHeight(chainHeight)
		if removed > 0 {
			fmt.Printf("Chain reset detected: removed %d orphaned outputs, rewound wallet to height %d\n", removed, chainHeight)
			c.wallet.Save()
		}
	}

	// Start API server if configured
	if c.api != nil {
		if err := c.api.Start(c.apiAddr); err != nil {
			return fmt.Errorf("failed to start API: %w", err)
		}
	}

	// Auto-scan new blocks for wallet
	go c.autoScanBlocks()

	// Watch for blocks we mined and print explorer links
	go c.watchMinedBlocks()

	// Daemon mode: just wait for shutdown signal
	if c.daemonMode {
		fmt.Println("Running in daemon mode (no interactive shell)")
		fmt.Printf("  Peer ID: %s\n", c.daemon.Node().PeerID())
		fmt.Printf("  Chain height: %d\n", c.daemon.Chain().Height())
		fmt.Println("Press Ctrl+C to stop")

		// Block until shutdown
		<-c.ctx.Done()
		return c.shutdown()
	}

	// Print welcome
	c.printWelcome()

	// Main command loop
	for {
		select {
		case <-c.ctx.Done():
			return c.shutdown()
		default:
		}

		// Print prompt
		fmt.Print("\n> ")

		// Read command
		line, err := c.reader.ReadString('\n')
		if err != nil {
			// EOF means stdin closed - wait for shutdown
			<-c.ctx.Done()
			return c.shutdown()
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse and execute
		if err := c.executeCommand(line); err != nil {
			if err.Error() == "quit" {
				return c.shutdown()
			}
			fmt.Printf("Error: %v\n", err)
		}
	}
}

func (c *CLI) printWelcome() {
	height := c.daemon.Chain().Height()
	spendable := c.wallet.SpendableBalance(height)
	pending := c.wallet.PendingBalance(height)

	balanceStr := formatAmount(spendable)
	if pending > 0 {
		balanceStr += fmt.Sprintf(" + %s pending", formatAmount(pending))
	}

	green := "\033[38;5;118m"
	reset := "\033[0m"
	if c.noColor {
		green = ""
		reset = ""
	}

	logo := []string{
		`        ▄███████▄`,
		`        ▀█████████▄`,
		`          ▀█████████▄`,
		`            ▀█████████▄`,
		`              ▀█████████▄`,
		`                ▀█████████▄`,
		`                  ▀███████▀`,
		``,
		`  ▄████████████████████████████▄`,
		fmt.Sprintf(`  ████    BLOCKNET v%s   ████`, Version),
		`  ▀████████████████████████████▀`,
	}

	fmt.Println()
	for _, line := range logo {
		fmt.Printf("%s%s%s\n", green, line, reset)
		time.Sleep(40 * time.Millisecond)
	}

	fmt.Println()
	fmt.Printf("  Address: %s...\n", c.wallet.Address()[:24])
	fmt.Printf("  Balance: %s\n", balanceStr)
	fmt.Printf("  Height:  %d\n", height)
	fmt.Println()
	fmt.Println("Type 'help' for available commands")
}

func (c *CLI) executeCommand(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	// Check if locked
	if c.locked && cmd != "unlock" && cmd != "quit" && cmd != "exit" {
		return fmt.Errorf("wallet is locked, use 'unlock' first")
	}

	switch cmd {
	case "help", "?":
		c.cmdHelp()
	case "status":
		c.cmdStatus()
	case "balance", "bal":
		c.cmdBalance()
	case "address", "addr":
		c.cmdAddress()
	case "send":
		return c.cmdSend(args)
	case "history", "hist":
		c.cmdHistory()
	case "peers":
		c.cmdPeers()
	case "banned":
		c.cmdBanned()
	case "export-peer":
		return c.cmdExportPeer()
	case "mining":
		return c.cmdMining(args)
	case "sync":
		c.cmdSync()
	case "seed":
		return c.cmdSeed()
	case "viewkeys":
		return c.cmdViewKeys()
	case "lock":
		c.cmdLock()
	case "unlock":
		return c.cmdUnlock()
	case "save":
		return c.cmdSave()
	case "quit", "exit":
		return fmt.Errorf("quit")
	default:
		return fmt.Errorf("unknown command: %s (type 'help' for commands)", cmd)
	}

	return nil
}

func (c *CLI) cmdHelp() {
	viewOnlyNote := ""
	if c.wallet.IsViewOnly() {
		viewOnlyNote = " [VIEW-ONLY]"
	}

	fmt.Printf(`
Commands:%s
  status            Show node and wallet status
  balance           Show wallet balance
  address           Show receiving address
  send <addr> <amt> Send funds to address%s
  history           Show transaction history
  peers             List connected peers
  banned            List banned peers
  export-peer       Export peer address to peer.txt
  mining start|stop|threads Control mining
  sync              Force chain sync
  seed              Show recovery seed (careful!)
  viewkeys          Export view-only wallet keys
  lock              Lock wallet
  unlock            Unlock wallet
  save              Save wallet to disk
  quit              Exit (saves automatically)
`, viewOnlyNote, func() string {
		if c.wallet.IsViewOnly() {
			return " (disabled)"
		}
		return ""
	}())
}

func (c *CLI) cmdStatus() {
	stats := c.daemon.Stats()
	total, unspent := c.wallet.OutputCount()

	walletType := "Full"
	if c.wallet.IsViewOnly() {
		walletType = "View-Only (cannot spend)"
	}

	height := stats.ChainHeight
	spendable := c.wallet.SpendableBalance(height)
	pending := c.wallet.PendingBalance(height)

	balanceStr := formatAmount(spendable)
	if pending > 0 {
		balanceStr += fmt.Sprintf(" + %s pending", formatAmount(pending))
	}

	fmt.Printf(`
Node Status:
  Peer ID:     %s
  Peers:       %d
  Height:      %d
  Best Hash:   %s
  Syncing:     %v
  Uptime:      %s

Wallet Status:
  Type:        %s
  Balance:     %s
  Outputs:     %d unspent / %d total
  Synced To:   %d
  Address:     %s...
`,
		stats.PeerID[:16]+"...",
		stats.Peers,
		stats.ChainHeight,
		stats.BestHash,
		stats.Syncing,
		time.Since(c.startTime).Round(time.Second),
		walletType,
		balanceStr,
		unspent, total,
		c.wallet.SyncedHeight(),
		c.wallet.Address()[:32],
	)
}

func (c *CLI) cmdBalance() {
	height := c.daemon.Chain().Height()
	spendable := c.wallet.SpendableBalance(height)
	pending := c.wallet.PendingBalance(height)
	total, unspent := c.wallet.OutputCount()

	fmt.Printf("%s spendable", formatAmount(spendable))
	if pending > 0 {
		fmt.Printf(" + %s pending", formatAmount(pending))
	}
	fmt.Printf(" (%d outputs)\n", unspent)

	if total > unspent {
		fmt.Printf("  + %d spent outputs in history\n", total-unspent)
	}
}

func (c *CLI) cmdAddress() {
	// For stealth addresses, we always give the same public address
	// The one-time addresses are derived per-transaction by senders
	fmt.Printf("Your address:\n%s\n", c.wallet.Address())
	fmt.Println("\n(Senders derive unique one-time addresses from this)")
}

func (c *CLI) cmdSend(args []string) error {
	// View-only wallets cannot send
	if c.wallet.IsViewOnly() {
		return fmt.Errorf("cannot send from a view-only wallet")
	}

	if len(args) < 2 {
		return fmt.Errorf("usage: send <address> <amount>")
	}

	// Parse recipient address (strip control characters from copy-paste)
	recipientAddr := sanitizeInput(args[0])
	spendPub, viewPub, err := wallet.ParseAddress(recipientAddr)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	// Parse amount
	amount, err := parseAmount(args[1])
	if err != nil {
		return fmt.Errorf("invalid amount: %w", err)
	}

	// Check spendable balance (excludes immature coinbase and unconfirmed)
	height := c.daemon.Chain().Height()
	spendable := c.wallet.SpendableBalance(height)
	if spendable < amount {
		pending := c.wallet.PendingBalance(height)
		if pending > 0 {
			return fmt.Errorf("insufficient spendable balance: have %s spendable + %s pending, need %s",
				formatAmount(spendable), formatAmount(pending), formatAmount(amount))
		}
		return fmt.Errorf("insufficient balance: have %s, need %s",
			formatAmount(spendable), formatAmount(amount))
	}

	// Confirm
	fmt.Printf("\nSend %s to %s...?\n", formatAmount(amount), recipientAddr[:24])
	fmt.Print("Confirm [y/N]: ")

	confirm, _ := c.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		fmt.Println("Cancelled")
		return nil
	}

	// Build and send transaction
	fmt.Printf("\nBuilding transaction...\n")

	// Build transaction using wallet and daemon
	recipient := wallet.Recipient{
		SpendPubKey: spendPub,
		ViewPubKey:  viewPub,
		Amount:      amount,
	}

	builder := c.createTxBuilder()
	chainHeight := c.daemon.Chain().Height()
	result, err := builder.Transfer([]wallet.Recipient{recipient}, 1000, chainHeight) // 1000 atomic = 0.00001 BNT fee rate
	if err != nil {
		return fmt.Errorf("failed to build transaction: %w", err)
	}

	// Submit to mempool via Dandelion++
	if err := c.daemon.SubmitTransaction(result.TxData); err != nil {
		return fmt.Errorf("failed to submit transaction: %w", err)
	}

	// Mark outputs as spent
	for _, spent := range result.SpentOutputs {
		c.wallet.MarkSpent(spent.OneTimePubKey, c.daemon.Chain().Height())
	}

	fmt.Printf("Transaction sent: %x\n", result.TxID[:16])
	fmt.Printf("  Fee: %s\n", formatAmount(result.Fee))
	if result.Change > 0 {
		fmt.Printf("  Change: %s\n", formatAmount(result.Change))
	}

	return nil
}

func (c *CLI) cmdHistory() {
	outputs := c.wallet.SpendableOutputs()
	if len(outputs) == 0 {
		fmt.Println("No transaction history")
		return
	}

	fmt.Println("\nRecent outputs:")
	fmt.Println("  Height    Amount          Status")
	fmt.Println("  ------    ------          ------")

	// Show last 10
	start := 0
	if len(outputs) > 10 {
		start = len(outputs) - 10
	}

	for _, out := range outputs[start:] {
		status := "spendable"
		if out.Spent {
			status = fmt.Sprintf("spent@%d", out.SpentHeight)
		}
		fmt.Printf("  %-8d  %-14s  %s\n",
			out.BlockHeight,
			formatAmount(out.Amount),
			status,
		)
	}
}

func (c *CLI) cmdPeers() {
	peers := c.daemon.Node().Peers()
	banned := c.daemon.Node().BannedCount()

	if len(peers) == 0 {
		fmt.Println("No connected peers")
	} else {
		fmt.Printf("\nConnected peers (%d):\n", len(peers))
		for _, p := range peers {
			fmt.Printf("  %s\n", p.String()[:32]+"...")
		}
	}

	if banned > 0 {
		fmt.Printf("\nBanned peers: %d (use 'banned' to see details)\n", banned)
	}
}

func (c *CLI) cmdBanned() {
	bans := c.daemon.Node().GetBannedPeers()
	if len(bans) == 0 {
		fmt.Println("No banned peers")
		return
	}

	fmt.Printf("\nBanned peers (%d):\n", len(bans))
	for _, ban := range bans {
		durStr := "permanent"
		if !ban.Permanent {
			remaining := time.Until(ban.ExpiresAt).Round(time.Minute)
			durStr = fmt.Sprintf("expires in %s", remaining)
		}
		fmt.Printf("  %s...\n    Reason: %s\n    Banned: %dx, %s\n",
			ban.PeerID.String()[:16],
			ban.Reason,
			ban.BanCount,
			durStr,
		)
	}
}

func (c *CLI) cmdExportPeer() error {
	if err := c.daemon.Node().WritePeerFile("peer.txt"); err != nil {
		return err
	}

	fmt.Println("\nPeer addresses written to peer.txt")
	fmt.Println("Share this file or its contents with other nodes.")
	fmt.Println("\nOther nodes can connect with:")
	for _, addr := range c.daemon.Node().FullMultiaddrs() {
		fmt.Printf("  ./blocknet %s\n", addr)
	}
	return nil
}

func (c *CLI) cmdMining(args []string) error {
	if len(args) == 0 {
		if c.daemon.IsMining() {
			stats := c.daemon.MinerStats()
			hashRate := c.daemon.Miner().HashRate()
			elapsed := time.Since(stats.StartTime).Round(time.Second)
			fmt.Printf("Mining: active (%s)\n", elapsed)
			fmt.Printf("  Hashrate:     %.2f H/s\n", hashRate)
			fmt.Printf("  Total hashes: %d\n", stats.HashCount)
			fmt.Printf("  Blocks found: %d\n", stats.BlocksFound)
			fmt.Printf("  Chain height: %d\n", c.daemon.Chain().Height())
		} else {
			fmt.Println("Mining: stopped")
		}
		return nil
	}

	switch args[0] {
	case "start":
		if c.daemon.IsMining() {
			fmt.Println("Mining already running")
			return nil
		}
		c.daemon.Miner().SetThreads(1)
		fmt.Println("Starting miner (1 thread)...")
		fmt.Println("  Note: Argon2id PoW uses ~2GB RAM per thread")
		fmt.Println("  First hash may take 10-30 seconds...")
		c.daemon.StartMining()
		fmt.Println("Mining started! Type 'mining' to see stats")
	case "stop":
		if !c.daemon.IsMining() {
			fmt.Println("Mining not running")
			return nil
		}
		fmt.Println("Stopping miner...")
		c.daemon.StopMining()
		fmt.Println("Mining stopped")
	case "threads":
		if len(args) < 2 {
			fmt.Printf("Mining threads: %d\n", c.daemon.Miner().Threads())
			return nil
		}
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 1 {
			return fmt.Errorf("usage: mining threads <N> (N >= 1)")
		}
		c.daemon.Miner().SetThreads(n)
		fmt.Printf("Mining threads set to %d (uses ~%dGB RAM)\n", n, n*2)
		if c.daemon.IsMining() {
			fmt.Println("  Takes effect on next block attempt")
		}
	default:
		return fmt.Errorf("usage: mining [start|stop|threads <N>]")
	}
	return nil
}

func (c *CLI) cmdSync() {
	chainHeight := c.daemon.Chain().Height()
	walletHeight := c.wallet.SyncedHeight()

	fmt.Printf("Chain height:  %d\n", chainHeight)
	fmt.Printf("Wallet synced: %d\n", walletHeight)

	if walletHeight >= chainHeight {
		fmt.Println("Wallet is fully synced")
		return
	}

	fmt.Printf("Scanning %d blocks...\n", chainHeight-walletHeight)

	// Scan blocks from wallet height to chain height
	for h := walletHeight + 1; h <= chainHeight; h++ {
		block := c.daemon.Chain().GetBlockByHeight(h)
		if block == nil {
			break
		}

		blockData := blockToScanData(block)
		found, spent := c.scanner.ScanBlock(blockData)

		if found > 0 || spent > 0 {
			fmt.Printf("  Block %d: +%d outputs, %d spent\n", h, found, spent)
		}
	}

	c.wallet.SetSyncedHeight(chainHeight)
	fmt.Printf("Wallet synced to height %d\n", chainHeight)
}

func (c *CLI) cmdSeed() error {
	fmt.Println("\n⚠️  WARNING: Your recovery seed controls all funds!")
	fmt.Println("Anyone with this seed can steal your coins.")
	fmt.Println("Never share it, never enter it online.")
	fmt.Print("\nShow recovery seed? [y/N]: ")

	confirm, _ := c.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		return nil
	}

	mnemonic := c.wallet.Mnemonic()
	if mnemonic == "" {
		fmt.Println("\nNo recovery seed available (wallet may predate BIP39 support)")
		return nil
	}

	fmt.Println("\n╔══════════════════════════════════════════════════════╗")
	fmt.Println("║           12-WORD RECOVERY SEED (BIP39)              ║")
	fmt.Println("╠══════════════════════════════════════════════════════╣")

	words := strings.Fields(mnemonic)
	for i := 0; i < len(words); i += 4 {
		end := i + 4
		if end > len(words) {
			end = len(words)
		}
		row := ""
		for j := i; j < end; j++ {
			row += fmt.Sprintf("%2d.%-10s ", j+1, words[j])
		}
		fmt.Printf("║  %s║\n", fmt.Sprintf("%-52s", row))
	}

	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println("\nWrite these words down and store them safely!")
	fmt.Println("You can recover your wallet with: blocknet --recover")

	return nil
}

func (c *CLI) cmdViewKeys() error {
	if c.wallet.IsViewOnly() {
		return fmt.Errorf("this is already a view-only wallet")
	}

	fmt.Println("\n⚠️  WARNING: View-only keys allow monitoring all incoming funds!")
	fmt.Println("Anyone with these keys can see your balance and transaction history.")
	fmt.Println("They CANNOT spend your funds.")
	fmt.Print("\nExport view-only keys? [y/N]: ")

	confirm, _ := c.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		return nil
	}

	keys := c.wallet.ExportViewOnlyKeys()

	fmt.Println("\n╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                     VIEW-ONLY WALLET KEYS                            ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Spend Public Key:                                                   ║\n")
	fmt.Printf("║    %x  ║\n", keys.SpendPubKey)
	fmt.Printf("║  View Private Key:                                                   ║\n")
	fmt.Printf("║    %x  ║\n", keys.ViewPrivKey)
	fmt.Printf("║  View Public Key:                                                    ║\n")
	fmt.Printf("║    %x  ║\n", keys.ViewPubKey)
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")

	fmt.Println("\nTo create a view-only wallet, run:")
	fmt.Println("  blocknet --viewonly --spend-pub <spend_pub> --view-priv <view_priv>")
	fmt.Println("\nOr copy these keys to a file and import with:")
	fmt.Println("  blocknet --import-viewonly <keyfile>")

	return nil
}

func (c *CLI) cmdLock() {
	c.locked = true
	fmt.Println("Wallet locked")
}

func (c *CLI) cmdUnlock() error {
	if !c.locked {
		fmt.Println("Wallet is not locked")
		return nil
	}

	password, err := c.promptPassword("Password: ")
	if err != nil {
		return err
	}

	// Verify password matches
	if string(password) != string(c.password) {
		return fmt.Errorf("incorrect password")
	}

	c.locked = false
	fmt.Println("Wallet unlocked")
	return nil
}

func (c *CLI) cmdSave() error {
	if err := c.wallet.Save(); err != nil {
		return fmt.Errorf("failed to save wallet: %w", err)
	}
	fmt.Println("Wallet saved")
	return nil
}

func (c *CLI) shutdown() error {
	// Stop API server first (removes cookie file)
	if c.api != nil {
		c.api.Stop()
	}

	fmt.Println("Saving wallet...")
	if err := c.wallet.Save(); err != nil {
		fmt.Printf("Warning: failed to save wallet: %v\n", err)
	}

	fmt.Println("Stopping daemon...")
	c.daemon.Stop()

	fmt.Println("Goodbye!")
	return nil
}

// Password prompting with hidden input
func (c *CLI) promptPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)

	// Check if we're in a terminal
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		password, err := term.ReadPassword(fd)
		fmt.Println() // newline after hidden input
		return password, err
	}

	// Fallback for non-terminal (testing)
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(line)), nil
}

func (c *CLI) promptNewPassword() ([]byte, error) {
	password, err := c.promptPassword("Enter new password: ")
	if err != nil {
		return nil, err
	}

	if len(password) < 3 {
		return nil, fmt.Errorf("password must be at least 3 characters")
	}

	confirm, err := c.promptPassword("Confirm password: ")
	if err != nil {
		return nil, err
	}

	if string(password) != string(confirm) {
		return nil, fmt.Errorf("passwords do not match")
	}

	return password, nil
}

// Helpers
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func formatAmount(atomicUnits uint64) string {
	// 1 BNT = 100,000,000 atomic units (8 decimals)
	whole := atomicUnits / 100_000_000
	frac := atomicUnits % 100_000_000
	if frac == 0 {
		return fmt.Sprintf("%d BNT", whole)
	}
	// Trim trailing zeros
	fracStr := fmt.Sprintf("%08d", frac)
	fracStr = strings.TrimRight(fracStr, "0")
	return fmt.Sprintf("%d.%s BNT", whole, fracStr)
}

func parseAmount(s string) (uint64, error) {
	// Remove "BNT" suffix if present
	s = strings.TrimSuffix(strings.TrimSpace(s), "BNT")
	s = strings.TrimSpace(s)

	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return 0, fmt.Errorf("invalid amount format")
	}

	// Parse whole part
	whole, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, err
	}

	result := whole * 100_000_000

	// Parse fractional part if present
	if len(parts) == 2 {
		fracStr := parts[1]
		// Pad or truncate to 8 digits
		if len(fracStr) > 8 {
			fracStr = fracStr[:8]
		} else {
			fracStr = fracStr + strings.Repeat("0", 8-len(fracStr))
		}
		frac, err := strconv.ParseUint(fracStr, 10, 64)
		if err != nil {
			return 0, err
		}
		result += frac
	}

	return result, nil
}

// createTxBuilder creates a transaction builder with daemon integration
func (c *CLI) createTxBuilder() *wallet.Builder {
	cfg := wallet.TransferConfig{
		SelectRingMembers: func(realPubKey, realCommitment [32]byte) (keys, commitments [][32]byte, secretIndex int, err error) {
			ringData, err := c.daemon.Chain().SelectRingMembersWithCommitments(realPubKey, realCommitment)
			if err != nil {
				return nil, nil, 0, err
			}
			return ringData.Keys, ringData.Commitments, ringData.SecretIndex, nil
		},
		CreateCommitment: func(amount uint64, blinding [32]byte) [32]byte {
			commitment, _ := CreatePedersenCommitmentWithBlinding(amount, blinding)
			return commitment
		},
		CreateRangeProof: func(amount uint64, blinding [32]byte) ([]byte, error) {
			proof, err := CreateRangeProof(amount, blinding)
			if err != nil {
				return nil, err
			}
			return proof.Proof, nil
		},
		SignRingCT: func(ringKeys, ringCommitments [][32]byte, secretIndex int, privateKey, realBlinding, pseudoCommitment, pseudoBlinding [32]byte, message []byte) ([]byte, [32]byte, error) {
			sig, err := SignRingCT(ringKeys, ringCommitments, secretIndex, privateKey, realBlinding, pseudoCommitment, pseudoBlinding, message)
			if err != nil {
				return nil, [32]byte{}, err
			}
			return sig.Signature, sig.KeyImage, nil
		},
		GenerateBlinding: func() [32]byte {
			blinding, _ := GenerateBlinding()
			return blinding
		},
		ComputeTxID: func(txData []byte) [32]byte {
			return ComputeTxHash(txData)
		},
		DeriveStealthAddress: func(spendPub, viewPub [32]byte) (txPriv, txPub, oneTimePub [32]byte, err error) {
			output, err := DeriveStealthAddress(spendPub, viewPub)
			if err != nil {
				return txPriv, txPub, oneTimePub, err
			}
			return output.TxPrivKey, output.TxPubKey, output.OnetimePubKey, nil
		},
		BlindingAdd: BlindingAdd,
		BlindingSub: BlindingSub,
		RingSize:    RingSize,
		MinFee:      10000, // 0.0001 BNT minimum
		FeePerByte:  100,   // 0.000001 BNT per byte
	}

	return wallet.NewBuilder(c.wallet, cfg)
}

// autoScanBlocks subscribes to new blocks and scans them for wallet outputs
func (c *CLI) autoScanBlocks() {
	blockCh := c.daemon.SubscribeBlocks()

	for {
		select {
		case <-c.ctx.Done():
			return
		case block := <-blockCh:
			if block == nil {
				continue
			}
			blockData := blockToScanData(block)
			found, spent := c.scanner.ScanBlock(blockData)
			if found > 0 || spent > 0 {
				c.wallet.Save()
			}
		}
	}
}

// watchMinedBlocks prints explorer links for blocks we mined
func (c *CLI) watchMinedBlocks() {
	minedCh := c.daemon.SubscribeMinedBlocks()

	// ANSI colors - #AAFF00 in 24-bit true color
	green := "\033[38;2;170;255;0m"
	underline := "\033[4m"
	reset := "\033[0m"

	for {
		select {
		case <-c.ctx.Done():
			return
		case block := <-minedCh:
			if block == nil {
				continue
			}
			height := block.Header.Height
			url := fmt.Sprintf("https://explorer.blocknetcrypto.com/block/%d", height)

			if c.noColor {
				fmt.Printf("\nYou mined block %d! View: %s\n", height, url)
			} else {
				fmt.Printf("\n%sYou mined block %d!%s View: %s%s%s%s\n",
					green, height, reset,
					green, underline, url, reset)
			}
		}
	}
}

// blockToScanData converts a Block to scanner-compatible format
func blockToScanData(block *Block) *wallet.BlockData {
	data := &wallet.BlockData{
		Height:       block.Header.Height,
		Transactions: make([]wallet.TxData, len(block.Transactions)),
	}

	for i, tx := range block.Transactions {
		txID, _ := tx.TxID()
		data.Transactions[i] = wallet.TxData{
			TxID:       txID,
			TxPubKey:   tx.TxPublicKey,
			IsCoinbase: tx.IsCoinbase(),
			Outputs:    make([]wallet.OutputData, len(tx.Outputs)),
		}

		for j, out := range tx.Outputs {
			data.Transactions[i].Outputs[j] = wallet.OutputData{
				Index:           j,
				PubKey:          out.PublicKey,
				Commitment:      out.Commitment,
				EncryptedAmount: out.EncryptedAmount,
			}
		}

		for _, inp := range tx.Inputs {
			data.Transactions[i].KeyImages = append(data.Transactions[i].KeyImages, inp.KeyImage)
		}
	}

	return data
}

// sanitizeInput removes control characters from user input (fixes tmux copy-paste issues)
func sanitizeInput(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return -1 // drop the rune
	}, s)
}
