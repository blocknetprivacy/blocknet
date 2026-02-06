package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"blocknet/wallet"
)

func main() {
	// Parse command line flags
	walletFile := flag.String("wallet", "wallet.dat", "Path to wallet file")
	dataDir := flag.String("data", "./data", "Data directory")
	listen := flag.String("listen", "/ip4/0.0.0.0/tcp/28080", "P2P listen address")
	testMode := flag.Bool("test", false, "Run in test mode (run crypto tests)")
	recover := flag.Bool("recover", false, "Recover wallet from mnemonic seed")
	seedNode := flag.Bool("seed", false, "Run as seed node (persistent identity)")
	daemonMode := flag.Bool("daemon", false, "Run headless (no interactive shell)")
	explorerAddr := flag.String("explorer", "", "HTTP address for block explorer (e.g. :8080)")
	noColor := flag.Bool("nocolor", false, "Disable colored output")
	viewOnly := flag.Bool("viewonly", false, "Create a view-only wallet")
	spendPub := flag.String("spend-pub", "", "Spend public key (hex) for view-only wallet")
	viewPriv := flag.String("view-priv", "", "View private key (hex) for view-only wallet")
	flag.Parse()

	// Test mode runs the crypto/chain tests
	if *testMode {
		runTests()
		return
	}

	// View-only wallet creation mode
	if *viewOnly {
		if *spendPub == "" || *viewPriv == "" {
			fmt.Fprintln(os.Stderr, "Error: --viewonly requires --spend-pub and --view-priv")
			fmt.Fprintln(os.Stderr, "Usage: blocknet --viewonly --spend-pub <hex> --view-priv <hex>")
			os.Exit(1)
		}

		if err := createViewOnlyWallet(*walletFile, *spendPub, *viewPriv); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Normal mode: start interactive CLI
	seedNodes := DefaultSeedNodes
	if len(flag.Args()) > 0 {
		seedNodes = append(seedNodes, flag.Args()...)
	}
	cfg := CLIConfig{
		WalletFile:   *walletFile,
		DataDir:      *dataDir,
		ListenAddrs:  []string{*listen},
		SeedNodes:    seedNodes,
		RecoverMode:  *recover,
		SeedMode:     *seedNode,
		DaemonMode:   *daemonMode,
		ExplorerAddr: *explorerAddr,
		NoColor:      *noColor,
	}

	cli, err := NewCLI(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := cli.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func createViewOnlyWallet(filename, spendPubHex, viewPrivHex string) error {
	// Parse hex keys
	spendPubBytes, err := hex.DecodeString(spendPubHex)
	if err != nil || len(spendPubBytes) != 32 {
		return fmt.Errorf("invalid spend public key (expected 64 hex chars)")
	}

	viewPrivBytes, err := hex.DecodeString(viewPrivHex)
	if err != nil || len(viewPrivBytes) != 32 {
		return fmt.Errorf("invalid view private key (expected 64 hex chars)")
	}

	var keys wallet.ViewOnlyKeys
	copy(keys.SpendPubKey[:], spendPubBytes)
	copy(keys.ViewPrivKey[:], viewPrivBytes)

	// Derive view public key from view private key
	kp, err := GenerateRistrettoKeypairFromSeed(keys.ViewPrivKey)
	if err != nil {
		return fmt.Errorf("failed to derive view public key: %w", err)
	}
	keys.ViewPubKey = kp.PublicKey

	// Prompt for password
	fmt.Print("Enter password for new view-only wallet: ")
	var password string
	fmt.Scanln(&password)
	if len(password) < 3 {
		return fmt.Errorf("password must be at least 3 characters")
	}

	// Create wallet config
	cfg := wallet.WalletConfig{
		CheckStealthOutput: CheckStealthOutput,
		DeriveOutputSecret: DeriveStealthSecret,
	}

	// Create view-only wallet
	w, err := wallet.NewViewOnlyWallet(filename, []byte(password), keys, cfg)
	if err != nil {
		return fmt.Errorf("failed to create view-only wallet: %w", err)
	}

	fmt.Printf("View-only wallet created: %s\n", filename)
	fmt.Printf("Address: %s\n", w.Address())
	fmt.Println("\nThis wallet can monitor incoming funds but cannot spend.")

	return nil
}
