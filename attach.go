package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	defaultAPITimeout = 30 * time.Second
	patienceThreshold = 5 * time.Second
)

func withPatience(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	go func() {
		select {
		case <-time.After(patienceThreshold):
			fmt.Println("  Core is busy, hang on...")
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

type AttachSession struct {
	client  *CoreClient
	reader  *bufio.Reader
	noColor bool
	network Network
	locked  bool
}

func NewAttachSession(client *CoreClient, net Network, noColor bool) *AttachSession {
	return &AttachSession{
		client:  client,
		reader:  bufio.NewReader(os.Stdin),
		noColor: noColor,
		network: net,
	}
}

func (s *AttachSession) Run() error {
	s.checkLockState()
	go s.listenEvents()
	s.printWelcome()

	for {
		fmt.Print("\n> ")
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return nil
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := s.executeCommand(line); err != nil {
			if err.Error() == "quit" {
				return nil
			}
			fmt.Printf("\n%s\n  %v\n", ErrorHead("Error", s.noColor), err)
		}
	}
}

func (s *AttachSession) executeCommand(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	if sendArgs, matched, err := parseSendArgsFromPaymentLink(line); matched {
		if err != nil {
			return err
		}
		parts = append([]string{"send"}, sendArgs...)
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	if s.locked && cmd != "unlock" && cmd != "load" && cmd != "unload" && cmd != "help" && cmd != "?" && cmd != "quit" && cmd != "exit" && cmd != "q" {
		return fmt.Errorf("wallet is locked, use 'unlock' first")
	}

	switch cmd {
	case "help", "?":
		s.cmdHelp(args)
	case "version":
		s.cmdVersion()
	case "status":
		return s.cmdStatus()
	case "balance", "bal", "b":
		return s.cmdBalance()
	case "address", "addr", "a":
		return s.cmdAddress()
	case "send":
		return s.cmdSend(args)
	case "sign":
		return s.cmdSign()
	case "verify":
		return s.cmdVerifyMsg()
	case "history", "hist", "h":
		return s.cmdHistory()
	case "outputs", "outs", "out":
		return s.cmdOutputs(args)
	case "peers":
		return s.cmdPeers()
	case "banned":
		return s.cmdBanned()
	case "export-peer":
		return s.cmdExportPeer()
	case "mining":
		return s.cmdMining(args)
	case "load":
		return s.cmdLoad()
	case "unload":
		return s.cmdUnload()
	case "sync", "scan":
		return s.cmdSync()
	case "seed":
		return s.cmdSeed()
	case "import":
		return s.cmdImport()
	case "viewkeys":
		return s.cmdViewKeys()
	case "prove":
		return s.cmdProve(args)
	case "lock":
		return s.cmdLock()
	case "unlock":
		return s.cmdUnlock()
	case "audit":
		return s.cmdAudit()
	case "save":
		return s.cmdSave()
	case "explore", "exp":
		return s.cmdExplore(args)
	case "mempool":
		return s.cmdExplore([]string{"mempool"})
	case "purge":
		return s.cmdPurge()
	case "certify":
		return s.cmdCertify()
	case "license":
		s.cmdLicense()
	case "about":
		s.cmdAbout()
	case "quit", "exit", "q":
		return fmt.Errorf("quit")
	default:
		return fmt.Errorf("unknown command: %s (type 'help' for commands)", cmd)
	}

	return nil
}

func (s *AttachSession) checkLockState() {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()
	_, err := s.client.Get(ctx, "/api/wallet/balance")
	if err != nil {
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == 403 {
			s.locked = true
		}
	}
}

func (s *AttachSession) readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		fmt.Println()
		return strings.TrimSpace(string(pw)), err
	}
	line, err := s.reader.ReadString('\n')
	return strings.TrimSpace(line), err
}

func (s *AttachSession) handleAPIError(err error) error {
	if apiErr, ok := err.(*APIError); ok {
		if apiErr.StatusCode == 403 && strings.Contains(apiErr.Message, "locked") {
			s.locked = true
			return fmt.Errorf("wallet is locked, use 'unlock' first")
		}
		return fmt.Errorf("%s", apiErr.Message)
	}
	return err
}

func (s *AttachSession) printWelcome() {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	raw, err := s.client.Status(ctx)
	if err != nil {
		fmt.Printf("\n  Connected to %s (status unavailable)\n", s.network)
		fmt.Println("  Type 'help' for available commands")
		return
	}

	var status struct {
		Height uint64 `json:"chain_height"`
	}
	json.Unmarshal(raw, &status)

	raw, err = s.client.Get(ctx, "/api/wallet/balance")
	if err == nil {
		var bal struct {
			Spendable uint64 `json:"spendable"`
			Pending   uint64 `json:"pending"`
		}
		json.Unmarshal(raw, &bal)

		raw2, _ := s.client.Get(ctx, "/api/wallet/address")
		var addr struct {
			Address string `json:"address"`
		}
		if raw2 != nil {
			json.Unmarshal(raw2, &addr)
		}

		balStr := FormatAmount(bal.Spendable)
		if bal.Pending > 0 {
			balStr += fmt.Sprintf(" + %s pending", FormatAmount(bal.Pending))
		}

		fmt.Printf("\n  Address: %s\n", addr.Address)
		fmt.Printf("  Balance: %s\n", balStr)
	}

	fmt.Printf("  Height:  %d\n", status.Height)
	fmt.Println()
	fmt.Println("  Type 'help' for available commands")
}

func (s *AttachSession) listenEvents() {
	for {
		ctx := context.Background()
		_ = s.client.SSE(ctx, "/api/events", func(event, data string) {
			if event == "mined_block" {
				var block struct {
					Height uint64 `json:"height"`
				}
				if json.Unmarshal([]byte(data), &block) == nil {
					fmt.Printf("\n%s\n", SectionHead(fmt.Sprintf("Mined block %d", block.Height), s.noColor))
					fmt.Printf("  https://explorer.blocknetcrypto.com/block/%d\n", block.Height)
				}
			}
		})
		time.Sleep(5 * time.Second)
	}
}

func parseSendArgsFromPaymentLink(line string) ([]string, bool, error) {
	raw := strings.TrimSpace(line)
	if raw == "" {
		return nil, false, nil
	}

	lower := strings.ToLower(raw)
	isBlocknetURI := strings.HasPrefix(lower, "blocknet://") || strings.HasPrefix(lower, "blocknet:")
	isBntpayLink := strings.HasPrefix(lower, "bntpay.com/") ||
		strings.HasPrefix(lower, "www.bntpay.com/") ||
		strings.HasPrefix(lower, "https://bntpay.com/") ||
		strings.HasPrefix(lower, "http://bntpay.com/") ||
		strings.HasPrefix(lower, "https://www.bntpay.com/") ||
		strings.HasPrefix(lower, "http://www.bntpay.com/")
	if !isBlocknetURI && !isBntpayLink {
		return nil, false, nil
	}

	link := raw
	if isBntpayLink && !strings.Contains(lower, "://") {
		link = "https://" + raw
	}

	u, err := url.Parse(link)
	if err != nil {
		return nil, true, fmt.Errorf("invalid payment link: %w", err)
	}

	var address string
	switch strings.ToLower(u.Scheme) {
	case "blocknet":
		address = strings.TrimSpace(u.Host)
		if address == "" {
			address = strings.TrimSpace(u.Opaque)
		}
		if address == "" {
			address = strings.Trim(strings.TrimSpace(u.Path), "/")
		}
	case "http", "https":
		host := strings.ToLower(u.Hostname())
		if host != "bntpay.com" && host != "www.bntpay.com" {
			return nil, true, fmt.Errorf("invalid bntpay host: %s", u.Hostname())
		}
		address = strings.Trim(strings.TrimSpace(u.Path), "/")
	default:
		return nil, true, fmt.Errorf("unsupported payment link scheme: %s", u.Scheme)
	}

	if address == "" {
		return nil, true, fmt.Errorf("payment link missing address")
	}

	query := u.Query()
	amount := strings.TrimSpace(query.Get("amount"))
	if amount == "" {
		return nil, true, fmt.Errorf("payment link missing amount")
	}

	args := []string{address, amount}
	if memo := query.Get("memo"); memo != "" {
		args = append(args, memo)
	}
	return args, true, nil
}
