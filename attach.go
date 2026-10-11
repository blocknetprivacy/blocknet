package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

const (
	defaultAPITimeout = 30 * time.Second
	patienceThreshold = 5 * time.Second

	// syncLagWarnBlocks is how far behind the network tip the wallet must be
	// before we caution that the displayed balance may be incomplete. A node
	// routinely sits ~1 block behind for a moment right after a new block is
	// mined, so this small floor suppresses that normal case and avoids
	// pestering the user, while a genuine backlog (a node that was offline, or
	// is still doing its initial sync) still trips the warning.
	syncLagWarnBlocks = 2
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
			fmt.Fprintf(os.Stderr, "\n%s\n\n  %v\n", ErrorHead("Error", s.noColor), capitalize(err.Error()))
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

	if a, ok := commandArity[cmd]; ok {
		if err := ExtraArgs(args, a.max, a.usage); err != nil {
			return err
		}
	}

	if needsUnlockedWallet[cmd] {
		if err := s.ensureUnlocked(); err != nil {
			return err
		}
	}

	switch cmd {
	case "help", "?":
		return s.cmdHelp(args)
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
	case "explore", "exp":
		return s.cmdExplore(args)
	case "mempool":
		return s.cmdExplore([]string{"mempool"})
	case "purge":
		return s.cmdPurge()
	case "certify":
		return s.cmdCertify()
	case "save-checkpoints":
		return s.cmdSaveCheckpoints()
	case "load-checkpoints":
		return s.cmdLoadCheckpoints()
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

// arity is the most arguments a command takes and its usage line.
type arity struct {
	max   int
	usage string
}

// commandArity holds every fixed-arity command and alias, so extra arguments
// are rejected in one place. Commands that take free text (send with its memo)
// or read their input from prompts (sign, verify) are left out.
var commandArity = map[string]arity{
	"help": {1, "help [command]"}, "?": {1, "help [command]"},
	"version": {0, "version"},
	"status":  {0, "status"},
	"balance": {0, "balance"}, "bal": {0, "balance"}, "b": {0, "balance"},
	"address": {0, "address"}, "addr": {0, "address"}, "a": {0, "address"},
	"history": {0, "history"}, "hist": {0, "history"}, "h": {0, "history"},
	"outputs": {2, outputsUsage}, "outs": {2, outputsUsage}, "out": {2, outputsUsage},
	"peers":       {0, "peers"},
	"banned":      {0, "banned"},
	"export-peer": {0, "export-peer"},
	"mining":      {2, miningUsage},
	"load":        {0, "load"},
	"unload":      {0, "unload"},
	"sync":        {0, "sync"}, "scan": {0, "sync"},
	"seed":     {0, "seed"},
	"import":   {0, "import"},
	"viewkeys": {0, "viewkeys"},
	"prove":    {1, "prove <txid>"},
	"lock":     {0, "lock"},
	"unlock":   {0, "unlock"},
	"audit":    {0, "audit"},
	"explore":  {1, exploreUsage}, "exp": {1, exploreUsage},
	"mempool":          {0, "mempool"},
	"purge":            {0, "purge"},
	"certify":          {0, "certify"},
	"save-checkpoints": {0, "save-checkpoints"},
	"load-checkpoints": {0, "load-checkpoints"},
	"license":          {0, "license"},
	"about":            {0, "about"},
	"quit":             {0, "quit"}, "exit": {0, "quit"}, "q": {0, "quit"},
}

// Usage lines shared by the arity table and the commands themselves.
const (
	outputsUsage = "outputs [spent|unspent|pending] [index] | outputs tx <txid>[:<index>]"
	miningUsage  = "mining [start|stop|threads [N]]"
	exploreUsage = "explore <height|hash|mempool>"
)

// needsUnlockedWallet lists the commands whose core endpoints refuse to run
// while the wallet is locked. Node commands, load/unload, lock/unlock,
// import, verify and purge do not need an unlocked wallet.
var needsUnlockedWallet = map[string]bool{
	"balance": true, "bal": true, "b": true,
	"address": true, "addr": true, "a": true,
	"send": true, "sign": true,
	"history": true, "hist": true, "h": true,
	"outputs": true, "outs": true, "out": true,
	"seed": true, "viewkeys": true, "prove": true, "audit": true,
	"sync": true, "scan": true,
}

// errLocked is the error every command returns while the wallet is locked.
var errLocked = fmt.Errorf("wallet is locked, use 'unlock' first")

// coreLocked asks the core whether the loaded wallet is locked. It returns
// an error when the core cannot say (no wallet loaded, core down).
func (s *AttachSession) coreLocked() (bool, error) {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()
	_, err := s.client.Get(ctx, "/api/wallet/balance")
	if err == nil {
		s.locked = false
		return false, nil
	}
	if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == 403 && strings.Contains(apiErr.Message, "locked") {
		s.locked = true
		return true, nil
	}
	return false, err
}

// ensureUnlocked stops a wallet command early when the wallet is locked, so
// the user is not asked for input that the core will refuse. The local flag
// can be stale (another client may have unlocked), so it is checked with the
// core before refusing.
func (s *AttachSession) ensureUnlocked() error {
	if !s.locked {
		return nil
	}
	locked, err := s.coreLocked()
	if err != nil {
		return s.handleAPIError(err)
	}
	if locked {
		return errLocked
	}
	return nil
}

// capitalize upper-cases the first letter of an error message for display.
// Go error strings stay lowercase; only the printed "# Error" block changes.
func capitalize(msg string) string {
	r, size := utf8.DecodeRuneInString(msg)
	if r == utf8.RuneError {
		return msg
	}
	return string(unicode.ToUpper(r)) + msg[size:]
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
			return errLocked
		}
		return fmt.Errorf("%s", apiErr.Message)
	}
	return err
}

// bannerInner is the room for the title on the banner's middle line: the bar
// is 28 blocks wide between its end caps and keeps 4 blocks on each side.
const bannerInner = 22

// bannerTitle is "BLOCKNET <version>", with the version cut short so the title
// always leaves at least a 1-column margin on each side of the bar.
func bannerTitle() string {
	const prefix = "BLOCKNET "
	ver := []rune(displayVersion())
	if room := bannerInner - 2 - len(prefix); len(ver) > room {
		ver = append(ver[:room-1], '…')
	}
	return prefix + string(ver)
}

// printLogo renders the BLOCKNET banner, matching the core's interactive menu so
// the attach session feels like the same product. The accent follows the network.
func (s *AttachSession) printLogo() {
	accent := NetColor(s.network, s.noColor)
	_, _, _, _, _, reset := Palette(s.noColor)

	const inner = bannerInner
	title := bannerTitle()
	pad := max(inner-VisibleLen(title), 2)
	left := (pad + 1) / 2
	right := pad - left

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
		"  ████" + strings.Repeat(" ", left) + title + strings.Repeat(" ", right) + "████",
		`  ▀████████████████████████████▀`,
	}

	fmt.Println()
	for _, line := range logo {
		fmt.Printf("%s%s%s\n", accent, line, reset)
		time.Sleep(40 * time.Millisecond)
	}
	fmt.Println()
}

type apiResult struct {
	raw json.RawMessage
	err error
}

func (s *AttachSession) fetchAll(ctx context.Context, paths ...string) []apiResult {
	out := make([]apiResult, len(paths))
	var wg sync.WaitGroup
	for i, path := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i].raw, out[i].err = s.client.Get(ctx, path)
		}()
	}
	wg.Wait()
	return out
}

func (s *AttachSession) printWelcome() {
	ctx, cancel := withPatience(defaultAPITimeout)
	defer cancel()

	fetched := make(chan []apiResult, 1)
	go func() {
		fetched <- s.fetchAll(ctx, "/api/status", "/api/wallet/balance", "/api/wallet/address")
	}()
	s.printLogo()
	res := <-fetched
	if apiErr, ok := res[1].err.(*APIError); ok && apiErr.StatusCode == 403 {
		s.locked = true
	}

	st := res[0]
	if st.err != nil {
		fmt.Printf("  Connected to %s (status unavailable)\n", s.network)
		fmt.Println("  Type 'help' for available commands")
		printUpgradeNotice(builtinUpgradeNotice, s.noColor)
		return
	}

	var status struct {
		Height uint64 `json:"chain_height"`
	}
	json.Unmarshal(st.raw, &status)

	if b := res[1]; b.err == nil {
		var bal struct {
			Spendable uint64 `json:"spendable"`
			Pending   uint64 `json:"pending"`
		}
		json.Unmarshal(b.raw, &bal)

		raw2 := res[2].raw
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

		fmt.Printf("  Address: %s\n", addr.Address)
		fmt.Printf("  Balance: %s\n", balStr)
	}

	fmt.Printf("  Height:  %d\n", status.Height)
	if s.locked {
		fmt.Println("  Wallet:  locked (use 'unlock')")
	}
	fmt.Println()
	fmt.Println("  Type 'help' for available commands")
	printUpgradeNotice(upgradeNoticeFrom(st.raw), s.noColor)
}

func (s *AttachSession) listenEvents() {
	const minBackoff, maxBackoff = 100 * time.Millisecond, 5 * time.Second
	backoff := minBackoff
	for {
		ctx := context.Background()
		start := time.Now()
		_ = s.client.SSE(ctx, "/api/events", func(event, data string) {
			if event == "mined_block" {
				var block struct {
					Height uint64 `json:"height"`
				}
				if json.Unmarshal([]byte(data), &block) == nil {
					fmt.Printf("\n%s\n\n", SectionHead(fmt.Sprintf("Mined block %d", block.Height), s.noColor))
					fmt.Printf("  https://explorer.blocknetcrypto.com/block/%d\n", block.Height)
				}
			}
		})
		if time.Since(start) > maxBackoff {
			backoff = minBackoff
		}
		time.Sleep(backoff)
		backoff = min(backoff*2, maxBackoff)
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
