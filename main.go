package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

var (
	Version = ""
	NoColor bool
)

func main() {
	args := filterFlags(os.Args[1:])
	if len(args) == 0 {
		if err := cmdStatus(nil); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// noArgs wraps a command that takes no arguments.
	noArgs := func(usage string, fn func([]string) error) error {
		if err := ExtraArgs(args[1:], 0, usage); err != nil {
			return err
		}
		return fn(args[1:])
	}

	var err error
	switch args[0] {
	case "start":
		err = cmdStart(args[1:])
	case "stop":
		err = cmdStop(args[1:])
	case "restart":
		err = cmdRestart(args[1:])
	case "status":
		err = cmdStatus(args[1:])
	case "attach":
		err = cmdAttach(args[1:])
	case "enable":
		err = cmdEnable(args[1:])
	case "disable":
		err = cmdDisable(args[1:])
	case "upgrade":
		err = cmdUpgrade(args[1:])
	case "list":
		err = cmdList(args[1:])
	case "install":
		err = cmdInstall(args[1:])
	case "uninstall":
		err = cmdUninstall(args[1:])
	case "use":
		err = cmdUse(args[1:])
	case "logs":
		err = cmdLogs(args[1:])
	case "cleanup":
		err = cmdCleanup(args[1:])
	case "doctor":
		err = noArgs("blocknet doctor", cmdDoctor)
	case "setup":
		err = noArgs("blocknet setup", cmdSetup)
	case "completions":
		if err = ExtraArgs(args[1:], 1, "blocknet completions <bash|zsh|fish>"); err == nil {
			err = cmdCompletions(args[1:])
		}
	case "config":
		err = cmdConfig(args[1:])
	case "watchdog":
		err = cmdWatchdog(args[1:])
	case "version", "--version", "-v":
		err = noArgs("blocknet version", func([]string) error {
			green, _, _, _, _, reset := Palette(NoColor)
			fmt.Printf("\n%s\n\n", SectionHead("blocknet "+green+displayVersion()+reset, NoColor))
			return nil
		})
	case "help", "--help", "-h":
		err = noArgs("blocknet help", func([]string) error {
			printUsage()
			return nil
		})
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command: %s\n", args[0])
		fmt.Fprintf(os.Stderr, "Run 'blocknet help' for the list.\n")
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// displayVersion is the build version with exactly one leading "v" (release
// builds set Version from the git tag, "v1.1.0"), or "dev" for a build
// without one.
func displayVersion() string {
	v := strings.TrimLeft(strings.TrimSpace(Version), "vV")
	if v == "" {
		return "dev"
	}
	return "v" + v
}

func printUsage() {
	_, _, _, _, dim, reset := Palette(NoColor)

	h := func(s string) { fmt.Printf("\n%s\n\n", SectionHead(s, NoColor)) }
	row := func(cmd, desc string) {
		fmt.Printf("  %s %s%s%s\n", PadRight(cmd, 32), dim, desc, reset)
	}

	fmt.Printf("\n%s\n\n", SectionHead("blocknet "+displayVersion(), NoColor))
	fmt.Printf("  Usage: blocknet <command> [args]\n")
	h("Lifecycle")
	row("start [mainnet|testnet]", "Start managed cores")
	row("stop [mainnet|testnet]", "Stop managed cores")
	row("restart [mainnet|testnet]", "Restart managed cores")
	row("enable <mainnet|testnet>", "Enable auto-start for a core")
	row("disable <mainnet|testnet>", "Disable auto-start for a core")
	row("status", "Show status of all managed cores")
	h("Interactive")
	row("attach [mainnet|testnet]", "Open interactive CLI session")
	row("logs [mainnet|testnet]", "Follow core log output")
	h("Versions")
	row("list", "List available and installed core versions")
	row("install <version>", "Download a core version")
	row("uninstall <version>", "Remove a core version")
	row("use <version> [mainnet|testnet]", "Set which core version to use")
	row("upgrade", "Upgrade blocknet and the core to the latest release")
	row("cleanup", "Remove core versions not in use")
	h("Maintenance")
	row("setup", "First-run setup wizard")
	row("watchdog [mainnet|testnet]", "Watch core health, restart on crash")
	row("doctor", "Check system health and diagnose issues")
	row("config", "Print current configuration")
	row("completions <shell>", "Generate shell completions (bash/zsh/fish)")
	row("version", "Print version")
	row("help", "Show this help")
	h("Flags")
	row("--nocolor", "Disable colored output (or set NO_COLOR=1)")
	fmt.Println()
}

func filterFlags(args []string) []string {
	// No color when NO_COLOR is set or when output goes to a pipe or a file.
	if os.Getenv("NO_COLOR") != "" || !term.IsTerminal(int(os.Stdout.Fd())) {
		NoColor = true
	}
	var filtered []string
	for _, a := range args {
		switch a {
		case "--nocolor", "--no-color":
			NoColor = true
		default:
			filtered = append(filtered, a)
		}
	}
	return filtered
}
