package main

import (
	"fmt"
	"os"
)

var (
	Version = "1.0.0"
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
		err = cmdDoctor(args[1:])
	case "setup":
		err = cmdSetup(args[1:])
	case "completions":
		err = cmdCompletions(args[1:])
	case "config":
		err = cmdConfig(args[1:])
	case "version", "--version", "-v":
		green, reset := "\033[38;2;170;255;0m", "\033[0m"
		if NoColor {
			green, reset = "", ""
		}
		fmt.Printf("\n%s#%s blocknet %s%s%s\n\n", green, reset, green, Version, reset)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	dim, reset := "\033[38;2;160;160;160m", "\033[0m"
	if NoColor {
		dim, reset = "", ""
	}

	h := func(s string) string { return fmt.Sprintf("\n%s\n", SectionHead(s, NoColor)) }
	d := func(s string) string { return fmt.Sprintf("%s%s%s", dim, s, reset) }

	fmt.Printf("\n%s\n\n", SectionHead("blocknet "+Version, NoColor))
	fmt.Printf("  Usage: blocknet <command> [args]\n")
	fmt.Print(h("Lifecycle"))
	fmt.Printf("  start [mainnet|testnet]     %s\n", d("Start managed cores"))
	fmt.Printf("  stop [mainnet|testnet]      %s\n", d("Stop managed cores"))
	fmt.Printf("  restart [mainnet|testnet]   %s\n", d("Restart managed cores"))
	fmt.Printf("  enable [mainnet|testnet]    %s\n", d("Enable auto-start for a core"))
	fmt.Printf("  disable [mainnet|testnet]   %s\n", d("Disable auto-start for a core"))
	fmt.Printf("  status                      %s\n", d("Show status of all managed cores"))
	fmt.Print(h("Interactive"))
	fmt.Printf("  attach [mainnet|testnet]    %s\n", d("Open interactive CLI session"))
	fmt.Printf("  logs [mainnet|testnet]      %s\n", d("Follow core log output"))
	fmt.Print(h("Versions"))
	fmt.Printf("  list                        %s\n", d("List available and installed core versions"))
	fmt.Printf("  install <version>           %s\n", d("Download a core version"))
	fmt.Printf("  uninstall <version>         %s\n", d("Remove a core version"))
	fmt.Printf("  use <version> [network]     %s\n", d("Set which core version to use"))
	fmt.Printf("  upgrade                     %s\n", d("Download and apply latest core release"))
	fmt.Printf("  cleanup                     %s\n", d("Remove core versions not in use"))
	fmt.Print(h("Maintenance"))
	fmt.Printf("  setup                       %s\n", d("First-run setup wizard"))
	fmt.Printf("  doctor                      %s\n", d("Check system health and diagnose issues"))
	fmt.Printf("  config                      %s\n", d("Print current configuration"))
	fmt.Printf("  completions <shell>         %s\n", d("Generate shell completions (bash/zsh/fish)"))
	fmt.Printf("  version                     %s\n", d("Print version"))
	fmt.Printf("  help                        %s\n", d("Show this help"))
	fmt.Print(h("Flags"))
	fmt.Printf("  --nocolor                   %s\n\n", d("Disable colored output"))
}

func filterFlags(args []string) []string {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
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
