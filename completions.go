package main

import "fmt"

func printBashCompletion() {
	fmt.Print(`_blocknet() {
    local cur prev commands networks
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="start stop restart status attach logs enable disable list install uninstall use upgrade cleanup setup doctor config version help"
    networks="mainnet testnet"

    case "$prev" in
        start|stop|restart|attach|logs|enable|disable)
            COMPREPLY=( $(compgen -W "$networks" -- "$cur") )
            return 0
            ;;
        use)
            local versions=$(blocknet list 2>/dev/null | awk '{print $1}' | grep -v '^version$' | grep -v '^─')
            COMPREPLY=( $(compgen -W "$versions" -- "$cur") )
            return 0
            ;;
        install|uninstall)
            local versions=$(blocknet list 2>/dev/null | awk '{print $1}' | grep -v '^version$' | grep -v '^─')
            COMPREPLY=( $(compgen -W "$versions latest nightly" -- "$cur") )
            return 0
            ;;
        blocknet)
            COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
            return 0
            ;;
    esac

    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
    fi
}
complete -F _blocknet blocknet
complete -F _blocknet bnt
`)
}

func printZshCompletion() {
	fmt.Print(`#compdef blocknet bnt

_blocknet() {
    local -a commands networks
    commands=(
        'start:Start managed cores'
        'stop:Stop managed cores'
        'restart:Restart managed cores'
        'status:Show status of all managed cores'
        'attach:Open interactive CLI session'
        'logs:Follow core log output'
        'enable:Enable auto-start for a core'
        'disable:Disable auto-start for a core'
        'list:List available and installed core versions'
        'install:Download a core version'
        'uninstall:Remove a core version'
        'use:Set which core version to use'
        'upgrade:Download and apply latest core release'
        'cleanup:Remove core versions not in use'
        'setup:First-run setup wizard'
        'doctor:Check system health and diagnose issues'
        'config:Print current configuration'
        'version:Print version'
        'help:Show help'
    )
    networks=(mainnet testnet)

    case "$words[2]" in
        start|stop|restart|attach|logs|enable|disable)
            _describe 'network' networks
            ;;
        install|uninstall)
            _message 'version (e.g. latest, nightly, v1.0.0)'
            ;;
        use)
            _message 'version [network]'
            ;;
        *)
            _describe 'command' commands
            ;;
    esac
}

_blocknet "$@"
`)
}

func printFishCompletion() {
	fmt.Print(`# Fish completions for blocknet
complete -c blocknet -f
complete -c bnt -w blocknet

# Commands
complete -c blocknet -n '__fish_use_subcommand' -a start -d 'Start managed cores'
complete -c blocknet -n '__fish_use_subcommand' -a stop -d 'Stop managed cores'
complete -c blocknet -n '__fish_use_subcommand' -a restart -d 'Restart managed cores'
complete -c blocknet -n '__fish_use_subcommand' -a status -d 'Show status of all managed cores'
complete -c blocknet -n '__fish_use_subcommand' -a attach -d 'Open interactive CLI session'
complete -c blocknet -n '__fish_use_subcommand' -a logs -d 'Follow core log output'
complete -c blocknet -n '__fish_use_subcommand' -a enable -d 'Enable auto-start for a core'
complete -c blocknet -n '__fish_use_subcommand' -a disable -d 'Disable auto-start for a core'
complete -c blocknet -n '__fish_use_subcommand' -a list -d 'List available and installed core versions'
complete -c blocknet -n '__fish_use_subcommand' -a install -d 'Download a core version'
complete -c blocknet -n '__fish_use_subcommand' -a uninstall -d 'Remove a core version'
complete -c blocknet -n '__fish_use_subcommand' -a use -d 'Set which core version to use'
complete -c blocknet -n '__fish_use_subcommand' -a upgrade -d 'Download and apply latest core release'
complete -c blocknet -n '__fish_use_subcommand' -a cleanup -d 'Remove core versions not in use'
complete -c blocknet -n '__fish_use_subcommand' -a setup -d 'First-run setup wizard'
complete -c blocknet -n '__fish_use_subcommand' -a doctor -d 'Check system health and diagnose issues'
complete -c blocknet -n '__fish_use_subcommand' -a config -d 'Print current configuration'
complete -c blocknet -n '__fish_use_subcommand' -a version -d 'Print version'
complete -c blocknet -n '__fish_use_subcommand' -a help -d 'Show help'

# Network arguments
for cmd in start stop restart attach logs enable disable
    complete -c blocknet -n "__fish_seen_subcommand_from $cmd" -a 'mainnet testnet'
end

# Version arguments
for cmd in install uninstall
    complete -c blocknet -n "__fish_seen_subcommand_from $cmd" -a 'latest nightly'
end
`)
}

func cmdCompletions(args []string) error {
	if len(args) == 0 {
		fmt.Println("Usage: blocknet completions <bash|zsh|fish>")
		fmt.Println()
		fmt.Println("  Generate shell completion scripts.")
		fmt.Println()
		fmt.Println("  bash:  eval \"$(blocknet completions bash)\"")
		fmt.Println("  zsh:   eval \"$(blocknet completions zsh)\"")
		fmt.Println("  fish:  blocknet completions fish | source")
		fmt.Println()
		fmt.Println("  To make permanent, add the eval line to your shell's rc file")
		fmt.Println("  (~/.bashrc, ~/.zshrc, or ~/.config/fish/config.fish).")
		return nil
	}

	switch args[0] {
	case "bash":
		printBashCompletion()
	case "zsh":
		printZshCompletion()
	case "fish":
		printFishCompletion()
	default:
		return fmt.Errorf("unsupported shell: %s (use bash, zsh, or fish)", args[0])
	}
	return nil
}
