package main

import "fmt"

// The command lists here must match the dispatch switch in main.go. Version
// candidates come from 'blocknet --nocolor list': only the first column of
// rows that look like a version (v1.2.3, 0.13.4 or nightly) is used, so headings,
// table rules and status text never show up as completions.

func printBashCompletion() {
	fmt.Print(`_blocknet_versions() {
    blocknet --nocolor list 2>/dev/null | awk '$1 ~ /^(v?[0-9]|nightly$)/ {print $1}'
}

_blocknet() {
    local cur cmd commands networks
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    cmd="${COMP_WORDS[1]}"

    commands="start stop restart status attach logs enable disable watchdog list install uninstall use upgrade cleanup setup doctor config completions version help"
    networks="mainnet testnet"

    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return 0
    fi

    case "$cmd" in
        start|stop|restart|attach|logs|enable|disable|watchdog)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$networks" -- "$cur") )
            fi
            ;;
        use)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "latest $(_blocknet_versions)" -- "$cur") )
            elif [ "$COMP_CWORD" -eq 3 ]; then
                COMPREPLY=( $(compgen -W "$networks" -- "$cur") )
            fi
            ;;
        install|uninstall)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "latest $(_blocknet_versions)" -- "$cur") )
            fi
            ;;
        completions)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            fi
            ;;
    esac
    return 0
}
complete -F _blocknet blocknet
complete -F _blocknet bnt
`)
}

// The zsh script works both ways it can be loaded: through
// eval "$(blocknet completions zsh)" (what setup installs), where it
// registers itself with compdef, and saved as _blocknet in a directory on
// $fpath, where compinit autoloads it and the last line runs it.
func printZshCompletion() {
	fmt.Print(`#compdef blocknet bnt

_blocknet_versions() {
    blocknet --nocolor list 2>/dev/null | awk '$1 ~ /^(v?[0-9]|nightly$)/ {print $1}'
}

_blocknet() {
    local -a commands networks versions shells
    commands=(
        'start:Start managed cores'
        'stop:Stop managed cores'
        'restart:Restart managed cores'
        'status:Show status of all managed cores'
        'attach:Open interactive CLI session'
        'logs:Follow core log output'
        'enable:Enable auto-start for a core'
        'disable:Disable auto-start for a core'
        'watchdog:Monitor daemon health, restart on crash'
        'list:List available and installed core versions'
        'install:Download a core version'
        'uninstall:Remove a core version'
        'use:Set which core version to use'
        'upgrade:Download and apply latest core release'
        'cleanup:Remove core versions not in use'
        'setup:First-run setup wizard'
        'doctor:Check system health and diagnose issues'
        'config:Print current configuration'
        'completions:Generate shell completions'
        'version:Print version'
        'help:Show help'
    )
    networks=(mainnet testnet)
    shells=(bash zsh fish)

    if (( CURRENT == 2 )); then
        _describe 'command' commands
        return
    fi

    case "$words[2]" in
        start|stop|restart|attach|logs|enable|disable|watchdog)
            (( CURRENT == 3 )) && _describe 'network' networks
            ;;
        use)
            if (( CURRENT == 3 )); then
                versions=(latest ${(f)"$(_blocknet_versions)"})
                _describe 'version' versions
            elif (( CURRENT == 4 )); then
                _describe 'network' networks
            fi
            ;;
        install|uninstall)
            if (( CURRENT == 3 )); then
                versions=(latest ${(f)"$(_blocknet_versions)"})
                _describe 'version' versions
            fi
            ;;
        completions)
            (( CURRENT == 3 )) && _describe 'shell' shells
            ;;
    esac
}

if [[ "${zsh_eval_context[-1]}" == loadautofunc ]]; then
    _blocknet "$@"
else
    (( $+functions[compdef] )) || { autoload -Uz compinit && compinit; }
    compdef _blocknet blocknet bnt
fi
`)
}

func printFishCompletion() {
	fmt.Print(`# Fish completions for blocknet
complete -c blocknet -f
complete -c bnt -w blocknet

function __blocknet_versions
    blocknet --nocolor list 2>/dev/null | awk '$1 ~ /^(v?[0-9]|nightly$)/ {print $1}'
end

# True when the cursor is on argument N (first argument) of one of the
# subcommands given after it.
function __blocknet_arg
    set -l words (commandline -opc)
    test (count $words) -ge 2; or return 1
    contains -- $words[2] $argv[2..-1]; or return 1
    test (count $words) -eq (math $argv[1] + 1)
end

# Commands
complete -c blocknet -n '__fish_use_subcommand' -a start -d 'Start managed cores'
complete -c blocknet -n '__fish_use_subcommand' -a stop -d 'Stop managed cores'
complete -c blocknet -n '__fish_use_subcommand' -a restart -d 'Restart managed cores'
complete -c blocknet -n '__fish_use_subcommand' -a status -d 'Show status of all managed cores'
complete -c blocknet -n '__fish_use_subcommand' -a attach -d 'Open interactive CLI session'
complete -c blocknet -n '__fish_use_subcommand' -a logs -d 'Follow core log output'
complete -c blocknet -n '__fish_use_subcommand' -a enable -d 'Enable auto-start for a core'
complete -c blocknet -n '__fish_use_subcommand' -a disable -d 'Disable auto-start for a core'
complete -c blocknet -n '__fish_use_subcommand' -a watchdog -d 'Monitor daemon health, restart on crash'
complete -c blocknet -n '__fish_use_subcommand' -a list -d 'List available and installed core versions'
complete -c blocknet -n '__fish_use_subcommand' -a install -d 'Download a core version'
complete -c blocknet -n '__fish_use_subcommand' -a uninstall -d 'Remove a core version'
complete -c blocknet -n '__fish_use_subcommand' -a use -d 'Set which core version to use'
complete -c blocknet -n '__fish_use_subcommand' -a upgrade -d 'Download and apply latest core release'
complete -c blocknet -n '__fish_use_subcommand' -a cleanup -d 'Remove core versions not in use'
complete -c blocknet -n '__fish_use_subcommand' -a setup -d 'First-run setup wizard'
complete -c blocknet -n '__fish_use_subcommand' -a doctor -d 'Check system health and diagnose issues'
complete -c blocknet -n '__fish_use_subcommand' -a config -d 'Print current configuration'
complete -c blocknet -n '__fish_use_subcommand' -a completions -d 'Generate shell completions'
complete -c blocknet -n '__fish_use_subcommand' -a version -d 'Print version'
complete -c blocknet -n '__fish_use_subcommand' -a help -d 'Show help'

# Network arguments
complete -c blocknet -n '__blocknet_arg 1 start stop restart attach logs enable disable watchdog' -a 'mainnet testnet'
complete -c blocknet -n '__blocknet_arg 2 use' -a 'mainnet testnet'

# Version arguments
complete -c blocknet -n '__blocknet_arg 1 install uninstall use' -a 'latest (__blocknet_versions)'

# Shells
complete -c blocknet -n '__blocknet_arg 1 completions' -a 'bash zsh fish'
`)
}

func cmdCompletions(args []string) error {
	if err := ExtraArgs(args, 1, "blocknet completions <bash|zsh|fish>"); err != nil {
		return err
	}
	if len(args) == 0 {
		fmt.Printf("\n%s\n\n", SectionHead("Completions", NoColor))
		fmt.Println("  Usage: blocknet completions <bash|zsh|fish>")
		fmt.Println()
		fmt.Println("  bash:  eval \"$(blocknet completions bash)\"")
		fmt.Println("  zsh:   eval \"$(blocknet completions zsh)\"")
		fmt.Println("  fish:  blocknet completions fish | source")
		fmt.Println()
		fmt.Println("  To keep them, add the line to your shell's rc file")
		fmt.Println("  (~/.bashrc, ~/.zshrc or ~/.config/fish/config.fish).")
		fmt.Println("  For zsh you can also save the output as _blocknet in a folder on $fpath.")
		fmt.Println()
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
		return fmt.Errorf("unsupported shell: %s (usage: blocknet completions <bash|zsh|fish>)", args[0])
	}
	return nil
}
