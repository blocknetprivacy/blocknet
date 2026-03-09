package main

import "fmt"

type Network string

const (
	Mainnet Network = "mainnet"
	Testnet Network = "testnet"
)

func ParseNetwork(s string) (Network, error) {
	switch s {
	case "mainnet", "":
		return Mainnet, nil
	case "testnet":
		return Testnet, nil
	default:
		return "", fmt.Errorf("invalid network %q: must be mainnet or testnet", s)
	}
}

// ResolveNetwork picks the target network from an explicit argument. If arg is
// empty it falls back to whichever single network is in the running set. When
// both are running and no arg is given it returns an error.
func ResolveNetwork(arg string, running []Network) (Network, error) {
	if arg != "" {
		return ParseNetwork(arg)
	}
	switch len(running) {
	case 0:
		return Mainnet, nil
	case 1:
		return running[0], nil
	default:
		return "", fmt.Errorf("multiple cores running — specify mainnet or testnet")
	}
}
