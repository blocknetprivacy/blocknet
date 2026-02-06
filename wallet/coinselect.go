package wallet

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sort"
)

var (
	ErrInsufficientFunds  = errors.New("insufficient funds")
	ErrNoSpendableOutputs = errors.New("no spendable outputs")
)

// SelectInputs chooses outputs to spend for a given target amount
// Uses a combination of strategies to minimize fees and maximize privacy
func SelectInputs(available []*OwnedOutput, targetAmount uint64) ([]*OwnedOutput, error) {
	if len(available) == 0 {
		return nil, ErrNoSpendableOutputs
	}

	// Filter to only unspent
	var spendable []*OwnedOutput
	var totalAvailable uint64
	for _, out := range available {
		if !out.Spent {
			spendable = append(spendable, out)
			totalAvailable += out.Amount
		}
	}

	if totalAvailable < targetAmount {
		return nil, ErrInsufficientFunds
	}

	// Try exact match first (best for privacy - no change output)
	if exact := findExactMatch(spendable, targetAmount); exact != nil {
		return exact, nil
	}

	// Try smallest-first selection (minimizes number of inputs)
	selected := selectSmallestFirst(spendable, targetAmount)
	if selected != nil {
		return selected, nil
	}

	// Fallback: use all inputs if needed
	return spendable, nil
}

// findExactMatch tries to find a combination that exactly matches target
// Only checks single outputs and pairs for efficiency
func findExactMatch(outputs []*OwnedOutput, target uint64) []*OwnedOutput {
	// Check single outputs
	for _, out := range outputs {
		if out.Amount == target {
			return []*OwnedOutput{out}
		}
	}

	// Check pairs
	for i, a := range outputs {
		for j, b := range outputs {
			if i != j && a.Amount+b.Amount == target {
				return []*OwnedOutput{a, b}
			}
		}
	}

	return nil
}

// selectSmallestFirst sorts by amount ascending and picks until target is reached
// This tends to consolidate small UTXOs
func selectSmallestFirst(outputs []*OwnedOutput, target uint64) []*OwnedOutput {
	// Sort by amount (smallest first)
	sorted := make([]*OwnedOutput, len(outputs))
	copy(sorted, outputs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Amount < sorted[j].Amount
	})

	var selected []*OwnedOutput
	var total uint64

	for _, out := range sorted {
		selected = append(selected, out)
		total += out.Amount
		if total >= target {
			return selected
		}
	}

	return nil // shouldn't reach here if totalAvailable >= target
}

// SelectInputsWithDecoys is an alternative that also considers decoy availability
// Prefers outputs that have good decoy options in the UTXO set
func SelectInputsWithDecoys(
	available []*OwnedOutput,
	targetAmount uint64,
	countDecoys func(commitment [32]byte) int,
	minDecoys int,
) ([]*OwnedOutput, error) {
	if len(available) == 0 {
		return nil, ErrNoSpendableOutputs
	}

	// Filter to spendable outputs with sufficient decoys
	var spendable []*OwnedOutput
	var totalAvailable uint64
	for _, out := range available {
		if !out.Spent && countDecoys(out.Commitment) >= minDecoys {
			spendable = append(spendable, out)
			totalAvailable += out.Amount
		}
	}

	if totalAvailable < targetAmount {
		return nil, ErrInsufficientFunds
	}

	return SelectInputs(spendable, targetAmount)
}

// RandomShuffle shuffles outputs using cryptographically secure randomness
// This prevents output order from revealing which is the change output
func RandomShuffle(outputs []*OwnedOutput) {
	n := len(outputs)
	if n <= 1 {
		return
	}

	// Fisher-Yates shuffle with crypto/rand
	for i := n - 1; i > 0; i-- {
		// Generate random index j where 0 <= j <= i
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			// If crypto/rand fails, don't shuffle (fail safe)
			return
		}
		j := int(binary.LittleEndian.Uint64(buf[:]) % uint64(i+1))
		outputs[i], outputs[j] = outputs[j], outputs[i]
	}
}
