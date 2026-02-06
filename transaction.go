package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"

	"golang.org/x/crypto/sha3"
)

// TxOutput represents a transaction output (UTXO)
type TxOutput struct {
	// Commitment is a Pedersen commitment to the amount (hides value)
	Commitment [32]byte `json:"commitment"`

	// PublicKey is the one-time stealth address for this output
	PublicKey [32]byte `json:"public_key"`

	// RangeProof proves the committed amount is in valid range [0, 2^64)
	RangeProof []byte `json:"range_proof,omitempty"`

	// EncryptedAmount is the amount encrypted with ECDH shared secret
	// The recipient can decrypt this with their view key
	EncryptedAmount [8]byte `json:"encrypted_amount"`
}

// OwnedOutput contains the secret data the owner needs to spend an output
type OwnedOutput struct {
	UTXO     *UTXO
	Amount   uint64
	Blinding [32]byte
	PrivKey  [32]byte // One-time private key to spend
}

// TxInput references a previous output being spent
type TxInput struct {
	// KeyImage is used to prevent double-spending without revealing which output is spent
	KeyImage [32]byte `json:"key_image"`

	// RingMembers are public keys used in the ring signature (includes real + decoys)
	RingMembers [][32]byte `json:"ring_members"`

	// RingCommitments are the Pedersen commitments for each ring member
	// Used for RingCT commitment linking
	RingCommitments [][32]byte `json:"ring_commitments"`

	// PseudoOutput is a commitment to the same amount as the real input
	// but with a different blinding factor. Used for balance verification.
	PseudoOutput [32]byte `json:"pseudo_output"`

	// RingSignature is a RingCT CLSAG signature proving:
	// 1. Ownership of one ring member's private key
	// 2. PseudoOutput commits to the same amount as that ring member
	RingSignature []byte `json:"ring_signature"`
}

// Transaction represents a privacy-preserving transaction
type Transaction struct {
	// Version for future upgrades
	Version uint8 `json:"version"`

	// Inputs being spent
	Inputs []TxInput `json:"inputs"`

	// Outputs being created
	Outputs []TxOutput `json:"outputs"`

	// Fee is public (can't hide this without complexity)
	Fee uint64 `json:"fee"`

	// TxPublicKey is used for stealth address derivation
	TxPublicKey [32]byte `json:"tx_public_key"`
}

// TxID returns the transaction ID (hash of transaction)
func (tx *Transaction) TxID() ([32]byte, error) {
	data, err := json.Marshal(tx)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to marshal tx: %w", err)
	}
	return sha3.Sum256(data), nil
}

// IsCoinbase returns true if this is a coinbase (mining reward) transaction
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Inputs) == 0
}

// UTXO represents an unspent transaction output in the UTXO set
type UTXO struct {
	TxID        [32]byte `json:"tx_id"`
	OutputIndex uint32   `json:"output_index"`
	Output      TxOutput `json:"output"`
	BlockHeight uint64   `json:"block_height"`
}

// UTXOKey returns the unique key for this UTXO
func (u *UTXO) UTXOKey() string {
	return fmt.Sprintf("%x:%d", u.TxID, u.OutputIndex)
}

// UTXOSet manages the set of unspent transaction outputs
type UTXOSet struct {
	mu        sync.RWMutex
	utxos     map[string]*UTXO
	keyImages map[string]bool

	// Index by public key for faster scanning
	byPubKey map[string][]*UTXO
}

// NewUTXOSet creates a new empty UTXO set
func NewUTXOSet() *UTXOSet {
	return &UTXOSet{
		utxos:     make(map[string]*UTXO),
		keyImages: make(map[string]bool),
		byPubKey:  make(map[string][]*UTXO),
	}
}

// Add adds a new UTXO to the set
func (s *UTXOSet) Add(txID [32]byte, index uint32, output TxOutput, blockHeight uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	utxo := &UTXO{
		TxID:        txID,
		OutputIndex: index,
		Output:      output,
		BlockHeight: blockHeight,
	}

	key := utxo.UTXOKey()
	s.utxos[key] = utxo

	// Index by public key
	pkHex := hex.EncodeToString(output.PublicKey[:])
	s.byPubKey[pkHex] = append(s.byPubKey[pkHex], utxo)
}

// MarkSpent marks a key image as spent (prevents double-spending)
func (s *UTXOSet) MarkSpent(keyImage [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hex.EncodeToString(keyImage[:])
	if s.keyImages[key] {
		return fmt.Errorf("key image already spent (double-spend attempt)")
	}
	s.keyImages[key] = true
	return nil
}

// IsSpent checks if a key image has been used
func (s *UTXOSet) IsSpent(keyImage [32]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := hex.EncodeToString(keyImage[:])
	return s.keyImages[key]
}

// GetAllUTXOs returns all UTXOs (for ring member selection)
func (s *UTXOSet) GetAllUTXOs() []*UTXO {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*UTXO, 0, len(s.utxos))
	for _, utxo := range s.utxos {
		result = append(result, utxo)
	}
	return result
}

// GetByPublicKey returns UTXOs for a specific public key
func (s *UTXOSet) GetByPublicKey(pubKey [32]byte) []*UTXO {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pkHex := hex.EncodeToString(pubKey[:])
	return s.byPubKey[pkHex]
}

// SelectRingMembers selects random decoy UTXOs for ring signature
// Returns the selected public keys and the index where realPubKey should be inserted
func (s *UTXOSet) SelectRingMembers(realPubKey [32]byte) ([][32]byte, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ringSize := RingSize

	// Get all available UTXOs as potential decoys
	allUTXOs := make([]*UTXO, 0, len(s.utxos))
	for _, utxo := range s.utxos {
		// Don't include our own output as a decoy
		if utxo.Output.PublicKey != realPubKey {
			allUTXOs = append(allUTXOs, utxo)
		}
	}

	if len(allUTXOs) < ringSize-1 {
		return nil, 0, fmt.Errorf("not enough UTXOs for ring (need %d, have %d)", ringSize-1, len(allUTXOs))
	}

	// Shuffle and pick decoys
	rand.Shuffle(len(allUTXOs), func(i, j int) {
		allUTXOs[i], allUTXOs[j] = allUTXOs[j], allUTXOs[i]
	})

	decoys := allUTXOs[:ringSize-1]

	// Create ring with random position for real key
	secretIndex := rand.Intn(ringSize)
	ring := make([][32]byte, ringSize)

	decoyIdx := 0
	for i := 0; i < ringSize; i++ {
		if i == secretIndex {
			ring[i] = realPubKey
		} else {
			ring[i] = decoys[decoyIdx].Output.PublicKey
			decoyIdx++
		}
	}

	return ring, secretIndex, nil
}

// RingMemberData contains both public key and commitment for ring members
type RingMemberData struct {
	Keys        [][32]byte
	Commitments [][32]byte
	SecretIndex int
}

// SelectRingMembersWithCommitments selects ring members and returns their commitments too
// Required for RingCT to prove amount equality
func (s *UTXOSet) SelectRingMembersWithCommitments(realPubKey, realCommitment [32]byte) (*RingMemberData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ringSize := RingSize

	// Get all available UTXOs as potential decoys
	allUTXOs := make([]*UTXO, 0, len(s.utxos))
	for _, utxo := range s.utxos {
		if utxo.Output.PublicKey != realPubKey {
			allUTXOs = append(allUTXOs, utxo)
		}
	}

	if len(allUTXOs) < ringSize-1 {
		return nil, fmt.Errorf("not enough UTXOs for ring (need %d, have %d)", ringSize-1, len(allUTXOs))
	}

	// Shuffle and pick decoys
	rand.Shuffle(len(allUTXOs), func(i, j int) {
		allUTXOs[i], allUTXOs[j] = allUTXOs[j], allUTXOs[i]
	})

	decoys := allUTXOs[:ringSize-1]

	// Create ring with random position for real key
	secretIndex := rand.Intn(ringSize)
	keys := make([][32]byte, ringSize)
	commitments := make([][32]byte, ringSize)

	decoyIdx := 0
	for i := 0; i < ringSize; i++ {
		if i == secretIndex {
			keys[i] = realPubKey
			commitments[i] = realCommitment
		} else {
			keys[i] = decoys[decoyIdx].Output.PublicKey
			commitments[i] = decoys[decoyIdx].Output.Commitment
			decoyIdx++
		}
	}

	return &RingMemberData{
		Keys:        keys,
		Commitments: commitments,
		SecretIndex: secretIndex,
	}, nil
}

// Count returns the number of UTXOs in the set
func (s *UTXOSet) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.utxos)
}

// KeyImageCount returns the number of spent key images
func (s *UTXOSet) KeyImageCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keyImages)
}

// ============================================================================
// Transaction Building
// ============================================================================

// TxBuilder helps construct privacy-preserving transactions
type TxBuilder struct {
	inputs  []txBuilderInput
	outputs []txBuilderOutput
	fee     uint64
}

type txBuilderInput struct {
	ownedOutput *OwnedOutput // Contains UTXO, amount, blinding, privkey
}

type txBuilderOutput struct {
	recipientSpendPub [32]byte
	recipientViewPub  [32]byte
	amount            uint64
	blinding          [32]byte // Set during Build() to balance
	commitment        [32]byte // Set during Build()
}

// NewTxBuilder creates a new transaction builder
func NewTxBuilder() *TxBuilder {
	return &TxBuilder{}
}

// AddInput adds an input to spend (using owned output data)
func (b *TxBuilder) AddInput(owned *OwnedOutput) {
	b.inputs = append(b.inputs, txBuilderInput{
		ownedOutput: owned,
	})
}

// AddOutput adds an output to create
func (b *TxBuilder) AddOutput(spendPubKey, viewPubKey [32]byte, amount uint64) {
	b.outputs = append(b.outputs, txBuilderOutput{
		recipientSpendPub: spendPubKey,
		recipientViewPub:  viewPubKey,
		amount:            amount,
	})
}

// SetFee sets the transaction fee
func (b *TxBuilder) SetFee(fee uint64) {
	b.fee = fee
}

// Build constructs the transaction with balanced commitments
func (b *TxBuilder) Build(utxoSet *UTXOSet) (*Transaction, error) {
	if len(b.inputs) == 0 {
		return nil, fmt.Errorf("transaction must have at least one input")
	}
	if len(b.outputs) == 0 {
		return nil, fmt.Errorf("transaction must have at least one output")
	}

	// Verify amounts balance
	var inputSum, outputSum uint64
	for _, in := range b.inputs {
		inputSum += in.ownedOutput.Amount
	}
	for _, out := range b.outputs {
		outputSum += out.amount
	}
	if inputSum != outputSum+b.fee {
		return nil, fmt.Errorf("amounts don't balance: inputs=%d, outputs=%d, fee=%d",
			inputSum, outputSum, b.fee)
	}

	tx := &Transaction{
		Version: 1,
		Fee:     b.fee,
	}

	// Calculate sum of input blinding factors
	var inputBlindingSum [32]byte
	for i, in := range b.inputs {
		if i == 0 {
			inputBlindingSum = in.ownedOutput.Blinding
		} else {
			sum, err := BlindingAdd(inputBlindingSum, in.ownedOutput.Blinding)
			if err != nil {
				return nil, fmt.Errorf("failed to sum blindings: %w", err)
			}
			inputBlindingSum = sum
		}
	}

	// Create outputs with balanced blinding factors
	// For all outputs except the last, use random blinding
	// For the last output, compute blinding so that sum(outputs) = sum(inputs)
	var outputBlindingSum [32]byte
	outputBlindings := make([][32]byte, len(b.outputs))

	for i := range b.outputs {
		if i < len(b.outputs)-1 {
			// Random blinding for non-last outputs
			commitment, err := CreatePedersenCommitment(b.outputs[i].amount)
			if err != nil {
				return nil, fmt.Errorf("failed to create commitment: %w", err)
			}
			outputBlindings[i] = commitment.Blinding
			b.outputs[i].blinding = commitment.Blinding
			b.outputs[i].commitment = commitment.Commitment

			if i == 0 {
				outputBlindingSum = outputBlindings[i]
			} else {
				sum, err := BlindingAdd(outputBlindingSum, outputBlindings[i])
				if err != nil {
					return nil, fmt.Errorf("failed to sum blindings: %w", err)
				}
				outputBlindingSum = sum
			}
		} else {
			// Last output: blinding = sum(input_blindings) - sum(other_output_blindings)
			lastBlinding, err := BlindingSub(inputBlindingSum, outputBlindingSum)
			if err != nil {
				return nil, fmt.Errorf("failed to compute last blinding: %w", err)
			}
			outputBlindings[i] = lastBlinding
			b.outputs[i].blinding = lastBlinding

			// Create commitment with this specific blinding
			commitment, err := CreatePedersenCommitmentWithBlinding(b.outputs[i].amount, lastBlinding)
			if err != nil {
				return nil, fmt.Errorf("failed to create last commitment: %w", err)
			}
			b.outputs[i].commitment = commitment
		}
	}

	// Build outputs FIRST (so we can sign the complete transaction)
	for i, out := range b.outputs {
		// Derive one-time stealth address
		stealthOut, err := DeriveStealthAddress(out.recipientSpendPub, out.recipientViewPub)
		if err != nil {
			return nil, fmt.Errorf("failed to derive stealth address: %w", err)
		}

		// Set transaction public key (from first output)
		if tx.TxPublicKey == [32]byte{} {
			tx.TxPublicKey = stealthOut.TxPubKey
		}

		// Create range proof
		rangeProof, err := CreateRangeProof(out.amount, outputBlindings[i])
		if err != nil {
			return nil, fmt.Errorf("failed to create range proof: %w", err)
		}

		tx.Outputs = append(tx.Outputs, TxOutput{
			Commitment: out.commitment,
			PublicKey:  stealthOut.OnetimePubKey,
			RangeProof: rangeProof.Proof,
		})
	}

	// Build inputs with RingCT signatures
	// Each input needs a pseudo-output that commits to the same amount as the real input

	// Calculate sum of output blindings (we already have this from above)
	// For proper balance: sum(pseudo_outputs) = sum(outputs) + fee*G
	// Since pseudo_output[i] = amount[i]*H + pseudo_blinding[i]*G
	// We need: sum(pseudo_blindings) = sum(output_blindings)
	// (fee doesn't need blinding since it's public)

	// Calculate total output blinding
	var totalOutputBlinding [32]byte
	for i, blinding := range outputBlindings {
		if i == 0 {
			totalOutputBlinding = blinding
		} else {
			sum, err := BlindingAdd(totalOutputBlinding, blinding)
			if err != nil {
				return nil, fmt.Errorf("failed to sum output blindings: %w", err)
			}
			totalOutputBlinding = sum
		}
	}

	// Generate pseudo-output blindings
	// For all inputs except the last, use random blindings
	// For the last input, compute so that sum(pseudo_blindings) = sum(output_blindings)
	pseudoBlindings := make([][32]byte, len(b.inputs))
	var pseudoBlindingSum [32]byte

	for i := range b.inputs {
		if i < len(b.inputs)-1 {
			// Random blinding for non-last inputs
			randBlinding := make([]byte, 32)
			for j := range randBlinding {
				randBlinding[j] = byte(rand.Intn(256))
			}
			copy(pseudoBlindings[i][:], randBlinding)

			if i == 0 {
				pseudoBlindingSum = pseudoBlindings[i]
			} else {
				sum, err := BlindingAdd(pseudoBlindingSum, pseudoBlindings[i])
				if err != nil {
					return nil, fmt.Errorf("failed to sum pseudo blindings: %w", err)
				}
				pseudoBlindingSum = sum
			}
		} else {
			// Last input: blinding = sum(output_blindings) - sum(other_pseudo_blindings)
			if len(b.inputs) == 1 {
				pseudoBlindings[i] = totalOutputBlinding
			} else {
				lastBlinding, err := BlindingSub(totalOutputBlinding, pseudoBlindingSum)
				if err != nil {
					return nil, fmt.Errorf("failed to compute last pseudo blinding: %w", err)
				}
				pseudoBlindings[i] = lastBlinding
			}
		}
	}

	// First pass: create input structures with ring members and pseudo-outputs
	ringData := make([]*RingMemberData, len(b.inputs))
	for i, in := range b.inputs {
		owned := in.ownedOutput

		// Get key image
		keyImage, err := GenerateKeyImage(owned.PrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key image: %w", err)
		}

		// Select ring members with commitments
		ring, err := utxoSet.SelectRingMembersWithCommitments(
			owned.UTXO.Output.PublicKey,
			owned.UTXO.Output.Commitment,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to select ring members: %w", err)
		}
		ringData[i] = ring

		// Create pseudo-output commitment (same amount, different blinding)
		pseudoOutput, err := CreatePedersenCommitmentWithBlinding(owned.Amount, pseudoBlindings[i])
		if err != nil {
			return nil, fmt.Errorf("failed to create pseudo-output: %w", err)
		}

		// Build input without signature first
		tx.Inputs = append(tx.Inputs, TxInput{
			KeyImage:        keyImage,
			RingMembers:     ring.Keys,
			RingCommitments: ring.Commitments,
			PseudoOutput:    pseudoOutput,
		})
	}

	// Second pass: sign each input with RingCT
	for i, in := range b.inputs {
		owned := in.ownedOutput
		ring := ringData[i]

		// Sign with RingCT (proves key ownership AND amount equality)
		txData, _ := json.Marshal(tx)
		ringSig, err := SignRingCT(
			ring.Keys,
			ring.Commitments,
			ring.SecretIndex,
			owned.PrivKey,
			owned.Blinding,            // Real input blinding
			tx.Inputs[i].PseudoOutput, // Pseudo-output commitment
			pseudoBlindings[i],        // Pseudo-output blinding
			txData,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create RingCT signature: %w", err)
		}

		tx.Inputs[i].RingSignature = ringSig.Signature
	}

	return tx, nil
}

// ============================================================================
// Transaction Validation
// ============================================================================

// KeyImageChecker is a function that checks if a key image is spent
type KeyImageChecker func(keyImage [32]byte) bool

// ValidateTransaction validates a transaction
func ValidateTransaction(tx *Transaction, isSpent KeyImageChecker) error {
	// Coinbase transactions have no inputs
	if tx.IsCoinbase() {
		return validateCoinbase(tx)
	}

	// Check each input
	for i, input := range tx.Inputs {
		// Check key image not already spent
		if isSpent(input.KeyImage) {
			return fmt.Errorf("input %d: key image already spent (double-spend)", i)
		}

		// Verify ring size is exactly RingSize
		if len(input.RingMembers) != RingSize {
			return fmt.Errorf("input %d: ring size must be %d, got %d", i, RingSize, len(input.RingMembers))
		}
		if len(input.RingCommitments) != RingSize {
			return fmt.Errorf("input %d: ring commitments size must be %d, got %d", i, RingSize, len(input.RingCommitments))
		}

		// Verify RingCT signature (proves key ownership AND amount equality)
		txData, _ := json.Marshal(tx)
		ringSig := &RingCTSignature{
			Signature:    input.RingSignature,
			RingSize:     len(input.RingMembers),
			PseudoOutput: input.PseudoOutput,
		}

		if err := VerifyRingCT(input.RingMembers, input.RingCommitments, txData, ringSig); err != nil {
			return fmt.Errorf("input %d: invalid RingCT signature: %w", i, err)
		}
	}

	// Verify each output range proof
	for i, output := range tx.Outputs {
		rangeProof := &RangeProof{Proof: output.RangeProof}
		if err := VerifyRangeProof(output.Commitment, rangeProof); err != nil {
			return fmt.Errorf("output %d: invalid range proof: %w", i, err)
		}
	}

	// Verify commitment balance using pseudo-outputs (RingCT)
	// sum(pseudo_outputs) = sum(outputs) + fee
	if err := verifyCommitmentBalance(tx); err != nil {
		return fmt.Errorf("commitment balance: %w", err)
	}

	return nil
}

// verifyCommitmentBalance verifies that input commitments equal output commitments + fee
//
// With RingCT, we verify: sum(pseudo_outputs) = sum(outputs) + fee*G
//
// The RingCT signatures prove that each pseudo_output commits to the same amount
// as the corresponding real input (without revealing which ring member is real).
// Therefore if pseudo_outputs balance with outputs + fee, the real inputs do too.
func verifyCommitmentBalance(tx *Transaction) error {
	if len(tx.Outputs) == 0 {
		return fmt.Errorf("transaction has no outputs")
	}
	if len(tx.Inputs) == 0 {
		return fmt.Errorf("transaction has no inputs")
	}

	// Sum pseudo-output commitments
	var pseudoSum [32]byte
	for i, input := range tx.Inputs {
		if i == 0 {
			pseudoSum = input.PseudoOutput
		} else {
			sum, err := CommitmentAdd(pseudoSum, input.PseudoOutput)
			if err != nil {
				return fmt.Errorf("input %d: invalid pseudo-output commitment: %w", i, err)
			}
			pseudoSum = sum
		}
	}

	// Sum output commitments
	var outputSum [32]byte
	for i, output := range tx.Outputs {
		if i == 0 {
			outputSum = output.Commitment
		} else {
			sum, err := CommitmentAdd(outputSum, output.Commitment)
			if err != nil {
				return fmt.Errorf("output %d: invalid commitment point: %w", i, err)
			}
			outputSum = sum
		}
	}

	// Add fee commitment to outputs (fee is public, blinding = 0)
	feeCommitment, err := CreateFeeCommitment(tx.Fee)
	if err != nil {
		return fmt.Errorf("failed to create fee commitment: %w", err)
	}

	outputPlusFee, err := CommitmentAdd(outputSum, feeCommitment)
	if err != nil {
		return fmt.Errorf("failed to add fee commitment: %w", err)
	}

	// Verify: sum(pseudo_outputs) - sum(outputs) - fee*G = 0 (identity)
	// Equivalent to: sum(pseudo_outputs) = sum(outputs) + fee*G
	diff, err := CommitmentSub(pseudoSum, outputPlusFee)
	if err != nil {
		return fmt.Errorf("failed to compute balance difference: %w", err)
	}

	if !CommitmentIsZero(diff) {
		return fmt.Errorf("commitment balance failed: sum(pseudo_outputs) != sum(outputs) + fee")
	}

	return nil
}

func validateCoinbase(tx *Transaction) error {
	if len(tx.Inputs) != 0 {
		return fmt.Errorf("coinbase must have no inputs")
	}
	if len(tx.Outputs) == 0 {
		return fmt.Errorf("coinbase must have at least one output")
	}

	// Verify range proofs on outputs
	for i, output := range tx.Outputs {
		rangeProof := &RangeProof{Proof: output.RangeProof}
		if err := VerifyRangeProof(output.Commitment, rangeProof); err != nil {
			return fmt.Errorf("coinbase output %d: invalid range proof: %w", i, err)
		}
	}

	return nil
}

// ============================================================================
// Coinbase Transaction
// ============================================================================

// deriveAmountKey derives the key for amount encryption from shared secret
// Must match wallet/scanner.go's deriveBlinding function
func deriveAmountKey(sharedSecret [32]byte, outputIndex int) [32]byte {
	h := sha3.New256()
	h.Write([]byte("blocknet_blinding"))
	h.Write(sharedSecret[:])
	var buf [4]byte
	buf[0] = byte(outputIndex)
	buf[1] = byte(outputIndex >> 8)
	buf[2] = byte(outputIndex >> 16)
	buf[3] = byte(outputIndex >> 24)
	h.Write(buf[:])
	sum := h.Sum(nil)

	var key [32]byte
	copy(key[:], sum)
	return key
}

// CoinbaseResult contains the coinbase transaction and the data needed to spend it
type CoinbaseResult struct {
	Tx       *Transaction
	Amount   uint64
	Blinding [32]byte
	TxPubKey [32]byte // Needed for deriving one-time private key
}

// CreateCoinbase creates a coinbase (mining reward) transaction
func CreateCoinbase(recipientSpendPub, recipientViewPub [32]byte, reward uint64) (*CoinbaseResult, error) {
	// Derive stealth address for reward
	stealthOut, err := DeriveStealthAddress(recipientSpendPub, recipientViewPub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive stealth address: %w", err)
	}

	// Derive shared secret for amount encryption and blinding derivation
	// Sender uses: ECDH(txPriv, viewPub) -> shared secret
	// Recipient uses: ECDH(viewPriv, txPub) -> same shared secret
	sharedSecret, err := DeriveStealthSecretSender(stealthOut.TxPrivKey, recipientViewPub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Derive blinding factor from shared secret (must match scanner's deriveBlinding)
	blinding := deriveAmountKey(sharedSecret, 0)

	// Create commitment with derived blinding (so scanner can reproduce it)
	commitment, err := CreatePedersenCommitmentWithBlinding(reward, blinding)
	if err != nil {
		return nil, fmt.Errorf("failed to create commitment: %w", err)
	}

	// Create range proof
	rangeProof, err := CreateRangeProof(reward, blinding)
	if err != nil {
		return nil, fmt.Errorf("failed to create range proof: %w", err)
	}

	// Encrypt the amount for the recipient
	encryptedAmount := EncryptAmount(reward, blinding, 0)

	tx := &Transaction{
		Version:     1,
		Inputs:      []TxInput{},
		TxPublicKey: stealthOut.TxPubKey,
		Outputs: []TxOutput{
			{
				Commitment:      commitment,
				PublicKey:       stealthOut.OnetimePubKey,
				RangeProof:      rangeProof.Proof,
				EncryptedAmount: encryptedAmount,
			},
		},
		Fee: 0,
	}

	return &CoinbaseResult{
		Tx:       tx,
		Amount:   reward,
		Blinding: blinding,
		TxPubKey: stealthOut.TxPubKey,
	}, nil
}

// ============================================================================
// Apply Transaction to UTXO Set
// ============================================================================

// ApplyTransaction applies a validated transaction to the UTXO set
func (s *UTXOSet) ApplyTransaction(tx *Transaction, blockHeight uint64) error {
	txID, err := tx.TxID()
	if err != nil {
		return fmt.Errorf("failed to get tx ID: %w", err)
	}

	// Mark key images as spent
	for _, input := range tx.Inputs {
		if err := s.MarkSpent(input.KeyImage); err != nil {
			return err
		}
	}

	// Add new outputs to UTXO set
	for i, output := range tx.Outputs {
		s.Add(txID, uint32(i), output, blockHeight)
	}

	return nil
}

// UnapplyTransaction reverses the UTXO changes from a transaction
// Used during chain reorganization
func (s *UTXOSet) UnapplyTransaction(tx *Transaction) error {
	txID, err := tx.TxID()
	if err != nil {
		return fmt.Errorf("failed to get tx ID: %w", err)
	}

	// Remove outputs that were added
	for i, output := range tx.Outputs {
		s.Remove(txID, uint32(i), output.PublicKey)
	}

	// Unmark key images (they're no longer spent)
	for _, input := range tx.Inputs {
		s.UnmarkSpent(input.KeyImage)
	}

	return nil
}

// Remove removes a UTXO from the set (used during reorg)
func (s *UTXOSet) Remove(txID [32]byte, index uint32, pubKey [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%x:%d", txID, index)
	delete(s.utxos, key)

	// Remove from pubkey index
	pkHex := hex.EncodeToString(pubKey[:])
	utxos := s.byPubKey[pkHex]
	filtered := make([]*UTXO, 0, len(utxos))
	for _, u := range utxos {
		if u.TxID != txID || u.OutputIndex != index {
			filtered = append(filtered, u)
		}
	}
	s.byPubKey[pkHex] = filtered
}

// UnmarkSpent removes a key image from the spent set (used during reorg)
func (s *UTXOSet) UnmarkSpent(keyImage [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hex.EncodeToString(keyImage[:])
	delete(s.keyImages, key)
}
