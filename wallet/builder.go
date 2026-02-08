package wallet

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Recipient represents a transaction recipient
type Recipient struct {
	SpendPubKey [32]byte
	ViewPubKey  [32]byte
	Amount      uint64
}

// TransferResult contains the result of building a transaction
type TransferResult struct {
	TxData       []byte         // Serialized transaction
	TxID         [32]byte       // Transaction ID
	SpentOutputs []*OwnedOutput // Outputs that were spent
	Fee          uint64         // Fee paid
	Change       uint64         // Change returned
}

// TransferConfig holds dependencies for transaction building
type TransferConfig struct {
	// Ring member selection
	SelectRingMembers func(realPubKey, realCommitment [32]byte) (keys, commitments [][32]byte, secretIndex int, err error)

	// Cryptographic operations
	CreateCommitment func(amount uint64, blinding [32]byte) [32]byte
	CreateRangeProof func(amount uint64, blinding [32]byte) ([]byte, error)
	SignRingCT       func(
		ringKeys, ringCommitments [][32]byte,
		secretIndex int,
		privateKey, realBlinding [32]byte,
		pseudoCommitment, pseudoBlinding [32]byte,
		message []byte,
	) (signature []byte, keyImage [32]byte, err error)
	GenerateBlinding func() [32]byte
	ComputeTxID      func(txData []byte) [32]byte

	// Scalar arithmetic for blinding factors
	BlindingAdd func(a, b [32]byte) ([32]byte, error)
	BlindingSub func(a, b [32]byte) ([32]byte, error)

	// Stealth derivation (sender side)
	GenerateStealthTxKeypair    func() (txPriv, txPub [32]byte, err error)
	DeriveStealthOnetimePubKey  func(spendPub, viewPub, txPriv [32]byte) (oneTimePub [32]byte, err error)
	DeriveStealthSecretSender   func(txPriv, viewPub [32]byte) ([32]byte, error)

	// Constants
	RingSize   int
	MinFee     uint64
	FeePerByte uint64
}

// Builder constructs transactions
type Builder struct {
	wallet *Wallet
	config TransferConfig
}

// NewBuilder creates a transaction builder
func NewBuilder(w *Wallet, cfg TransferConfig) *Builder {
	return &Builder{
		wallet: w,
		config: cfg,
	}
}

// Transfer creates a transaction sending to recipients
func (b *Builder) Transfer(recipients []Recipient, feeRate uint64, currentHeight uint64) (*TransferResult, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients specified")
	}

	// Calculate total amount needed
	var totalSend uint64
	for _, r := range recipients {
		totalSend += r.Amount
	}

	// Estimate fee (will refine after building)
	estimatedSize := 200 + len(recipients)*100 // rough estimate
	fee := max(b.config.MinFee, uint64(estimatedSize)*feeRate)

	// Select inputs from mature outputs only
	inputs, err := SelectInputs(b.wallet.MatureOutputs(currentHeight), totalSend+fee)
	if err != nil {
		return nil, fmt.Errorf("insufficient funds: %w", err)
	}

	// Calculate total input and change
	var totalInput uint64
	for _, inp := range inputs {
		totalInput += inp.Amount
	}
	change := totalInput - totalSend - fee

	// Build outputs
	outputs := make([]outputData, 0, len(recipients)+1)

	// Generate a single tx keypair (r,R) shared across all outputs in this tx
	txPrivKey, txPubKey, err := b.config.GenerateStealthTxKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate tx keypair: %w", err)
	}

	var allBlindings [][32]byte

	for i, r := range recipients {
		oneTimePub, err := b.config.DeriveStealthOnetimePubKey(r.SpendPubKey, r.ViewPubKey, txPrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive stealth output for recipient %d: %w", i, err)
		}

		sharedSecret, err := b.config.DeriveStealthSecretSender(txPrivKey, r.ViewPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive stealth secret for recipient %d: %w", i, err)
		}

		// Derive blinding deterministically so the recipient can decrypt amount and recover commitments.
		blinding := DeriveBlinding(sharedSecret, i)
		commitment := b.config.CreateCommitment(r.Amount, blinding)
		rangeProof, err := b.config.CreateRangeProof(r.Amount, blinding)
		if err != nil {
			return nil, fmt.Errorf("failed to create range proof: %w", err)
		}

		encryptedAmount := encryptAmount(r.Amount, blinding, i)

		outputs = append(outputs, outputData{
			pubKey:          oneTimePub,
			commitment:      commitment,
			rangeProof:      rangeProof,
			encryptedAmount: encryptedAmount,
			blinding:        blinding,
			amount:          r.Amount,
		})
		allBlindings = append(allBlindings, blinding)
	}

	// Add change output to self if needed
	if change > 0 {
		keys := b.wallet.Keys()
		outputIndex := len(outputs)

		oneTimePub, err := b.config.DeriveStealthOnetimePubKey(keys.SpendPubKey, keys.ViewPubKey, txPrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive change address: %w", err)
		}

		sharedSecret, err := b.config.DeriveStealthSecretSender(txPrivKey, keys.ViewPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive stealth secret for change: %w", err)
		}

		blinding := DeriveBlinding(sharedSecret, outputIndex)
		commitment := b.config.CreateCommitment(change, blinding)
		rangeProof, err := b.config.CreateRangeProof(change, blinding)
		if err != nil {
			return nil, fmt.Errorf("failed to create change range proof: %w", err)
		}

		encryptedAmount := encryptAmount(change, blinding, outputIndex)

		outputs = append(outputs, outputData{
			pubKey:          oneTimePub,
			commitment:      commitment,
			rangeProof:      rangeProof,
			encryptedAmount: encryptedAmount,
			blinding:        blinding,
			amount:          change,
		})
		allBlindings = append(allBlindings, blinding)
	}

	// Calculate total output blinding using proper scalar arithmetic
	// sum(pseudo_blindings) must equal sum(output_blindings)
	totalOutputBlinding, err := b.sumBlindings(allBlindings)
	if err != nil {
		return nil, fmt.Errorf("failed to sum output blindings: %w", err)
	}

	// Build inputs with ring signatures
	inputsData := make([]inputData, len(inputs))

	// Distribute blinding across pseudo-outputs so they sum to totalOutputBlinding
	pseudoBlindings, err := b.distributeBlindings(totalOutputBlinding, len(inputs))
	if err != nil {
		return nil, fmt.Errorf("failed to distribute blindings: %w", err)
	}

	// Build message to sign (tx prefix hash without signatures)
	txPrefix := serializeTxPrefix(txPubKey, len(inputs), outputs, fee)
	txPrefixHash := sha3.Sum256(txPrefix)

	for i, inp := range inputs {
		// Get ring members
		ringKeys, ringCommitments, secretIndex, err := b.config.SelectRingMembers(inp.OneTimePubKey, inp.Commitment)
		if err != nil {
			return nil, fmt.Errorf("failed to select ring members: %w", err)
		}

		// Create pseudo-output commitment (same amount, different blinding)
		pseudoCommitment := b.config.CreateCommitment(inp.Amount, pseudoBlindings[i])

		// Sign with tx prefix hash as message
		sig, keyImage, err := b.config.SignRingCT(
			ringKeys, ringCommitments,
			secretIndex,
			inp.OneTimePrivKey, inp.Blinding,
			pseudoCommitment, pseudoBlindings[i],
			txPrefixHash[:],
		)
		if err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", i, err)
		}

		inputsData[i] = inputData{
			keyImage:        keyImage,
			ringMembers:     ringKeys,
			ringCommitments: ringCommitments,
			pseudoOutput:    pseudoCommitment,
			signature:       sig,
		}
	}

	// Serialize full transaction
	txData := serializeTx(txPubKey, inputsData, outputs, fee)
	txID := b.config.ComputeTxID(txData)

	return &TransferResult{
		TxData:       txData,
		TxID:         txID,
		SpentOutputs: inputs,
		Fee:          fee,
		Change:       change,
	}, nil
}

// sumBlindings adds blinding factors using proper scalar arithmetic
func (b *Builder) sumBlindings(blindings [][32]byte) ([32]byte, error) {
	if len(blindings) == 0 {
		return [32]byte{}, nil
	}
	if len(blindings) == 1 {
		return blindings[0], nil
	}

	sum := blindings[0]
	for i := 1; i < len(blindings); i++ {
		var err error
		sum, err = b.config.BlindingAdd(sum, blindings[i])
		if err != nil {
			return [32]byte{}, fmt.Errorf("scalar add failed at index %d: %w", i, err)
		}
	}
	return sum, nil
}

// distributeBlindings creates pseudo-output blindings that sum to target
func (b *Builder) distributeBlindings(target [32]byte, count int) ([][32]byte, error) {
	if count == 0 {
		return nil, nil
	}
	if count == 1 {
		return [][32]byte{target}, nil
	}

	// Generate random blindings for first n-1, compute last to balance
	result := make([][32]byte, count)
	sum := [32]byte{} // Start with zero

	for i := 0; i < count-1; i++ {
		result[i] = b.config.GenerateBlinding()
		var err error
		sum, err = b.config.BlindingAdd(sum, result[i])
		if err != nil {
			return nil, fmt.Errorf("scalar add failed: %w", err)
		}
	}

	// Last blinding = target - sum
	var err error
	result[count-1], err = b.config.BlindingSub(target, sum)
	if err != nil {
		return nil, fmt.Errorf("scalar sub failed: %w", err)
	}

	return result, nil
}

// encryptAmount encrypts an amount using the blinding factor as shared secret
// Format: amount XOR first 8 bytes of Hash("amount" || blinding || output_index)
func encryptAmount(amount uint64, blinding [32]byte, outputIndex int) [8]byte {
	h := sha3.New256()
	h.Write([]byte("blocknet_amount"))
	h.Write(blinding[:])
	binary.Write(h, binary.LittleEndian, uint32(outputIndex))
	mask := h.Sum(nil)

	var amountBytes [8]byte
	binary.LittleEndian.PutUint64(amountBytes[:], amount)

	var encrypted [8]byte
	for i := 0; i < 8; i++ {
		encrypted[i] = amountBytes[i] ^ mask[i]
	}
	return encrypted
}

// DecryptAmount decrypts an encrypted amount using the blinding factor
func DecryptAmount(encrypted [8]byte, blinding [32]byte, outputIndex int) uint64 {
	h := sha3.New256()
	h.Write([]byte("blocknet_amount"))
	h.Write(blinding[:])
	binary.Write(h, binary.LittleEndian, uint32(outputIndex))
	mask := h.Sum(nil)

	var amountBytes [8]byte
	for i := 0; i < 8; i++ {
		amountBytes[i] = encrypted[i] ^ mask[i]
	}
	return binary.LittleEndian.Uint64(amountBytes[:])
}

// serializeTxPrefix creates the transaction prefix (everything except signatures)
func serializeTxPrefix(txPubKey [32]byte, inputCount int, outputs []outputData, fee uint64) []byte {
	// Calculate size
	size := 1 + // version
		32 + // tx public key
		4 + // input count
		4 + // output count
		8 // fee

	// Each output: pubkey + commitment + encrypted_amount + range_proof_len + range_proof
	for _, out := range outputs {
		size += 32 + 32 + 8 + 4 + len(out.rangeProof)
	}

	buf := make([]byte, size)
	offset := 0

	// Version
	buf[offset] = 1
	offset++

	// Tx public key
	copy(buf[offset:], txPubKey[:])
	offset += 32

	// Input count
	binary.LittleEndian.PutUint32(buf[offset:], uint32(inputCount))
	offset += 4

	// Output count
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(outputs)))
	offset += 4

	// Fee
	binary.LittleEndian.PutUint64(buf[offset:], fee)
	offset += 8

	// Outputs
	for _, out := range outputs {
		copy(buf[offset:], out.pubKey[:])
		offset += 32

		copy(buf[offset:], out.commitment[:])
		offset += 32

		copy(buf[offset:], out.encryptedAmount[:])
		offset += 8

		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(out.rangeProof)))
		offset += 4

		copy(buf[offset:], out.rangeProof)
		offset += len(out.rangeProof)
	}

	return buf
}

// serializeTx creates the full transaction bytes
func serializeTx(txPubKey [32]byte, inputs []inputData, outputs []outputData, fee uint64) []byte {
	// Start with prefix
	prefix := serializeTxPrefix(txPubKey, len(inputs), outputs, fee)

	// Calculate input section size
	inputSize := 0
	for _, inp := range inputs {
		// key_image + pseudo_output + ring_size + ring_members + ring_commitments + sig_len + signature
		inputSize += 32 + 32 + 4 + len(inp.ringMembers)*32 + len(inp.ringCommitments)*32 + 4 + len(inp.signature)
	}

	buf := make([]byte, len(prefix)+inputSize)
	offset := 0

	// Copy prefix
	copy(buf[offset:], prefix)
	offset += len(prefix)

	// Serialize inputs
	for _, inp := range inputs {
		// Key image
		copy(buf[offset:], inp.keyImage[:])
		offset += 32

		// Pseudo-output commitment
		copy(buf[offset:], inp.pseudoOutput[:])
		offset += 32

		// Ring size
		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(inp.ringMembers)))
		offset += 4

		// Ring member public keys
		for _, pk := range inp.ringMembers {
			copy(buf[offset:], pk[:])
			offset += 32
		}

		// Ring member commitments
		for _, c := range inp.ringCommitments {
			copy(buf[offset:], c[:])
			offset += 32
		}

		// Signature length
		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(inp.signature)))
		offset += 4

		// Signature
		copy(buf[offset:], inp.signature)
		offset += len(inp.signature)
	}

	return buf
}

type inputData struct {
	keyImage        [32]byte
	ringMembers     [][32]byte
	ringCommitments [][32]byte
	pseudoOutput    [32]byte
	signature       []byte
}

type outputData struct {
	pubKey          [32]byte
	commitment      [32]byte
	rangeProof      []byte
	encryptedAmount [8]byte
	blinding        [32]byte // Not serialized, just for building
	amount          uint64   // Not serialized, just for building
}

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
