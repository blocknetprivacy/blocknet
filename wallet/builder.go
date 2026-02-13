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
	Memo        []byte
}

// TransferResult contains the result of building a transaction
type TransferResult struct {
	TxData       []byte         // Serialized transaction
	TxID         [32]byte       // Transaction ID
	TxPrivKey    [32]byte       // Transaction private key (for sender-side shared secret derivation)
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
	ComputeTxID      func(txData []byte) ([32]byte, error)

	// Scalar arithmetic for blinding factors
	BlindingAdd func(a, b [32]byte) ([32]byte, error)
	BlindingSub func(a, b [32]byte) ([32]byte, error)

	// Stealth address derivation
	DeriveStealthAddress func(spendPub, viewPub [32]byte) (txPriv, txPub, oneTimePub [32]byte, err error)

	// ECDH shared secret derivation (sender side): H(txPriv * viewPub)
	DeriveSharedSecret func(txPriv, viewPub [32]byte) ([32]byte, error)

	// Point operations for deriving one-time keys from an existing txPriv
	ScalarToPoint func(scalar [32]byte) ([32]byte, error) // scalar * G
	PointAdd      func(p1, p2 [32]byte) ([32]byte, error) // p1 + p2

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

	// Generate a single tx keypair (r, R) shared across all outputs.
	// Use DeriveStealthAddress for the first recipient to obtain txPriv/txPub,
	// then reuse txPriv with each recipient's view key to derive shared secrets
	// and one-time keys for all subsequent outputs (including change).
	txPrivKey, txPubKey, firstOneTimePub, err := b.config.DeriveStealthAddress(
		recipients[0].SpendPubKey, recipients[0].ViewPubKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive stealth address: %w", err)
	}

	var allBlindings [][32]byte

	for i, r := range recipients {
		// Derive ECDH shared secret from the single txPriv and recipient's view key
		sharedSecret, err := b.config.DeriveSharedSecret(txPrivKey, r.ViewPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive shared secret for recipient %d: %w", i, err)
		}

		var oneTimePub [32]byte
		if i == 0 {
			// First recipient already derived via DeriveStealthAddress
			oneTimePub = firstOneTimePub
		} else {
			// Compose from existing primitives: oneTimePub = H(r*V)*G + S
			sharedPoint, err := b.config.ScalarToPoint(sharedSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to derive shared point for recipient %d: %w", i, err)
			}
			oneTimePub, err = b.config.PointAdd(sharedPoint, r.SpendPubKey)
			if err != nil {
				return nil, fmt.Errorf("failed to derive one-time key for recipient %d: %w", i, err)
			}
		}

		// Derive blinding deterministically from shared secret so the
		// recipient's scanner can reproduce it for amount decryption.
		blinding := DeriveBlinding(sharedSecret, i)
		commitment := b.config.CreateCommitment(r.Amount, blinding)
		rangeProof, err := b.config.CreateRangeProof(r.Amount, blinding)
		if err != nil {
			return nil, fmt.Errorf("failed to create range proof: %w", err)
		}

		encryptedAmount := encryptAmount(r.Amount, blinding, i)
		encryptedMemo, err := EncryptMemo(r.Memo, sharedSecret, i)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt memo for recipient %d: %w", i, err)
		}

		outputs = append(outputs, outputData{
			pubKey:          oneTimePub,
			commitment:      commitment,
			rangeProof:      rangeProof,
			encryptedAmount: encryptedAmount,
			encryptedMemo:   encryptedMemo,
			blinding:        blinding,
			amount:          r.Amount,
		})
		allBlindings = append(allBlindings, blinding)
	}

	// Add change output to self if needed
	if change > 0 {
		keys := b.wallet.Keys()
		outputIndex := len(outputs)

		// Derive shared secret from same txPriv and our own view key
		changeSecret, err := b.config.DeriveSharedSecret(txPrivKey, keys.ViewPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive shared secret for change: %w", err)
		}

		// Derive one-time key: H(r*V)*G + S
		sharedPoint, err := b.config.ScalarToPoint(changeSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to derive shared point for change: %w", err)
		}
		oneTimePub, err := b.config.PointAdd(sharedPoint, keys.SpendPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive one-time key for change: %w", err)
		}

		blinding := DeriveBlinding(changeSecret, outputIndex)
		commitment := b.config.CreateCommitment(change, blinding)
		rangeProof, err := b.config.CreateRangeProof(change, blinding)
		if err != nil {
			return nil, fmt.Errorf("failed to create change range proof: %w", err)
		}

		encryptedAmount := encryptAmount(change, blinding, outputIndex)
		encryptedMemo, err := EncryptMemo(nil, changeSecret, outputIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt memo for change output: %w", err)
		}

		outputs = append(outputs, outputData{
			pubKey:          oneTimePub,
			commitment:      commitment,
			rangeProof:      rangeProof,
			encryptedAmount: encryptedAmount,
			encryptedMemo:   encryptedMemo,
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
	txID, err := b.config.ComputeTxID(txData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute tx ID: %w", err)
	}

	return &TransferResult{
		TxData:       txData,
		TxID:         txID,
		TxPrivKey:    txPrivKey,
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
	var outputIndexBytes [4]byte
	binary.LittleEndian.PutUint32(outputIndexBytes[:], uint32(outputIndex))
	h.Write(outputIndexBytes[:])
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
	var outputIndexBytes [4]byte
	binary.LittleEndian.PutUint32(outputIndexBytes[:], uint32(outputIndex))
	h.Write(outputIndexBytes[:])
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

	// Each output: pubkey + commitment + encrypted_amount + encrypted_memo + range_proof_len + range_proof
	for _, out := range outputs {
		size += 32 + 32 + 8 + MemoSize + 4 + len(out.rangeProof)
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

		copy(buf[offset:], out.encryptedMemo[:])
		offset += MemoSize

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
	encryptedMemo   [MemoSize]byte
	blinding        [32]byte // Not serialized, just for building
	amount          uint64   // Not serialized, just for building
}

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
