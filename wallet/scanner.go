package wallet

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// BlockData is the minimal block info needed for scanning
type BlockData struct {
	Height       uint64
	Transactions []TxData
}

// TxData is the minimal tx info needed for scanning
type TxData struct {
	TxID       [32]byte
	TxPubKey   [32]byte
	IsCoinbase bool // True if this is a coinbase (mining reward) transaction
	Outputs    []OutputData
	KeyImages  [][32]byte // For detecting spent outputs
}

// OutputData is the minimal output info for scanning
type OutputData struct {
	Index           int
	PubKey          [32]byte
	Commitment      [32]byte
	EncryptedAmount [8]byte
	EncryptedMemo   [MemoSize]byte
}

// ScannerConfig holds callbacks for cryptographic operations
type ScannerConfig struct {
	GenerateKeyImage func(privKey [32]byte) ([32]byte, error)

	// CreateCommitment recomputes a Pedersen commitment for (amount, blinding).
	// If non-nil, the scanner verifies the decrypted amount matches the on-chain
	// commitment before recording the output. This prevents garbage balances when
	// amount decryption produces wrong results (e.g. legacy broken transactions).
	CreateCommitment func(amount uint64, blinding [32]byte) ([32]byte, error)
}

// Scanner scans blocks for wallet-relevant transactions
type Scanner struct {
	wallet *Wallet
	config ScannerConfig
}

// NewScanner creates a scanner for a wallet
func NewScanner(w *Wallet, cfg ScannerConfig) *Scanner {
	return &Scanner{
		wallet: w,
		config: cfg,
	}
}

// ScanBlock scans a block for owned outputs and spent outputs
func (s *Scanner) ScanBlock(block *BlockData) (found int, spent int) {
	keys := s.wallet.Keys()
	spendableByKeyImage := s.buildSpendableKeyImageIndex()

	for _, tx := range block.Transactions {
		// Check each output - is it ours?
		for _, out := range tx.Outputs {
			if s.wallet.checkStealthOutput(tx.TxPubKey, out.PubKey, keys.ViewPrivKey, keys.SpendPubKey) {
				// This output is ours!
				// Derive the one-time private key so we can spend it
				oneTimePriv, err := s.wallet.deriveSpendKey(tx.TxPubKey, keys.ViewPrivKey, keys.SpendPrivKey)
				if err != nil {
					continue
				}

				var outputSecret [32]byte
				var blinding [32]byte
				if tx.IsCoinbase {
					blinding = DeriveCoinbaseConsensusBlinding(tx.TxPubKey, block.Height, out.Index)
				} else {
					// Derive the shared secret for amount decryption.
					outputSecret, err = s.wallet.deriveOutputSecret(tx.TxPubKey, keys.ViewPrivKey)
					if err != nil {
						continue
					}
					// Derive the blinding factor from shared secret.
					blinding = DeriveBlinding(outputSecret, out.Index)
				}

				// Decrypt the amount
				amount := DecryptAmount(out.EncryptedAmount, blinding, out.Index)

				// Verify the decrypted amount and derived blinding reopen the
				// on-chain Pedersen commitment. This catches cases where the
				// derivation path is wrong (e.g. legacy broken transactions)
				// and prevents garbage amounts from polluting the balance.
				if s.config.CreateCommitment != nil {
					commitment, err := s.config.CreateCommitment(amount, blinding)
					if err != nil {
						continue
					}
					if commitment != out.Commitment {
						continue
					}
				}

				owned := &OwnedOutput{
					TxID:           tx.TxID,
					OutputIndex:    out.Index,
					Amount:         amount,
					Blinding:       blinding,
					OneTimePrivKey: oneTimePriv,
					OneTimePubKey:  out.PubKey,
					Commitment:     out.Commitment,
					BlockHeight:    block.Height,
					IsCoinbase:     tx.IsCoinbase,
					Spent:          false,
				}

				// Decrypt memo from the canonical output field.
				if !tx.IsCoinbase {
					if memo, ok := DecryptMemo(out.EncryptedMemo, outputSecret, out.Index); ok {
						owned.Memo = memo
					}
				}

				s.wallet.AddOutput(owned)
				if keyImage, err := s.config.GenerateKeyImage(owned.OneTimePrivKey); err == nil {
					spendableByKeyImage[keyImage] = append(spendableByKeyImage[keyImage], owned.OneTimePubKey)
				}
				found++
			}
		}

		// Check key images - did we spend something?
		for _, keyImage := range tx.KeyImages {
			ownedPubKeys := spendableByKeyImage[keyImage]
			for _, ownedPubKey := range ownedPubKeys {
				if s.wallet.MarkSpent(ownedPubKey, block.Height) {
					spent++
				}
			}
			delete(spendableByKeyImage, keyImage)
		}
	}

	return found, spent
}

func (s *Scanner) buildSpendableKeyImageIndex() map[[32]byte][][32]byte {
	spendableByKeyImage := make(map[[32]byte][][32]byte)
	for _, out := range s.wallet.SpendableOutputs() {
		keyImage, err := s.config.GenerateKeyImage(out.OneTimePrivKey)
		if err != nil {
			continue
		}
		spendableByKeyImage[keyImage] = append(spendableByKeyImage[keyImage], out.OneTimePubKey)
	}
	return spendableByKeyImage
}

// ScanBlocks scans multiple blocks
func (s *Scanner) ScanBlocks(blocks []*BlockData) (totalFound, totalSpent int) {
	for _, block := range blocks {
		found, spent := s.ScanBlock(block)
		totalFound += found
		totalSpent += spent

		s.wallet.SetSyncedHeight(block.Height)
	}
	return totalFound, totalSpent
}

// DeriveBlinding derives a blinding factor from the shared secret and output index.
// blinding = Hash("blocknet_blinding" || shared_secret || output_index)
func DeriveBlinding(sharedSecret [32]byte, outputIndex int) [32]byte {
	h := sha3.New256()
	h.Write([]byte("blocknet_blinding"))
	h.Write(sharedSecret[:])
	var outputIndexBytes [4]byte
	binary.LittleEndian.PutUint32(outputIndexBytes[:], uint32(outputIndex))
	h.Write(outputIndexBytes[:])
	sum := h.Sum(nil)

	var blinding [32]byte
	copy(blinding[:], sum)

	// Reduce modulo the curve order to ensure it's a valid scalar
	// For Ristretto255, scalars are mod 2^252 + 27742317777372353535851937790883648493
	// The hash output is already 32 bytes, which is fine for this purpose
	// as the Rust side handles canonical reduction
	return blinding
}

// DeriveCoinbaseConsensusBlinding derives the deterministic consensus blinding
// for coinbase outputs from public transaction data.
func DeriveCoinbaseConsensusBlinding(txPubKey [32]byte, blockHeight uint64, outputIndex int) [32]byte {
	h := sha3.New256()
	h.Write([]byte("blocknet_coinbase_consensus_blinding"))
	h.Write(txPubKey[:])
	var blockHeightBytes [8]byte
	binary.LittleEndian.PutUint64(blockHeightBytes[:], blockHeight)
	h.Write(blockHeightBytes[:])
	var outputIndexBytes [4]byte
	binary.LittleEndian.PutUint32(outputIndexBytes[:], uint32(outputIndex))
	h.Write(outputIndexBytes[:])
	sum := h.Sum(nil)

	var blinding [32]byte
	copy(blinding[:], sum)
	return blinding
}

// BlockToScanData converts a serialized block to scanner format
func BlockToScanData(blockJSON []byte) (*BlockData, error) {
	var raw struct {
		Header struct {
			Height uint64 `json:"height"`
		} `json:"header"`
		Transactions []struct {
			TxID        [32]byte `json:"tx_id"`
			TxPublicKey [32]byte `json:"tx_public_key"`
			Outputs     []struct {
				PublicKey       [32]byte `json:"public_key"`
				Commitment      [32]byte `json:"commitment"`
				EncryptedAmount [8]byte  `json:"encrypted_amount"`
				EncryptedMemo   [MemoSize]byte `json:"encrypted_memo"`
			} `json:"outputs"`
			Inputs []struct {
				KeyImage [32]byte `json:"key_image"`
			} `json:"inputs"`
		} `json:"transactions"`
	}

	if err := json.Unmarshal(blockJSON, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse block: %w", err)
	}

	block := &BlockData{
		Height:       raw.Header.Height,
		Transactions: make([]TxData, len(raw.Transactions)),
	}

	for i, tx := range raw.Transactions {
		block.Transactions[i] = TxData{
			TxID:     tx.TxID,
			TxPubKey: tx.TxPublicKey,
			Outputs:  make([]OutputData, len(tx.Outputs)),
		}

		for j, out := range tx.Outputs {
			block.Transactions[i].Outputs[j] = OutputData{
				Index:           j,
				PubKey:          out.PublicKey,
				Commitment:      out.Commitment,
				EncryptedAmount: out.EncryptedAmount,
				EncryptedMemo:   out.EncryptedMemo,
			}
		}

		for _, inp := range tx.Inputs {
			block.Transactions[i].KeyImages = append(block.Transactions[i].KeyImages, inp.KeyImage)
		}
	}

	return block, nil
}
