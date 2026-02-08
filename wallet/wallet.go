package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/argon2"
)

// StealthKeys contains the two keypairs needed for stealth addresses
type StealthKeys struct {
	SpendPrivKey [32]byte `json:"spend_priv"`
	SpendPubKey  [32]byte `json:"spend_pub"`
	ViewPrivKey  [32]byte `json:"view_priv"`
	ViewPubKey   [32]byte `json:"view_pub"`
}

// Address returns the public stealth address (base58 encoded spend+view pubkeys)
func (sk *StealthKeys) Address() string {
	// Address = base58(spend_pub || view_pub)
	combined := make([]byte, 64)
	copy(combined[:32], sk.SpendPubKey[:])
	copy(combined[32:], sk.ViewPubKey[:])
	return base58.Encode(combined)
}

// OwnedOutput represents an output the wallet can spend
type OwnedOutput struct {
	TxID           [32]byte `json:"txid"`
	OutputIndex    int      `json:"output_index"`
	Amount         uint64   `json:"amount"`
	Blinding       [32]byte `json:"blinding"`
	OneTimePrivKey [32]byte `json:"one_time_priv"`
	OneTimePubKey  [32]byte `json:"one_time_pub"`
	Commitment     [32]byte `json:"commitment"`
	BlockHeight    uint64   `json:"block_height"`
	IsCoinbase     bool     `json:"is_coinbase"` // True if from mining reward
	Spent          bool     `json:"spent"`
	SpentHeight    uint64   `json:"spent_height,omitempty"`
}

// WalletData is the serializable wallet state
type WalletData struct {
	Version      uint32         `json:"version"`
	ViewOnly     bool           `json:"view_only"`          // True if this is a view-only wallet
	Mnemonic     string         `json:"mnemonic,omitempty"` // BIP39 12-word recovery phrase (empty for view-only)
	Keys         StealthKeys    `json:"keys"`
	Outputs      []*OwnedOutput `json:"outputs"`
	SyncedHeight uint64         `json:"synced_height"`
	CreatedAt    int64          `json:"created_at"`
}

// ViewOnlyKeys contains only the keys needed for a view-only wallet
type ViewOnlyKeys struct {
	SpendPubKey [32]byte `json:"spend_pub"`
	ViewPrivKey [32]byte `json:"view_priv"`
	ViewPubKey  [32]byte `json:"view_pub"`
}

// Wallet manages keys and tracks owned outputs
type Wallet struct {
	mu sync.RWMutex

	data     WalletData
	filename string
	password []byte // kept in memory for re-encryption on save

	// Callbacks for crypto operations (set by main package)
	generateStealthKeys     func() (*StealthKeys, error)
	deriveStealthAddress    func(spendPub, viewPub [32]byte) (txPriv, txPub, oneTimePub [32]byte, err error)
	checkStealthOutput      func(txPub, outputPub, viewPriv, spendPub [32]byte) bool
	deriveSpendKey          func(txPub, viewPriv, spendPriv [32]byte) ([32]byte, error)
	deriveOutputSecret      func(txPub, viewPriv [32]byte) ([32]byte, error)
	generateKeypairFromSeed func(seed [32]byte) (priv, pub [32]byte, err error)
}

// WalletConfig holds wallet configuration
type WalletConfig struct {
	GenerateStealthKeys  func() (*StealthKeys, error)
	DeriveStealthAddress func(spendPub, viewPub [32]byte) (txPriv, txPub, oneTimePub [32]byte, err error)
	CheckStealthOutput   func(txPub, outputPub, viewPriv, spendPub [32]byte) bool
	DeriveSpendKey       func(txPub, viewPriv, spendPriv [32]byte) ([32]byte, error)
	DeriveOutputSecret   func(txPub, viewPriv [32]byte) ([32]byte, error)

	// For deterministic key derivation from BIP39 seed
	GenerateKeypairFromSeed func(seed [32]byte) (priv, pub [32]byte, err error)
}

// NewWallet creates a new wallet with a fresh BIP39 mnemonic
func NewWallet(filename string, password []byte, cfg WalletConfig) (*Wallet, error) {
	// Generate new mnemonic
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	return NewWalletFromMnemonic(filename, password, mnemonic, cfg)
}

// NewWalletFromMnemonic creates a wallet from an existing mnemonic (for recovery)
func NewWalletFromMnemonic(filename string, password []byte, mnemonic string, cfg WalletConfig) (*Wallet, error) {
	// Derive seed from mnemonic (no passphrase - password is for encryption only)
	seed, err := MnemonicToSeed(mnemonic, "")
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	// Derive keys from seed
	keys, err := DeriveKeysFromSeed(seed, cfg.GenerateKeypairFromSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys from seed: %w", err)
	}

	w := &Wallet{
		filename:                filename,
		password:                password,
		generateStealthKeys:     cfg.GenerateStealthKeys,
		deriveStealthAddress:    cfg.DeriveStealthAddress,
		checkStealthOutput:      cfg.CheckStealthOutput,
		deriveSpendKey:          cfg.DeriveSpendKey,
		deriveOutputSecret:      cfg.DeriveOutputSecret,
		generateKeypairFromSeed: cfg.GenerateKeypairFromSeed,
	}

	w.data = WalletData{
		Version:      1,
		Mnemonic:     mnemonic,
		Keys:         *keys,
		Outputs:      make([]*OwnedOutput, 0),
		SyncedHeight: 0,
		CreatedAt:    unixNow(),
	}

	// Save immediately
	if err := w.Save(); err != nil {
		return nil, fmt.Errorf("failed to save new wallet: %w", err)
	}

	return w, nil
}

// LoadWallet loads an existing encrypted wallet
func LoadWallet(filename string, password []byte, cfg WalletConfig) (*Wallet, error) {
	encrypted, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read wallet file: %w", err)
	}

	// Decrypt
	plaintext, err := decrypt(encrypted, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt wallet (wrong password?): %w", err)
	}

	var data WalletData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("failed to parse wallet data: %w", err)
	}

	return &Wallet{
		data:                    data,
		filename:                filename,
		password:                password,
		generateStealthKeys:     cfg.GenerateStealthKeys,
		deriveStealthAddress:    cfg.DeriveStealthAddress,
		generateKeypairFromSeed: cfg.GenerateKeypairFromSeed,
		checkStealthOutput:      cfg.CheckStealthOutput,
		deriveSpendKey:          cfg.DeriveSpendKey,
		deriveOutputSecret:      cfg.DeriveOutputSecret,
	}, nil
}

// NewViewOnlyWallet creates a view-only wallet from exported keys
// View-only wallets can scan for incoming funds but cannot spend
func NewViewOnlyWallet(filename string, password []byte, keys ViewOnlyKeys, cfg WalletConfig) (*Wallet, error) {
	w := &Wallet{
		filename:             filename,
		password:             password,
		deriveStealthAddress: cfg.DeriveStealthAddress,
		checkStealthOutput:   cfg.CheckStealthOutput,
		deriveOutputSecret:   cfg.DeriveOutputSecret,
	}

	// Create wallet data with view-only flag
	// SpendPrivKey is zeroed (we don't have it)
	w.data = WalletData{
		Version:  1,
		ViewOnly: true,
		Keys: StealthKeys{
			SpendPrivKey: [32]byte{}, // Zero - we don't have the spend key
			SpendPubKey:  keys.SpendPubKey,
			ViewPrivKey:  keys.ViewPrivKey,
			ViewPubKey:   keys.ViewPubKey,
		},
		Outputs:      make([]*OwnedOutput, 0),
		SyncedHeight: 0,
		CreatedAt:    unixNow(),
	}

	if err := w.Save(); err != nil {
		return nil, fmt.Errorf("failed to save view-only wallet: %w", err)
	}

	return w, nil
}

// LoadOrCreateWallet loads existing wallet or creates new one
func LoadOrCreateWallet(filename string, password []byte, cfg WalletConfig) (*Wallet, error) {
	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		return NewWallet(filename, password, cfg)
	}
	return LoadWallet(filename, password, cfg)
}

// Save encrypts and writes wallet to disk
func (w *Wallet) Save() error {
	w.mu.RLock()
	defer w.mu.RUnlock()

	plaintext, err := json.MarshalIndent(w.data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal wallet: %w", err)
	}

	encrypted, err := encrypt(plaintext, w.password)
	if err != nil {
		return fmt.Errorf("failed to encrypt wallet: %w", err)
	}

	if err := os.WriteFile(w.filename, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write wallet file: %w", err)
	}

	return nil
}

// Address returns the wallet's public stealth address
func (w *Wallet) Address() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.data.Keys.Address()
}

// Mnemonic returns the BIP39 recovery phrase
func (w *Wallet) Mnemonic() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.data.Mnemonic
}

// IsViewOnly returns true if this is a view-only wallet
func (w *Wallet) IsViewOnly() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.data.ViewOnly
}

// ExportViewOnlyKeys exports the keys needed to create a view-only wallet
func (w *Wallet) ExportViewOnlyKeys() ViewOnlyKeys {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return ViewOnlyKeys{
		SpendPubKey: w.data.Keys.SpendPubKey,
		ViewPrivKey: w.data.Keys.ViewPrivKey,
		ViewPubKey:  w.data.Keys.ViewPubKey,
	}
}

// Keys returns the wallet's stealth keys
func (w *Wallet) Keys() StealthKeys {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.data.Keys
}

// SpendPubKey returns the spend public key
func (w *Wallet) SpendPubKey() [32]byte {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.data.Keys.SpendPubKey
}

// ViewPubKey returns the view public key
func (w *Wallet) ViewPubKey() [32]byte {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.data.Keys.ViewPubKey
}

// Maturity constants (must match block.go)
const (
	CoinbaseMaturity  = 60 // Mined coins locked for 60 blocks
	SafeConfirmations = 10 // Regular coins need 10 confirmations
)

// IsOutputMature checks if an output is mature enough to spend
func IsOutputMature(out *OwnedOutput, currentHeight uint64) bool {
	if out.Spent {
		return false
	}

	confirmations := uint64(0)
	if currentHeight >= out.BlockHeight {
		confirmations = currentHeight - out.BlockHeight
	}

	if out.IsCoinbase {
		return confirmations >= CoinbaseMaturity
	}
	return confirmations >= SafeConfirmations
}

// Balance returns total unspent balance (regardless of maturity)
func (w *Wallet) Balance() uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var total uint64
	for _, out := range w.data.Outputs {
		if !out.Spent {
			total += out.Amount
		}
	}
	return total
}

// SpendableBalance returns balance that can actually be spent now
func (w *Wallet) SpendableBalance(currentHeight uint64) uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var total uint64
	for _, out := range w.data.Outputs {
		if IsOutputMature(out, currentHeight) {
			total += out.Amount
		}
	}
	return total
}

// PendingBalance returns balance that exists but can't be spent yet
func (w *Wallet) PendingBalance(currentHeight uint64) uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var total uint64
	for _, out := range w.data.Outputs {
		if !out.Spent && !IsOutputMature(out, currentHeight) {
			total += out.Amount
		}
	}
	return total
}

// SpendableOutputs returns all unspent outputs (regardless of maturity)
func (w *Wallet) SpendableOutputs() []*OwnedOutput {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var outputs []*OwnedOutput
	for _, out := range w.data.Outputs {
		if !out.Spent {
			outputs = append(outputs, out)
		}
	}
	return outputs
}

// MatureOutputs returns only outputs that are mature enough to spend
func (w *Wallet) MatureOutputs(currentHeight uint64) []*OwnedOutput {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var outputs []*OwnedOutput
	for _, out := range w.data.Outputs {
		if IsOutputMature(out, currentHeight) {
			outputs = append(outputs, out)
		}
	}
	return outputs
}

// AddOutput adds a newly discovered output.
// Dedupes by (txid, output_index) so rescans or repeated block notifications
// don't inflate balances.
func (w *Wallet) AddOutput(out *OwnedOutput) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, existing := range w.data.Outputs {
		if existing.TxID == out.TxID && existing.OutputIndex == out.OutputIndex {
			return
		}
	}

	w.data.Outputs = append(w.data.Outputs, out)
}

// MarkSpent marks an output as spent by its one-time pubkey
func (w *Wallet) MarkSpent(oneTimePubKey [32]byte, height uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, out := range w.data.Outputs {
		if out.OneTimePubKey == oneTimePubKey && !out.Spent {
			out.Spent = true
			out.SpentHeight = height
			return true
		}
	}
	return false
}

// SyncedHeight returns the last synced block height
func (w *Wallet) SyncedHeight() uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.data.SyncedHeight
}

// SetSyncedHeight updates the sync height
func (w *Wallet) SetSyncedHeight(height uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.data.SyncedHeight = height
}

// RewindToHeight removes outputs from blocks above the given height
// and resets synced height. Used when chain has been reset/reorged.
func (w *Wallet) RewindToHeight(height uint64) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	var kept []*OwnedOutput
	removed := 0
	for _, out := range w.data.Outputs {
		if out.BlockHeight <= height {
			// Also un-spend outputs whose spend was above the rewind point
			if out.Spent && out.SpentHeight > height {
				out.Spent = false
				out.SpentHeight = 0
			}
			kept = append(kept, out)
		} else {
			removed++
		}
	}
	w.data.Outputs = kept
	if w.data.SyncedHeight > height {
		w.data.SyncedHeight = height
	}
	return removed
}

// OutputCount returns total output count
func (w *Wallet) OutputCount() (total, unspent int) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	total = len(w.data.Outputs)
	for _, out := range w.data.Outputs {
		if !out.Spent {
			unspent++
		}
	}
	return
}

// ============================================================================
// Encryption helpers (Argon2id + AES-GCM)
// ============================================================================

func deriveKey(password, salt []byte) []byte {
	// Argon2id: 64MB memory, 3 iterations, 4 parallelism
	return argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
}

func encrypt(plaintext, password []byte) ([]byte, error) {
	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Format: salt (16) || nonce (12) || ciphertext
	result := make([]byte, 16+gcm.NonceSize()+len(ciphertext))
	copy(result[:16], salt)
	copy(result[16:16+gcm.NonceSize()], nonce)
	copy(result[16+gcm.NonceSize():], ciphertext)

	return result, nil
}

func decrypt(data, password []byte) ([]byte, error) {
	if len(data) < 16+12 { // salt + minimum nonce
		return nil, errors.New("ciphertext too short")
	}

	salt := data[:16]
	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < 16+nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := data[16 : 16+nonceSize]
	ciphertext := data[16+nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func unixNow() int64 {
	return time.Now().Unix()
}

// ParseAddress decodes a stealth address into spend and view pubkeys
func ParseAddress(address string) (spendPub, viewPub [32]byte, err error) {
	decoded := base58.Decode(address)
	if len(decoded) != 64 {
		return spendPub, viewPub, errors.New("invalid address length")
	}
	copy(spendPub[:], decoded[:32])
	copy(viewPub[:], decoded[32:])
	return spendPub, viewPub, nil
}
