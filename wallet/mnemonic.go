package wallet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// BIP39 constants
const (
	EntropyBits  = 128 // 12 words = 128 bits entropy
	ChecksumBits = 4   // 128/32 = 4 bits checksum
	WordBits     = 11  // Each word encodes 11 bits
	WordCount    = 12  // (128 + 4) / 11 = 12 words
	SeedBytes    = 64  // PBKDF2 output length
	PBKDF2Rounds = 2048
)

var (
	ErrInvalidMnemonic  = errors.New("invalid mnemonic")
	ErrInvalidWordCount = errors.New("mnemonic must be 12 words")
	ErrInvalidWord      = errors.New("word not in BIP39 wordlist")
	ErrInvalidChecksum  = errors.New("mnemonic checksum invalid")
)

// GenerateMnemonic creates a new 12-word BIP39 mnemonic
func GenerateMnemonic() (string, error) {
	// Generate 128 bits of entropy
	entropy := make([]byte, EntropyBits/8)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}

	return EntropyToMnemonic(entropy)
}

// EntropyToMnemonic converts entropy bytes to a mnemonic phrase
func EntropyToMnemonic(entropy []byte) (string, error) {
	if len(entropy) != EntropyBits/8 {
		return "", errors.New("entropy must be 16 bytes for 12-word mnemonic")
	}

	// Add checksum: first 4 bits of SHA256(entropy)
	hash := sha256.Sum256(entropy)
	checksumByte := hash[0]

	// Combine entropy + checksum into bit string
	// 128 bits entropy + 4 bits checksum = 132 bits = 12 * 11 bits
	bits := make([]bool, EntropyBits+ChecksumBits)

	for i := 0; i < EntropyBits; i++ {
		bits[i] = (entropy[i/8] & (1 << (7 - (i % 8)))) != 0
	}
	for i := 0; i < ChecksumBits; i++ {
		bits[EntropyBits+i] = (checksumByte & (1 << (7 - i))) != 0
	}

	// Convert to word indices
	words := make([]string, WordCount)
	for i := 0; i < WordCount; i++ {
		idx := 0
		for j := 0; j < WordBits; j++ {
			if bits[i*WordBits+j] {
				idx |= 1 << (WordBits - 1 - j)
			}
		}
		words[i] = wordlist[idx]
	}

	return strings.Join(words, " "), nil
}

// MnemonicToEntropy converts a mnemonic phrase back to entropy bytes
func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	words := strings.Fields(strings.ToLower(strings.TrimSpace(mnemonic)))
	if len(words) != WordCount {
		return nil, ErrInvalidWordCount
	}

	// Convert words to indices
	indices := make([]int, WordCount)
	for i, word := range words {
		idx, ok := wordIndex[word]
		if !ok {
			return nil, ErrInvalidWord
		}
		indices[i] = idx
	}

	// Convert indices to bits
	bits := make([]bool, WordCount*WordBits)
	for i, idx := range indices {
		for j := 0; j < WordBits; j++ {
			bits[i*WordBits+j] = (idx & (1 << (WordBits - 1 - j))) != 0
		}
	}

	// Extract entropy (first 128 bits)
	entropy := make([]byte, EntropyBits/8)
	for i := 0; i < EntropyBits; i++ {
		if bits[i] {
			entropy[i/8] |= 1 << (7 - (i % 8))
		}
	}

	// Extract checksum (last 4 bits)
	var checksumBits byte
	for i := 0; i < ChecksumBits; i++ {
		if bits[EntropyBits+i] {
			checksumBits |= 1 << (7 - i)
		}
	}

	// Verify checksum
	hash := sha256.Sum256(entropy)
	expectedChecksum := hash[0] & 0xF0 // Top 4 bits
	if checksumBits != expectedChecksum {
		return nil, ErrInvalidChecksum
	}

	return entropy, nil
}

// MnemonicToSeed derives a 64-byte seed from a mnemonic and optional passphrase
// Uses PBKDF2-HMAC-SHA512 as per BIP39
func MnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	// Validate mnemonic first
	if _, err := MnemonicToEntropy(mnemonic); err != nil {
		return nil, err
	}

	// BIP39 uses "mnemonic" + passphrase as salt
	salt := "mnemonic" + passphrase

	// PBKDF2 with SHA512
	seed := pbkdf2.Key(
		[]byte(strings.ToLower(strings.TrimSpace(mnemonic))),
		[]byte(salt),
		PBKDF2Rounds,
		SeedBytes,
		sha512.New,
	)

	return seed, nil
}

// ValidateMnemonic checks if a mnemonic is valid
func ValidateMnemonic(mnemonic string) bool {
	_, err := MnemonicToEntropy(mnemonic)
	return err == nil
}

// DeriveKeysFromSeed derives spend and view keypairs from a 64-byte seed
// Returns: spendPriv, spendPub, viewPriv, viewPub
func DeriveKeysFromSeed(seed []byte, generateKeypair func(seed [32]byte) ([32]byte, [32]byte, error)) (*StealthKeys, error) {
	if len(seed) < 64 {
		return nil, errors.New("seed must be at least 64 bytes")
	}

	// Derive spend key from first 32 bytes
	var spendSeed [32]byte
	copy(spendSeed[:], seed[:32])
	spendPriv, spendPub, err := generateKeypair(spendSeed)
	if err != nil {
		return nil, err
	}

	// Derive view key from last 32 bytes
	var viewSeed [32]byte
	copy(viewSeed[:], seed[32:64])
	viewPriv, viewPub, err := generateKeypair(viewSeed)
	if err != nil {
		return nil, err
	}

	return &StealthKeys{
		SpendPrivKey: spendPriv,
		SpendPubKey:  spendPub,
		ViewPrivKey:  viewPriv,
		ViewPubKey:   viewPub,
	}, nil
}

// Word index lookup map (built at init)
var wordIndex map[string]int

func init() {
	wordIndex = make(map[string]int, len(wordlist))
	for i, word := range wordlist {
		wordIndex[word] = i
	}
}
