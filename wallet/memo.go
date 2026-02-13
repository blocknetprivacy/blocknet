package wallet

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const (
	MemoSize            = 128
	memoEnvelopeVersion = 0x01
	memoPayloadMax      = 124
)

// EncryptMemo builds a memo envelope and encrypts it with a shared secret.
func EncryptMemo(memo []byte, sharedSecret [32]byte, outputIndex int) ([MemoSize]byte, error) {
	envelope, err := buildMemoEnvelope(memo, sharedSecret, outputIndex)
	if err != nil {
		return [MemoSize]byte{}, err
	}
	mask := deriveMemoMask(sharedSecret, outputIndex)
	var encrypted [MemoSize]byte
	for i := 0; i < MemoSize; i++ {
		encrypted[i] = envelope[i] ^ mask[i]
	}
	return encrypted, nil
}

// DecryptMemo decrypts and validates a memo envelope.
// Returns (nil, true) for an empty memo payload.
func DecryptMemo(encrypted [MemoSize]byte, sharedSecret [32]byte, outputIndex int) ([]byte, bool) {
	mask := deriveMemoMask(sharedSecret, outputIndex)
	var plain [MemoSize]byte
	for i := 0; i < MemoSize; i++ {
		plain[i] = encrypted[i] ^ mask[i]
	}
	if plain[0] != memoEnvelopeVersion {
		return nil, false
	}
	length := int(plain[1])
	if length < 0 || length > memoPayloadMax {
		return nil, false
	}
	payload := plain[4 : 4+length]
	var expected [2]byte
	checksum := memoChecksum(payload)
	copy(expected[:], checksum[:2])
	if plain[2] != expected[0] || plain[3] != expected[1] {
		return nil, false
	}
	if length == 0 {
		return nil, true
	}
	out := make([]byte, length)
	copy(out, payload)
	return out, true
}

func buildMemoEnvelope(memo []byte, sharedSecret [32]byte, outputIndex int) ([MemoSize]byte, error) {
	if len(memo) > memoPayloadMax {
		return [MemoSize]byte{}, fmt.Errorf("memo too long: max %d bytes", memoPayloadMax)
	}
	var envelope [MemoSize]byte
	envelope[0] = memoEnvelopeVersion
	envelope[1] = byte(len(memo))
	checksum := memoChecksum(memo)
	copy(envelope[2:4], checksum[:2])
	copy(envelope[4:], memo)

	// Use cryptographic random padding to make empty memos indistinguishable.
	padStart := 4 + len(memo)
	if padStart < MemoSize {
		if _, err := rand.Read(envelope[padStart:]); err != nil {
			// Fallback to deterministic pad in the unlikely event rand fails.
			det := deriveMemoMask(sharedSecret, outputIndex)
			copy(envelope[padStart:], det[:MemoSize-padStart])
		}
	}
	return envelope, nil
}

func memoChecksum(payload []byte) [32]byte {
	h := sha3.New256()
	h.Write([]byte("blocknet_memo_checksum"))
	var payloadLen [2]byte
	binary.LittleEndian.PutUint16(payloadLen[:], uint16(len(payload)))
	h.Write(payloadLen[:])
	h.Write(payload)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func deriveMemoMask(sharedSecret [32]byte, outputIndex int) [MemoSize]byte {
	h := sha3.New256()
	h.Write([]byte("blocknet_memo_mask"))
	h.Write(sharedSecret[:])
	var outputIndexBytes [4]byte
	binary.LittleEndian.PutUint32(outputIndexBytes[:], uint32(outputIndex))
	h.Write(outputIndexBytes[:])
	seed := h.Sum(nil)

	var mask [MemoSize]byte
	for i := 0; i < 4; i++ {
		hi := sha3.New256()
		hi.Write(seed)
		var blockIndex [4]byte
		binary.LittleEndian.PutUint32(blockIndex[:], uint32(i))
		hi.Write(blockIndex[:])
		block := hi.Sum(nil)
		copy(mask[i*32:(i+1)*32], block)
	}
	return mask
}
