package main

import (
	"strings"
	"testing"
)

func TestVerifyRangeProofRejectsEmptyProof(t *testing.T) {
	err := VerifyRangeProof([32]byte{}, &RangeProof{Proof: nil})
	if err == nil {
		t.Fatal("expected empty range proof to be rejected")
	}
	if !strings.Contains(err.Error(), "range proof must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyRingRejectsEmptySignature(t *testing.T) {
	ring := [][32]byte{{}}
	err := VerifyRing(ring, []byte("msg"), &RingSignature{
		RingSize:  1,
		Signature: nil,
	})
	if err == nil {
		t.Fatal("expected empty ring signature to be rejected")
	}
	if !strings.Contains(err.Error(), "ring signature must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTransactionRejectsEmptyRingCTSignature(t *testing.T) {
	txData := mustCraftMalformedTxVariant(t, "empty-ringct-signature")
	tx, err := DeserializeTx(txData)
	if err != nil {
		t.Fatalf("failed to deserialize malformed tx variant: %v", err)
	}

	err = ValidateTransaction(
		tx,
		func(_ [32]byte) bool { return false },
		func(_, _ [32]byte) bool { return true },
	)
	if err == nil {
		t.Fatal("expected transaction with empty RingCT signature to be rejected")
	}
	if !strings.Contains(err.Error(), "RingCT signature must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractRingCTBindingReturnsEmbeddedFields(t *testing.T) {
	expectedLen := 32 + RingSize*32 + RingSize*32 + 32 + 32
	signature := make([]byte, expectedLen)

	var wantKeyImage [32]byte
	var wantPseudoOutput [32]byte
	for i := 0; i < 32; i++ {
		wantKeyImage[i] = byte(i + 1)
		wantPseudoOutput[i] = byte(255 - i)
	}

	kiOffset := 32 + RingSize*32 + RingSize*32
	copy(signature[kiOffset:kiOffset+32], wantKeyImage[:])
	copy(signature[kiOffset+32:kiOffset+64], wantPseudoOutput[:])

	gotKeyImage, gotPseudoOutput, err := ExtractRingCTBinding(&RingCTSignature{
		Signature: signature,
		RingSize:  RingSize,
	})
	if err != nil {
		t.Fatalf("expected valid RingCT binding extraction, got error: %v", err)
	}
	if gotKeyImage != wantKeyImage {
		t.Fatalf("key image mismatch: got %x, want %x", gotKeyImage, wantKeyImage)
	}
	if gotPseudoOutput != wantPseudoOutput {
		t.Fatalf("pseudo-output mismatch: got %x, want %x", gotPseudoOutput, wantPseudoOutput)
	}
}

func TestExtractRingCTBindingRejectsInvalidSignatureLength(t *testing.T) {
	expectedLen := 32 + RingSize*32 + RingSize*32 + 32 + 32
	_, _, err := ExtractRingCTBinding(&RingCTSignature{
		Signature: make([]byte, expectedLen-1),
		RingSize:  RingSize,
	})
	if err == nil {
		t.Fatal("expected invalid RingCT signature length to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid RingCT signature length") {
		t.Fatalf("unexpected error: %v", err)
	}
}
