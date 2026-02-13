package main

import "encoding/binary"

// Aux data wire format (appended after TX bytes):
//
//	[0xAD marker byte]
//	[count: uint8]          — number of payment ID entries
//	for each entry:
//	  [outIdx: uint8]       — output index
//	  [encPaymentID: 8 bytes]
//
// Old nodes ignore trailing bytes after DeserializeTx, so this is
// backward compatible.

const auxMarker = 0xAD

// EncodeTxWithAux appends aux data after the TX bytes.
func EncodeTxWithAux(txData []byte, aux *TxAuxData) []byte {
	if aux == nil || len(aux.PaymentIDs) == 0 {
		return txData
	}

	// marker(1) + count(1) + entries(count * 9)
	extra := 2 + len(aux.PaymentIDs)*9
	result := make([]byte, len(txData)+extra)
	copy(result, txData)

	off := len(txData)
	result[off] = auxMarker
	off++
	result[off] = byte(len(aux.PaymentIDs))
	off++

	for outIdx, pid := range aux.PaymentIDs {
		result[off] = byte(outIdx)
		off++
		copy(result[off:off+8], pid[:])
		off += 8
	}

	return result
}

// DecodeTxWithAux splits a message into TX bytes and optional aux data.
// Returns the raw TX data and a TxAuxData (nil if no aux present).
func DecodeTxWithAux(data []byte) (txData []byte, aux *TxAuxData) {
	// Try to find aux data by scanning from what DeserializeTx would consume.
	// We re-parse to find the TX boundary, then check for the marker.
	txLen := findTxBoundary(data)
	if txLen <= 0 || txLen >= len(data) {
		return data, nil
	}

	tail := data[txLen:]
	if len(tail) < 2 || tail[0] != auxMarker {
		return data, nil
	}

	count := int(tail[1])
	expected := 2 + count*9
	if len(tail) < expected {
		return data[:txLen], nil
	}

	paymentIDs := make(map[int][8]byte)
	off := 2
	for i := 0; i < count; i++ {
		outIdx := int(tail[off])
		off++
		var pid [8]byte
		copy(pid[:], tail[off:off+8])
		off += 8
		paymentIDs[outIdx] = pid
	}

	return data[:txLen], &TxAuxData{PaymentIDs: paymentIDs}
}

// findTxBoundary parses the binary TX format to find where the TX data ends.
// Returns the byte offset after the last byte of the transaction.
func findTxBoundary(data []byte) int {
	// Hard limits derived from protocol constants (crypto.go).
	// DeserializeTx uses looser values; these match actual production ceilings.
	const (
		maxInputs     = 256
		maxOutputs    = 256
		maxRingSize   = RingSize           // fixed 16 (15 decoys + 1 real)
		maxProofSize  = 1024               // Bulletproof buffer size in CreateRangeProof
		maxSigSize    = 96 + 64*RingSize   // RingCT CLSAG buffer size in SignRingCT (1120)
		minHeaderSize = 1 + 32 + 4 + 4 + 8
	)

	if len(data) < minHeaderSize {
		return len(data)
	}

	off := 0
	off++ // version
	off += 32 // txPubKey

	if off+4 > len(data) {
		return len(data)
	}
	inputCount := int(binary.LittleEndian.Uint32(data[off:]))
	off += 4
	if inputCount > maxInputs {
		return len(data)
	}

	if off+4 > len(data) {
		return len(data)
	}
	outputCount := int(binary.LittleEndian.Uint32(data[off:]))
	off += 4
	if outputCount > maxOutputs {
		return len(data)
	}

	off += 8 // fee

	// Skip outputs
	for i := 0; i < outputCount; i++ {
		off += 32 + 32 + 8 // pubkey + commitment + encrypted amount
		if off+4 > len(data) {
			return len(data)
		}
		proofLen := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if proofLen > maxProofSize {
			return len(data)
		}
		off += proofLen
		if off > len(data) {
			return len(data)
		}
	}

	// Skip inputs
	for i := 0; i < inputCount; i++ {
		off += 32 + 32 // keyImage + pseudoOutput
		if off+4 > len(data) {
			return len(data)
		}
		ringSize := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if ringSize > maxRingSize {
			return len(data)
		}
		off += ringSize * 32 // ring member keys
		off += ringSize * 32 // ring member commitments
		if off+4 > len(data) {
			return len(data)
		}
		sigLen := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if sigLen > maxSigSize {
			return len(data)
		}
		off += sigLen
		if off > len(data) {
			return len(data)
		}
	}

	return off
}
