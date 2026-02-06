package p2p

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MaxMessageSize is the maximum size of a single message (16 MB)
	MaxMessageSize = 16 * 1024 * 1024
)

// writeLengthPrefixed writes data with a 4-byte big-endian length prefix
func writeLengthPrefixed(w io.Writer, data []byte) error {
	if len(data) > MaxMessageSize {
		return fmt.Errorf("message too large: %d > %d", len(data), MaxMessageSize)
	}

	// Write length prefix
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}

	// Write data
	_, err := w.Write(data)
	return err
}

// readLengthPrefixed reads length-prefixed data
func readLengthPrefixed(r io.Reader) ([]byte, error) {
	// Read length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d > %d", length, MaxMessageSize)
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	return data, nil
}

// writeMessage writes a message type byte followed by length-prefixed data
func writeMessage(w io.Writer, msgType byte, data []byte) error {
	if _, err := w.Write([]byte{msgType}); err != nil {
		return err
	}
	return writeLengthPrefixed(w, data)
}

// readMessage reads a message type byte followed by length-prefixed data
func readMessage(r io.Reader) (byte, []byte, error) {
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBuf); err != nil {
		return 0, nil, err
	}

	data, err := readLengthPrefixed(r)
	if err != nil {
		return 0, nil, err
	}

	return typeBuf[0], data, nil
}
