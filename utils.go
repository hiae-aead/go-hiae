package hiae

import (
	"crypto/subtle"
	"encoding/binary"
)

// xorBytes XORs two byte slices of equal length
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xorBytes: slices must have equal length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// xorBytesInPlace XORs two byte slices and stores result in dst
func xorBytesInPlace(dst, a, b []byte) {
	if len(a) != len(b) || len(dst) != len(a) {
		panic("xorBytesInPlace: all slices must have equal length")
	}
	for i := range a {
		dst[i] = a[i] ^ b[i]
	}
}

// le64 converts a uint64 to little-endian byte representation
func le64(x uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, x)
	return b
}

// zeroPad pads data with zeros to make its length a multiple of blockSize
func zeroPad(data []byte, blockSize int) []byte {
	if blockSize <= 0 {
		panic("zeroPad: blockSize must be positive")
	}

	padLen := (blockSize - (len(data) % blockSize)) % blockSize
	if padLen == 0 && len(data) > 0 {
		return data
	}

	result := make([]byte, len(data)+padLen)
	copy(result, data)
	return result
}

// truncate returns the first n bits of data as bytes
func truncate(data []byte, bits int) []byte {
	if bits < 0 {
		panic("truncate: bits cannot be negative")
	}
	if bits == 0 {
		return []byte{}
	}

	bytes := (bits + 7) / 8
	if bytes > len(data) {
		bytes = len(data)
	}

	result := make([]byte, bytes)
	copy(result, data[:bytes])

	// If we need to mask the last byte
	if bits%8 != 0 && bytes > 0 {
		mask := byte(0xFF << (8 - (bits % 8)))
		result[bytes-1] &= mask
	}

	return result
}

// tail returns the last n bits of data as bytes
func tail(data []byte, bits int) []byte {
	if bits < 0 {
		panic("tail: bits cannot be negative")
	}
	if bits == 0 {
		return []byte{}
	}

	totalBits := len(data) * 8
	if bits >= totalBits {
		result := make([]byte, len(data))
		copy(result, data)
		return result
	}

	bytes := (bits + 7) / 8
	startByte := len(data) - bytes

	result := make([]byte, bytes)
	copy(result, data[startByte:])

	// If we need to mask the first byte
	if bits%8 != 0 && bytes > 0 {
		shift := 8 - (bits % 8)
		mask := byte(0xFF >> shift)
		result[0] &= mask
	}

	return result
}

// split divides data into blockSize-byte blocks, ignoring partial blocks
func split(data []byte, blockSize int) [][]byte {
	if blockSize <= 0 {
		panic("split: blockSize must be positive")
	}

	numBlocks := len(data) / blockSize
	blocks := make([][]byte, numBlocks)

	for i := 0; i < numBlocks; i++ {
		start := i * blockSize
		end := start + blockSize
		blocks[i] = make([]byte, blockSize)
		copy(blocks[i], data[start:end])
	}

	return blocks
}

// ctEq performs constant-time comparison of two byte slices
func ctEq(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// zeroBytes securely zeros a byte slice
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// forEachChunk iterates over blockSize-byte chunks of data without allocation
// Partial blocks are passed with their actual size (not padded)
func forEachChunk(data []byte, blockSize int, fn func([]byte)) {
	if blockSize <= 0 {
		panic("forEachChunk: blockSize must be positive")
	}

	numFullBlocks := len(data) / blockSize

	// Process full blocks
	for i := 0; i < numFullBlocks; i++ {
		start := i * blockSize
		end := start + blockSize
		fn(data[start:end])
	}

	// Handle partial block if present
	remainder := len(data) % blockSize
	if remainder != 0 {
		fn(data[len(data)-remainder:])
	}
}

// processChunksToBuffer efficiently processes chunks and collects output
// Pre-allocates output buffer to avoid repeated allocations
func processChunksToBuffer(data []byte, blockSize int, expectedOutputLen int, fn func([]byte) []byte) []byte {
	if blockSize <= 0 {
		panic("processChunksToBuffer: blockSize must be positive")
	}

	result := make([]byte, 0, expectedOutputLen)

	numFullBlocks := len(data) / blockSize

	// Process full blocks
	for i := 0; i < numFullBlocks; i++ {
		start := i * blockSize
		end := start + blockSize
		output := fn(data[start:end])
		result = append(result, output...)
	}

	return result
}
