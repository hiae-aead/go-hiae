package hiae

import (
	"encoding/binary"
	"errors"
)

// Constants as defined in the HiAE specification
var (
	C0 = []byte{
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
		0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
	}
	C1 = []byte{
		0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d,
		0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8,
	}
)

// Algorithm parameters
const (
	KeyLen   = 32 // 256 bits
	NonceLen = 16 // 128 bits
	TagLen   = 16 // 128 bits
	BlockLen = 16 // 128 bits (AES block size)
	StateLen = 16 // Number of state blocks
)

// HiAE represents the HiAE cipher state
type HiAE struct {
	state  [StateLen][BlockLen]byte // 16 AES blocks, each 16 bytes
	offset int                      // Cycling index for efficient rotation
}

// NewHiAE creates a new HiAE instance
func NewHiAE() *HiAE {
	return &HiAE{}
}

// rol performs left rotation of the state by one position
// Using cycling index optimization to avoid copying data
func (h *HiAE) rol() {
	h.offset = (h.offset + 1) % StateLen
}

// getStateIndex returns the physical index for a logical state position
func (h *HiAE) getStateIndex(logical int) int {
	return (logical + h.offset) % StateLen
}

// update implements the core Update function
func (h *HiAE) update(xi []byte) {
	if len(xi) != BlockLen {
		panic("update: input must be exactly 16 bytes")
	}

	// Calculate state indices
	idx0 := h.offset % StateLen
	idx1 := (1 + h.offset) % StateLen
	idx3 := (3 + h.offset) % StateLen
	idx13 := (13 + h.offset) % StateLen

	// t = AESL(S0 ^ S1) ^ xi - direct state access, no allocations
	var s0XorS1 [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		s0XorS1[i] = h.state[idx0][i] ^ h.state[idx1][i]
	}
	var aeslResult [BlockLen]byte
	aeslInPlace(s0XorS1[:], aeslResult[:])

	var t [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		t[i] = aeslResult[i] ^ xi[i]
	}

	// S0 = AESL(S13) ^ t - direct state access, no allocations
	var aeslS13 [BlockLen]byte
	aeslInPlace(h.state[idx13][:], aeslS13[:])
	for i := 0; i < BlockLen; i++ {
		h.state[idx0][i] = aeslS13[i] ^ t[i]
	}

	// S3 = S3 ^ xi - direct state access, no allocations
	for i := 0; i < BlockLen; i++ {
		h.state[idx3][i] ^= xi[i]
	}

	// S13 = S13 ^ xi - direct state access, no allocations
	for i := 0; i < BlockLen; i++ {
		h.state[idx13][i] ^= xi[i]
	}

	// Rol()
	h.rol()
}

// updateEnc implements the UpdateEnc function for encryption
func (h *HiAE) updateEnc(mi []byte, ci []byte) {
	if len(mi) != BlockLen {
		panic("updateEnc: input must be exactly 16 bytes")
	}
	if len(ci) != BlockLen {
		panic("updateEnc: output must be exactly 16 bytes")
	}

	// Calculate state indices
	idx0 := h.offset % StateLen
	idx1 := (1 + h.offset) % StateLen
	idx3 := (3 + h.offset) % StateLen
	idx9 := (9 + h.offset) % StateLen
	idx13 := (13 + h.offset) % StateLen

	// t = AESL(S0 ^ S1) ^ mi - direct state access, no allocations
	var s0XorS1 [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		s0XorS1[i] = h.state[idx0][i] ^ h.state[idx1][i]
	}
	var aeslResult [BlockLen]byte
	aeslInPlace(s0XorS1[:], aeslResult[:])

	var t [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		t[i] = aeslResult[i] ^ mi[i]
	}

	// ci = t ^ S9 - direct state access, no allocations
	for i := 0; i < BlockLen; i++ {
		ci[i] = t[i] ^ h.state[idx9][i]
	}

	// S0 = AESL(S13) ^ t - direct state access, no allocations
	var aeslS13 [BlockLen]byte
	aeslInPlace(h.state[idx13][:], aeslS13[:])
	for i := 0; i < BlockLen; i++ {
		h.state[idx0][i] = aeslS13[i] ^ t[i]
	}

	// S3 = S3 ^ mi - direct state access, no allocations
	for i := 0; i < BlockLen; i++ {
		h.state[idx3][i] ^= mi[i]
	}

	// S13 = S13 ^ mi - direct state access, no allocations
	for i := 0; i < BlockLen; i++ {
		h.state[idx13][i] ^= mi[i]
	}

	// Rol()
	h.rol()
}

// updateDec implements the UpdateDec function for decryption
func (h *HiAE) updateDec(ci []byte, mi []byte) {
	if len(ci) != BlockLen {
		panic("updateDec: input must be exactly 16 bytes")
	}
	if len(mi) != BlockLen {
		panic("updateDec: output must be exactly 16 bytes")
	}

	// Calculate state indices
	idx0 := h.offset % StateLen
	idx1 := (1 + h.offset) % StateLen
	idx3 := (3 + h.offset) % StateLen
	idx9 := (9 + h.offset) % StateLen
	idx13 := (13 + h.offset) % StateLen

	// t = ci ^ S9 - direct state access, no allocations
	var t [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		t[i] = ci[i] ^ h.state[idx9][i]
	}

	// mi = AESL(S0 ^ S1) ^ t - direct state access, no allocations
	var s0XorS1 [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		s0XorS1[i] = h.state[idx0][i] ^ h.state[idx1][i]
	}
	var aeslResult [BlockLen]byte
	aeslInPlace(s0XorS1[:], aeslResult[:])

	for i := 0; i < BlockLen; i++ {
		mi[i] = aeslResult[i] ^ t[i]
	}

	// S0 = AESL(S13) ^ t - direct state access, no allocations
	var aeslS13 [BlockLen]byte
	aeslInPlace(h.state[idx13][:], aeslS13[:])
	for i := 0; i < BlockLen; i++ {
		h.state[idx0][i] = aeslS13[i] ^ t[i]
	}

	// S3 = S3 ^ mi - direct state access, no allocations
	for i := 0; i < BlockLen; i++ {
		h.state[idx3][i] ^= mi[i]
	}

	// S13 = S13 ^ mi - direct state access, no allocations
	for i := 0; i < BlockLen; i++ {
		h.state[idx13][i] ^= mi[i]
	}

	// Rol()
	h.rol()
}

// diffuse performs 32 rounds of update for full state diffusion
func (h *HiAE) diffuse(x []byte) {
	if len(x) != BlockLen {
		panic("diffuse: input must be exactly 16 bytes")
	}
	for i := 0; i < 32; i++ {
		h.update(x)
	}
}

// init initializes the HiAE state with key and nonce
func (h *HiAE) init(key, nonce []byte) {
	if len(key) != KeyLen {
		panic("init: key must be exactly 32 bytes")
	}
	if len(nonce) != NonceLen {
		panic("init: nonce must be exactly 16 bytes")
	}

	// Split key into k0 and k1 - use slices to avoid allocation
	k0 := key[:BlockLen]
	k1 := key[BlockLen:]

	// Initialize state as per specification - direct state access, no allocations
	copy(h.state[0][:], C0)
	copy(h.state[1][:], k1)
	copy(h.state[2][:], nonce)
	copy(h.state[3][:], C0)
	for i := 0; i < BlockLen; i++ {
		h.state[4][i] = 0 // all zeros
	}
	// h.setState(5, xorBytes(nonce, k0)) -> direct XOR
	for i := 0; i < BlockLen; i++ {
		h.state[5][i] = nonce[i] ^ k0[i]
	}
	for i := 0; i < BlockLen; i++ {
		h.state[6][i] = 0 // all zeros
	}
	copy(h.state[7][:], C1)
	// h.setState(8, xorBytes(nonce, k1)) -> direct XOR
	for i := 0; i < BlockLen; i++ {
		h.state[8][i] = nonce[i] ^ k1[i]
	}
	for i := 0; i < BlockLen; i++ {
		h.state[9][i] = 0 // all zeros
	}
	copy(h.state[10][:], k1)
	copy(h.state[11][:], C0)
	copy(h.state[12][:], C1)
	copy(h.state[13][:], k1)
	for i := 0; i < BlockLen; i++ {
		h.state[14][i] = 0 // all zeros
	}
	// h.setState(15, xorBytes(C0, C1)) -> direct XOR
	for i := 0; i < BlockLen; i++ {
		h.state[15][i] = C0[i] ^ C1[i]
	}

	// Diffuse with C0
	h.diffuse(C0)

	// Final XORs - direct state access, no allocations
	for i := 0; i < BlockLen; i++ {
		h.state[9][i] ^= k0[i]
	}
	for i := 0; i < BlockLen; i++ {
		h.state[13][i] ^= k1[i]
	}
}

// absorb processes associated data
func (h *HiAE) absorb(ai []byte) {
	if len(ai) != BlockLen {
		panic("absorb: input must be exactly 16 bytes")
	}
	h.update(ai)
}

// enc encrypts a single message block
func (h *HiAE) enc(mi []byte, ci []byte) {
	if len(mi) != BlockLen {
		panic("enc: input must be exactly 16 bytes")
	}
	if len(ci) != BlockLen {
		panic("enc: output must be exactly 16 bytes")
	}
	h.updateEnc(mi, ci)
}

// dec decrypts a single ciphertext block
func (h *HiAE) dec(ci []byte, mi []byte) {
	if len(ci) != BlockLen {
		panic("dec: input must be exactly 16 bytes")
	}
	if len(mi) != BlockLen {
		panic("dec: output must be exactly 16 bytes")
	}
	h.updateDec(ci, mi)
}

// decPartial handles decryption of partial blocks
func (h *HiAE) decPartial(cn []byte, mn []byte) {
	if len(cn) == 0 || len(cn) >= BlockLen {
		panic("decPartial: input must be 1-15 bytes")
	}
	if len(mn) < len(cn) {
		panic("decPartial: output buffer too small")
	}

	// Calculate state indices
	idx0 := h.offset % StateLen
	idx1 := (1 + h.offset) % StateLen
	idx9 := (9 + h.offset) % StateLen

	// Step 1: Recover the keystream that would encrypt a full zero block - no allocations
	var s0XorS1 [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		s0XorS1[i] = h.state[idx0][i] ^ h.state[idx1][i]
	}
	var aeslResult [BlockLen]byte
	aeslInPlace(s0XorS1[:], aeslResult[:])

	// Create zero-padded version of cn - no allocations
	var cnPadded [BlockLen]byte
	copy(cnPadded[:], cn)

	// ks = aeslResult ^ cnPadded ^ S9 - no allocations
	var ks [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		ks[i] = aeslResult[i] ^ cnPadded[i] ^ h.state[idx9][i]
	}

	// Step 2: Construct a full 128-bit ciphertext block
	var ci [BlockLen]byte
	copy(ci[:], cn)
	copy(ci[len(cn):], ks[len(cn):])

	// Step 3: Decrypt the full block using standard UpdateDec
	var mi [BlockLen]byte
	h.updateDec(ci[:], mi[:])

	// Step 4: Extract only the decrypted bytes corresponding to the partial input
	copy(mn, mi[:len(cn)])
}

// finalize generates the authentication tag
func (h *HiAE) finalize(adLenBits, msgLenBits uint64, tag []byte) {
	if len(tag) != TagLen {
		panic("finalize: tag buffer must be exactly 16 bytes")
	}

	// Create length encoding block - zero allocation
	var t [BlockLen]byte
	binary.LittleEndian.PutUint64(t[0:8], adLenBits)
	binary.LittleEndian.PutUint64(t[8:16], msgLenBits)

	// Diffuse with length block
	h.diffuse(t[:])

	// Compute tag as XOR of all state blocks - direct state access, no allocations
	for j := 0; j < BlockLen; j++ {
		tag[j] = 0
	}
	for i := 0; i < StateLen; i++ {
		idx := (i + h.offset) % StateLen
		for j := 0; j < BlockLen; j++ {
			tag[j] ^= h.state[idx][j]
		}
	}
}

// EncryptTo encrypts a message with associated data, writing to provided output buffers (zero-allocation)
func EncryptTo(msg, ad, key, nonce, ctOut, tagOut []byte) error {
	if len(key) != KeyLen {
		return errors.New("key must be 32 bytes")
	}
	if len(nonce) != NonceLen {
		return errors.New("nonce must be 16 bytes")
	}
	if len(ctOut) < len(msg) {
		return errors.New("ciphertext output buffer too small")
	}
	if len(tagOut) < TagLen {
		return errors.New("tag output buffer too small")
	}

	h := NewHiAE()
	h.init(key, nonce)

	// Process associated data
	if len(ad) > 0 {
		// Handle case where data is already aligned - no padding needed
		if len(ad)%BlockLen == 0 {
			numBlocks := len(ad) / BlockLen
			for i := 0; i < numBlocks; i++ {
				start := i * BlockLen
				end := start + BlockLen
				h.absorb(ad[start:end])
			}
		} else {
			// Handle case where padding is needed
			numFullBlocks := len(ad) / BlockLen

			// Process full blocks first
			for i := 0; i < numFullBlocks; i++ {
				start := i * BlockLen
				end := start + BlockLen
				h.absorb(ad[start:end])
			}

			// Process the final partial block with padding
			remainder := len(ad) % BlockLen
			var paddedBlock [BlockLen]byte
			copy(paddedBlock[:], ad[len(ad)-remainder:])
			h.absorb(paddedBlock[:])
		}
	}

	// Process message - write directly to output buffer
	if len(msg) > 0 {
		// Handle case where data is already aligned - no padding needed
		if len(msg)%BlockLen == 0 {
			numBlocks := len(msg) / BlockLen
			for i := 0; i < numBlocks; i++ {
				start := i * BlockLen
				end := start + BlockLen
				h.enc(msg[start:end], ctOut[start:end])
			}
		} else {
			// Handle case where padding is needed
			numFullBlocks := len(msg) / BlockLen

			// Process full blocks first
			for i := 0; i < numFullBlocks; i++ {
				start := i * BlockLen
				end := start + BlockLen
				h.enc(msg[start:end], ctOut[start:end])
			}

			// Process the final partial block with padding
			remainder := len(msg) % BlockLen
			var paddedBlock [BlockLen]byte
			copy(paddedBlock[:], msg[len(msg)-remainder:])
			var ctBlock [BlockLen]byte
			h.enc(paddedBlock[:], ctBlock[:])
			copy(ctOut[numFullBlocks*BlockLen:], ctBlock[:remainder])
		}
	}

	// Generate tag
	h.finalize(uint64(len(ad)*8), uint64(len(msg)*8), tagOut)

	return nil
}

// Encrypt encrypts a message with associated data (backward compatibility wrapper)
func Encrypt(msg, ad, key, nonce []byte) ([]byte, []byte, error) {
	if len(key) != KeyLen {
		return nil, nil, errors.New("key must be 32 bytes")
	}
	if len(nonce) != NonceLen {
		return nil, nil, errors.New("nonce must be 16 bytes")
	}

	ct := make([]byte, len(msg))
	tag := make([]byte, TagLen)

	err := EncryptTo(msg, ad, key, nonce, ct, tag)
	if err != nil {
		return nil, nil, err
	}

	return ct, tag, nil
}

// DecryptTo decrypts a ciphertext with associated data and verifies authentication, writing to provided output buffer (zero-allocation)
func DecryptTo(ct, tag, ad, key, nonce, msgOut []byte) error {
	if len(key) != KeyLen {
		return errors.New("key must be 32 bytes")
	}
	if len(nonce) != NonceLen {
		return errors.New("nonce must be 16 bytes")
	}
	if len(tag) != TagLen {
		return errors.New("tag must be 16 bytes")
	}
	if len(msgOut) < len(ct) {
		return errors.New("message output buffer too small")
	}

	h := NewHiAE()
	h.init(key, nonce)

	// Process associated data
	if len(ad) > 0 {
		// Handle case where data is already aligned - no padding needed
		if len(ad)%BlockLen == 0 {
			numBlocks := len(ad) / BlockLen
			for i := 0; i < numBlocks; i++ {
				start := i * BlockLen
				end := start + BlockLen
				h.absorb(ad[start:end])
			}
		} else {
			// Handle case where padding is needed
			numFullBlocks := len(ad) / BlockLen

			// Process full blocks first
			for i := 0; i < numFullBlocks; i++ {
				start := i * BlockLen
				end := start + BlockLen
				h.absorb(ad[start:end])
			}

			// Process the final partial block with padding
			remainder := len(ad) % BlockLen
			var paddedBlock [BlockLen]byte
			copy(paddedBlock[:], ad[len(ad)-remainder:])
			h.absorb(paddedBlock[:])
		}
	}

	// Process ciphertext - write directly to output buffer
	msgOffset := 0
	forEachChunk(ct, BlockLen, func(block []byte) {
		if len(block) == BlockLen {
			// Full block - use standard decryption
			h.dec(block, msgOut[msgOffset:msgOffset+BlockLen])
			msgOffset += BlockLen
		} else {
			// Partial block - use partial decryption
			h.decPartial(block, msgOut[msgOffset:msgOffset+len(block)])
			msgOffset += len(block)
		}
	})

	// Generate expected tag
	var expectedTag [TagLen]byte
	h.finalize(uint64(len(ad)*8), uint64(len(ct)*8), expectedTag[:])

	// Verify tag in constant time
	if !ctEq(tag, expectedTag[:]) {
		zeroBytes(msgOut[:len(ct)])
		zeroBytes(expectedTag[:])
		return errors.New("authentication verification failed")
	}

	return nil
}

// Decrypt decrypts a ciphertext with associated data and verifies authentication (backward compatibility wrapper)
func Decrypt(ct, tag, ad, key, nonce []byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, errors.New("key must be 32 bytes")
	}
	if len(nonce) != NonceLen {
		return nil, errors.New("nonce must be 16 bytes")
	}
	if len(tag) != TagLen {
		return nil, errors.New("tag must be 16 bytes")
	}

	msg := make([]byte, len(ct))

	err := DecryptTo(ct, tag, ad, key, nonce, msg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}
