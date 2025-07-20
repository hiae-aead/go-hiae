package hiae

import (
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

// getState returns a copy of the state block at logical position i
func (h *HiAE) getState(i int) []byte {
	idx := h.getStateIndex(i)
	block := make([]byte, BlockLen)
	copy(block, h.state[idx][:])
	return block
}

// setState sets the state block at logical position i
func (h *HiAE) setState(i int, block []byte) {
	if len(block) != BlockLen {
		panic("setState: block must be exactly 16 bytes")
	}
	idx := h.getStateIndex(i)
	copy(h.state[idx][:], block)
}

// xorState XORs a block with the state at logical position i
func (h *HiAE) xorState(i int, block []byte) {
	if len(block) != BlockLen {
		panic("xorState: block must be exactly 16 bytes")
	}
	idx := h.getStateIndex(i)
	for j := 0; j < BlockLen; j++ {
		h.state[idx][j] ^= block[j]
	}
}

// update implements the core Update function
func (h *HiAE) update(xi []byte) {
	if len(xi) != BlockLen {
		panic("update: input must be exactly 16 bytes")
	}

	// t = AESL(S0 ^ S1) ^ xi
	s0 := h.getState(0)
	s1 := h.getState(1)
	s0XorS1 := xorBytes(s0, s1)
	aeslResult := AESL(s0XorS1)
	t := xorBytes(aeslResult, xi)

	// S0 = AESL(S13) ^ t
	s13 := h.getState(13)
	aeslS13 := AESL(s13)
	newS0 := xorBytes(aeslS13, t)
	h.setState(0, newS0)

	// S3 = S3 ^ xi
	h.xorState(3, xi)

	// S13 = S13 ^ xi
	h.xorState(13, xi)

	// Rol()
	h.rol()
}

// updateEnc implements the UpdateEnc function for encryption
func (h *HiAE) updateEnc(mi []byte) []byte {
	if len(mi) != BlockLen {
		panic("updateEnc: input must be exactly 16 bytes")
	}

	// t = AESL(S0 ^ S1) ^ mi
	s0 := h.getState(0)
	s1 := h.getState(1)
	s0XorS1 := xorBytes(s0, s1)
	aeslResult := AESL(s0XorS1)
	t := xorBytes(aeslResult, mi)

	// ci = t ^ S9
	s9 := h.getState(9)
	ci := xorBytes(t, s9)

	// S0 = AESL(S13) ^ t
	s13 := h.getState(13)
	aeslS13 := AESL(s13)
	newS0 := xorBytes(aeslS13, t)
	h.setState(0, newS0)

	// S3 = S3 ^ mi
	h.xorState(3, mi)

	// S13 = S13 ^ mi
	h.xorState(13, mi)

	// Rol()
	h.rol()

	return ci
}

// updateDec implements the UpdateDec function for decryption
func (h *HiAE) updateDec(ci []byte) []byte {
	if len(ci) != BlockLen {
		panic("updateDec: input must be exactly 16 bytes")
	}

	// t = ci ^ S9
	s9 := h.getState(9)
	t := xorBytes(ci, s9)

	// mi = AESL(S0 ^ S1) ^ t
	s0 := h.getState(0)
	s1 := h.getState(1)
	s0XorS1 := xorBytes(s0, s1)
	aeslResult := AESL(s0XorS1)
	mi := xorBytes(aeslResult, t)

	// S0 = AESL(S13) ^ t
	s13 := h.getState(13)
	aeslS13 := AESL(s13)
	newS0 := xorBytes(aeslS13, t)
	h.setState(0, newS0)

	// S3 = S3 ^ mi
	h.xorState(3, mi)

	// S13 = S13 ^ mi
	h.xorState(13, mi)

	// Rol()
	h.rol()

	return mi
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

	// Split key into k0 and k1
	k0 := make([]byte, BlockLen)
	k1 := make([]byte, BlockLen)
	copy(k0, key[:BlockLen])
	copy(k1, key[BlockLen:])

	// Initialize state as per specification
	h.setState(0, C0)
	h.setState(1, k1)
	h.setState(2, nonce)
	h.setState(3, C0)
	h.setState(4, make([]byte, BlockLen)) // all zeros
	h.setState(5, xorBytes(nonce, k0))
	h.setState(6, make([]byte, BlockLen)) // all zeros
	h.setState(7, C1)
	h.setState(8, xorBytes(nonce, k1))
	h.setState(9, make([]byte, BlockLen)) // all zeros
	h.setState(10, k1)
	h.setState(11, C0)
	h.setState(12, C1)
	h.setState(13, k1)
	h.setState(14, make([]byte, BlockLen)) // all zeros
	h.setState(15, xorBytes(C0, C1))

	// Diffuse with C0
	h.diffuse(C0)

	// Final XORs
	h.xorState(9, k0)
	h.xorState(13, k1)
}

// absorb processes associated data
func (h *HiAE) absorb(ai []byte) {
	if len(ai) != BlockLen {
		panic("absorb: input must be exactly 16 bytes")
	}
	h.update(ai)
}

// enc encrypts a single message block
func (h *HiAE) enc(mi []byte) []byte {
	if len(mi) != BlockLen {
		panic("enc: input must be exactly 16 bytes")
	}
	return h.updateEnc(mi)
}

// dec decrypts a single ciphertext block
func (h *HiAE) dec(ci []byte) []byte {
	if len(ci) != BlockLen {
		panic("dec: input must be exactly 16 bytes")
	}
	return h.updateDec(ci)
}

// decPartial handles decryption of partial blocks
func (h *HiAE) decPartial(cn []byte) []byte {
	if len(cn) == 0 || len(cn) >= BlockLen {
		panic("decPartial: input must be 1-15 bytes")
	}

	// Step 1: Recover the keystream that would encrypt a full zero block
	s0 := h.getState(0)
	s1 := h.getState(1)
	s0XorS1 := xorBytes(s0, s1)
	aeslResult := AESL(s0XorS1)

	// Create zero-padded version of cn
	cnPadded := make([]byte, BlockLen)
	copy(cnPadded, cn)

	s9 := h.getState(9)
	ks := xorBytes(xorBytes(aeslResult, cnPadded), s9)

	// Step 2: Construct a full 128-bit ciphertext block
	ci := make([]byte, BlockLen)
	copy(ci, cn)
	copy(ci[len(cn):], ks[len(cn):])

	// Step 3: Decrypt the full block using standard UpdateDec
	mi := h.updateDec(ci)

	// Step 4: Extract only the decrypted bytes corresponding to the partial input
	mn := make([]byte, len(cn))
	copy(mn, mi[:len(cn)])

	return mn
}

// finalize generates the authentication tag
func (h *HiAE) finalize(adLenBits, msgLenBits uint64) []byte {
	// Create length encoding block
	adLen := le64(adLenBits)
	msgLen := le64(msgLenBits)
	t := append(adLen, msgLen...)

	// Diffuse with length block
	h.diffuse(t)

	// Compute tag as XOR of all state blocks
	tag := make([]byte, BlockLen)
	for i := 0; i < StateLen; i++ {
		si := h.getState(i)
		for j := 0; j < BlockLen; j++ {
			tag[j] ^= si[j]
		}
	}

	return tag
}

// Encrypt encrypts a message with associated data
func Encrypt(msg, ad, key, nonce []byte) ([]byte, []byte, error) {
	if len(key) != KeyLen {
		return nil, nil, errors.New("key must be 32 bytes")
	}
	if len(nonce) != NonceLen {
		return nil, nil, errors.New("nonce must be 16 bytes")
	}

	h := NewHiAE()
	h.init(key, nonce)

	// Process associated data
	forEachChunkZeroPadded(ad, BlockLen, func(block []byte) {
		h.absorb(block)
	})

	// Process message
	ct := make([]byte, 0, len(msg))
	forEachChunkZeroPadded(msg, BlockLen, func(block []byte) {
		ctBlock := h.enc(block)
		ct = append(ct, ctBlock...)
	})

	// Generate tag
	tag := h.finalize(uint64(len(ad)*8), uint64(len(msg)*8))

	// Truncate ciphertext to message length
	ct = ct[:len(msg)]

	return ct, tag, nil
}

// Decrypt decrypts a ciphertext with associated data and verifies authentication
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

	h := NewHiAE()
	h.init(key, nonce)

	// Process associated data
	forEachChunkZeroPadded(ad, BlockLen, func(block []byte) {
		h.absorb(block)
	})

	// Process ciphertext
	msg := make([]byte, 0, len(ct))
	forEachChunk(ct, BlockLen, func(block []byte) {
		if len(block) == BlockLen {
			// Full block - use standard decryption
			msgBlock := h.dec(block)
			msg = append(msg, msgBlock...)
		} else {
			// Partial block - use partial decryption
			partialMsg := h.decPartial(block)
			msg = append(msg, partialMsg...)
		}
	})

	// Generate expected tag
	expectedTag := h.finalize(uint64(len(ad)*8), uint64(len(msg)*8))

	// Verify tag in constant time
	if !ctEq(tag, expectedTag) {
		zeroBytes(msg)
		zeroBytes(expectedTag)
		return nil, errors.New("authentication verification failed")
	}

	return msg, nil
}
