package hiae

// Shared implementations used by both ARM64 and generic builds

// updateEncGeneric is the original pure Go implementation for encryption update
func updateEncGeneric(h *HiAE, mi []byte, ci []byte) {
	if len(mi) != BlockLen {
		panic("updateEncGeneric: input must be exactly 16 bytes")
	}
	if len(ci) != BlockLen {
		panic("updateEncGeneric: output must be exactly 16 bytes")
	}

	idx0 := h.offset % StateLen
	idx1 := (1 + h.offset) % StateLen
	idx3 := (3 + h.offset) % StateLen
	idx9 := (9 + h.offset) % StateLen
	idx13 := (13 + h.offset) % StateLen
	var s0XorS1 [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		s0XorS1[i] = h.state[idx0][i] ^ h.state[idx1][i]
	}
	var aeslResult [BlockLen]byte
	aeslInPlaceGeneric(s0XorS1[:], aeslResult[:])

	var t [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		t[i] = aeslResult[i] ^ mi[i]
	}

	for i := 0; i < BlockLen; i++ {
		ci[i] = t[i] ^ h.state[idx9][i]
	}

	var aeslS13 [BlockLen]byte
	aeslInPlaceGeneric(h.state[idx13][:], aeslS13[:])
	for i := 0; i < BlockLen; i++ {
		h.state[idx0][i] = aeslS13[i] ^ t[i]
	}

	for i := 0; i < BlockLen; i++ {
		h.state[idx3][i] ^= mi[i]
	}

	for i := 0; i < BlockLen; i++ {
		h.state[idx13][i] ^= mi[i]
	}
	h.rol()
}

// updateDecGeneric is the original pure Go implementation for decryption update
func updateDecGeneric(h *HiAE, ci []byte, mi []byte) {
	if len(ci) != BlockLen {
		panic("updateDecGeneric: input must be exactly 16 bytes")
	}
	if len(mi) != BlockLen {
		panic("updateDecGeneric: output must be exactly 16 bytes")
	}

	idx0 := h.offset % StateLen
	idx1 := (1 + h.offset) % StateLen
	idx3 := (3 + h.offset) % StateLen
	idx9 := (9 + h.offset) % StateLen
	idx13 := (13 + h.offset) % StateLen

	var t [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		t[i] = ci[i] ^ h.state[idx9][i]
	}
	var s0XorS1 [BlockLen]byte
	for i := 0; i < BlockLen; i++ {
		s0XorS1[i] = h.state[idx0][i] ^ h.state[idx1][i]
	}
	var aeslResult [BlockLen]byte
	aeslInPlaceGeneric(s0XorS1[:], aeslResult[:])

	for i := 0; i < BlockLen; i++ {
		mi[i] = aeslResult[i] ^ t[i]
	}

	var aeslS13 [BlockLen]byte
	aeslInPlaceGeneric(h.state[idx13][:], aeslS13[:])
	for i := 0; i < BlockLen; i++ {
		h.state[idx0][i] = aeslS13[i] ^ t[i]
	}

	for i := 0; i < BlockLen; i++ {
		h.state[idx3][i] ^= mi[i]
	}

	for i := 0; i < BlockLen; i++ {
		h.state[idx13][i] ^= mi[i]
	}
	h.rol()
}

// aeslInPlaceGeneric is the original pure Go implementation
func aeslInPlaceGeneric(input []byte, output []byte) {
	if len(input) != 16 || len(output) != 16 {
		panic("aeslInPlaceGeneric: input and output must be exactly 16 bytes")
	}

	state := bytesToState(input)
	state = subBytes(state)
	state = shiftRows(state)
	state = mixColumns(state)

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			output[i*4+j] = state[j][i]
		}
	}
}
