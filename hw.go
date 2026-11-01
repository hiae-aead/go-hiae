package hiae

// useAESLAsm is set when the CPU has AES-NI or the ARM crypto extension.
// encNI / decNI are the block loops. Nil means the Go update path.
var (
	useAESLAsm bool
	encNI      func(s *byte, off *int, in, out *byte, n uint64)
	decNI      func(s *byte, off *int, in, out *byte, n uint64)
)

// encBlocks encrypts n = len(in)/16 blocks at the current offset.
// One call covers any offset. The tail shorter than a block stays with enc.
func (h *HiAE) encBlocks(in, out []byte) {
	n := len(in) / BlockLen
	if n > len(out)/BlockLen {
		panic("encBlocks: output too small")
	}
	if n == 0 {
		return
	}
	if encNI != nil {
		encNI(&h.state[0][0], &h.offset, &in[0], &out[0], uint64(n))
		return
	}
	for i := 0; i < n*BlockLen; i += BlockLen {
		h.enc(in[i:i+BlockLen], out[i:i+BlockLen])
	}
}

// decBlocks decrypts n = len(in)/16 blocks at the current offset.
func (h *HiAE) decBlocks(in, out []byte) {
	n := len(in) / BlockLen
	if n > len(out)/BlockLen {
		panic("decBlocks: output too small")
	}
	if n == 0 {
		return
	}
	if decNI != nil {
		decNI(&h.state[0][0], &h.offset, &in[0], &out[0], uint64(n))
		return
	}
	for i := 0; i < n*BlockLen; i += BlockLen {
		h.dec(in[i:i+BlockLen], out[i:i+BlockLen])
	}
}
