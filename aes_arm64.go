//go:build arm64 && !purego

package hiae

import "golang.org/x/sys/cpu"

func init() {
	if cpu.ARM64.HasAES {
		useAESLAsm = true
		encNI = hiaeEncNI
		decNI = hiaeDecNI
	}
}

// SupportsHardwareAES reports the ARM crypto extension.
func SupportsHardwareAES() bool { return useAESLAsm }

func aeslInPlaceOptimized(input, output []byte) {
	if len(input) != 16 || len(output) != 16 {
		panic("aeslInPlaceOptimized: input and output must be exactly 16 bytes")
	}
	if useAESLAsm {
		aeslAsm(&output[0], &input[0])
		return
	}
	aeslInPlaceGeneric(input, output)
}

func updateEncOptimized(h *HiAE, mi, ci []byte) {
	if len(mi) != BlockLen || len(ci) != BlockLen {
		panic("updateEncOptimized: input and output must be exactly 16 bytes")
	}
	if encNI != nil {
		encNI(&h.state[0][0], &h.offset, &mi[0], &ci[0], 1)
		return
	}
	updateEncGeneric(h, mi, ci)
}

func updateDecOptimized(h *HiAE, ci, mi []byte) {
	if len(ci) != BlockLen || len(mi) != BlockLen {
		panic("updateDecOptimized: input and output must be exactly 16 bytes")
	}
	if decNI != nil {
		decNI(&h.state[0][0], &h.offset, &ci[0], &mi[0], 1)
		return
	}
	updateDecGeneric(h, ci, mi)
}

//go:noescape
func aeslAsm(dst, src *byte)

//go:noescape
func hiaeEncNI(s *byte, off *int, in, out *byte, n uint64)

//go:noescape
func hiaeDecNI(s *byte, off *int, in, out *byte, n uint64)
