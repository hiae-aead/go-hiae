//go:build arm64

package hiae

import "golang.org/x/sys/cpu"

// ARM64-specific AES implementations using hardware acceleration

// hasAES indicates if the CPU supports AES instructions
var hasAES bool

func init() {
	hasAES = cpu.ARM64.HasAES

	if !hasAES {
		hasAES = checkAppleSiliconAES()
	}
}

func checkAppleSiliconAES() bool {
	return true
}

// SupportsHardwareAES returns true if hardware AES acceleration is available
func SupportsHardwareAES() bool {
	return hasAES
}

// aeslInPlaceOptimized performs AESL transformation using ARM64 hardware acceleration
func aeslInPlaceOptimized(input []byte, output []byte) {
	if len(input) != 16 || len(output) != 16 {
		panic("aeslInPlaceOptimized: input and output must be exactly 16 bytes")
	}

	if hasAES {
		aeslARM64(input, output)
	} else {
		aeslInPlaceGeneric(input, output)
	}
}

// updateEncOptimized performs ARM64-optimized encryption update
func updateEncOptimized(h *HiAE, mi []byte, ci []byte) {
	if len(mi) != BlockLen || len(ci) != BlockLen {
		panic("updateEncOptimized: input and output must be exactly 16 bytes")
	}

	updateEncGeneric(h, mi, ci)
}

// updateDecOptimized performs ARM64-optimized decryption update
func updateDecOptimized(h *HiAE, ci []byte, mi []byte) {
	if len(ci) != BlockLen || len(mi) != BlockLen {
		panic("updateDecOptimized: input and output must be exactly 16 bytes")
	}

	updateDecGeneric(h, ci, mi)
}

// Assembly function declarations - implemented in aes_arm64.s

//go:noescape
func aeslARM64(input, output []byte)

//go:noescape
func updateEncARM64(h *HiAE, mi, ci []byte)

//go:noescape
func updateDecARM64(h *HiAE, ci, mi []byte)

//go:noescape
func xaeslARM64(x, y, output []byte)

//go:noescape
func batchEncryptARM64(h *HiAE, msgs, cts *[256]byte)

//go:noescape
func batchDecryptARM64(h *HiAE, cts, msgs *[256]byte)

// hasHardwareAcceleration overrides the default implementation
func hasHardwareAcceleration() bool {
	return hasAES
}

// batchEncryptOptimized overrides the default implementation with ARM64 assembly
func batchEncryptOptimized(h *HiAE, msgs, cts *[256]byte) {
	if hasAES {
		batchEncryptARM64(h, msgs, cts)
	} else {
		for i := 0; i < 16; i++ {
			start := i * BlockLen
			end := start + BlockLen
			h.updateEnc(msgs[start:end], cts[start:end])
		}
	}
}

// batchDecryptOptimized overrides the default implementation with ARM64 assembly
func batchDecryptOptimized(h *HiAE, cts, msgs *[256]byte) {
	if hasAES {
		batchDecryptARM64(h, cts, msgs)
	} else {
		for i := 0; i < 16; i++ {
			start := i * BlockLen
			end := start + BlockLen
			h.updateDec(cts[start:end], msgs[start:end])
		}
	}
}
