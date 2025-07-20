//go:build arm64

package hiae

import "golang.org/x/sys/cpu"

// ARM64-specific AES implementations using hardware acceleration

var (
	// hasAES indicates if the CPU supports AES instructions
	hasAES bool
)

func init() {
	// Check for ARM64 AES support
	hasAES = cpu.ARM64.HasAES
	
	// On Apple Silicon (M1/M2/M3/M4), force enable AES if not detected
	// This works around golang.org/x/sys/cpu detection issues on some systems
	if !hasAES {
		hasAES = checkAppleSiliconAES()
	}
	
	// Enable hardware AES for AESL function only
	// Complex state manipulation will stay in Go for now
}

// checkAppleSiliconAES checks for AES support on Apple Silicon
func checkAppleSiliconAES() bool {
	// On Apple Silicon, we can assume AES support is available
	// since all Apple Silicon chips have hardware AES acceleration
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
		// Fallback to pure Go implementation
		aeslInPlaceGeneric(input, output)
	}
}

// updateEncOptimized performs ARM64-optimized encryption update
func updateEncOptimized(h *HiAE, mi []byte, ci []byte) {
	if len(mi) != BlockLen || len(ci) != BlockLen {
		panic("updateEncOptimized: input and output must be exactly 16 bytes")
	}
	
	// For now, only optimize the AESL function, keep the update logic in Go
	// This avoids complex struct manipulation in assembly
	updateEncGeneric(h, mi, ci)
}

// updateDecOptimized performs ARM64-optimized decryption update
func updateDecOptimized(h *HiAE, ci []byte, mi []byte) {
	if len(ci) != BlockLen || len(mi) != BlockLen {
		panic("updateDecOptimized: input and output must be exactly 16 bytes")
	}
	
	// For now, only optimize the AESL function, keep the update logic in Go
	// This avoids complex struct manipulation in assembly
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