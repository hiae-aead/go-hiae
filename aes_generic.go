//go:build !arm64

package hiae

// Generic fallback implementations for non-ARM64 platforms

// SupportsHardwareAES returns false for non-ARM64 platforms
func SupportsHardwareAES() bool {
	return false
}

// aeslInPlaceOptimized uses the generic implementation on non-ARM64 platforms
func aeslInPlaceOptimized(input []byte, output []byte) {
	aeslInPlaceGeneric(input, output)
}

// updateEncOptimized uses the generic implementation on non-ARM64 platforms
func updateEncOptimized(h *HiAE, mi []byte, ci []byte) {
	updateEncGeneric(h, mi, ci)
}

// updateDecOptimized uses the generic implementation on non-ARM64 platforms
func updateDecOptimized(h *HiAE, ci []byte, mi []byte) {
	updateDecGeneric(h, ci, mi)
}