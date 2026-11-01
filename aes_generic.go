//go:build (!amd64 && !arm64) || purego

package hiae

// SupportsHardwareAES is false without AES-NI / AESE, and under purego.
func SupportsHardwareAES() bool { return false }

func aeslInPlaceOptimized(input, output []byte) {
	aeslInPlaceGeneric(input, output)
}

func updateEncOptimized(h *HiAE, mi, ci []byte) {
	updateEncGeneric(h, mi, ci)
}

func updateDecOptimized(h *HiAE, ci, mi []byte) {
	updateDecGeneric(h, ci, mi)
}
