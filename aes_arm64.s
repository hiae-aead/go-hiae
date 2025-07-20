//go:build arm64

#include "textflag.h"

// aeslARM64 performs AESL(input) using ARM64 AES instructions
// func aeslARM64(input, output []byte)
TEXT ·aeslARM64(SB), NOSPLIT, $0-48
	MOVD	input_base+0(FP), R0    // R0 = input pointer
	MOVD	output_base+24(FP), R1  // R1 = output pointer
	
	// Load 128-bit input block into V0
	VLD1	(R0), [V0.B16]
	
	// AESL = SubBytes + ShiftRows + MixColumns
	// Use AESE with zero key (performs SubBytes + ShiftRows)
	VEOR	V1.B16, V1.B16, V1.B16 // V1 = zero vector for key
	AESE	V1.B16, V0.B16         // SubBytes + ShiftRows with zero key
	
	// Apply MixColumns
	AESMC	V0.B16, V0.B16         // MixColumns
	
	// Store result
	VST1	[V0.B16], (R1)
	
	RET

// xaeslARM64 performs AESL(x ^ y) using fused ARM64 operations
// func xaeslARM64(x, y, output []byte)
TEXT ·xaeslARM64(SB), NOSPLIT, $0-72
	MOVD	x_base+0(FP), R0       // R0 = x pointer
	MOVD	y_base+24(FP), R1      // R1 = y pointer
	MOVD	output_base+48(FP), R2 // R2 = output pointer
	
	// Load inputs
	VLD1	(R0), [V0.B16]         // V0 = x
	VLD1	(R1), [V1.B16]         // V1 = y
	
	// Fused AESL(x ^ y) = AESE(x, y) + AESMC
	AESE	V1.B16, V0.B16         // Equivalent to SubBytes(ShiftRows(x ^ y))
	AESMC	V0.B16, V0.B16         // MixColumns
	
	// Store result
	VST1	[V0.B16], (R2)
	
	RET

// updateEncARM64 performs ARM64-optimized encryption update
// func updateEncARM64(h *HiAE, mi, ci []byte)
TEXT ·updateEncARM64(SB), NOSPLIT, $0-72
	MOVD	h+0(FP), R0            // R0 = HiAE struct pointer
	MOVD	mi_base+24(FP), R1     // R1 = mi pointer
	MOVD	ci_base+48(FP), R2     // R2 = ci pointer
	
	// Load current offset - offset field is at end of state array
	MOVD	256(R0), R3            // R3 = h.offset (offset is at byte 256 in struct)
	
	// Calculate state indices
	AND	$15, R3, R4            // R4 = idx0 = offset % 16
	ADD	$1, R3, R5
	AND	$15, R5, R5            // R5 = idx1 = (1 + offset) % 16
	ADD	$3, R3, R6
	AND	$15, R6, R6            // R6 = idx3 = (3 + offset) % 16
	ADD	$9, R3, R7
	AND	$15, R7, R7            // R7 = idx9 = (9 + offset) % 16
	ADD	$13, R3, R8
	AND	$15, R8, R8            // R8 = idx13 = (13 + offset) % 16
	
	// Calculate state block addresses (each block is 16 bytes)
	// State starts at offset 0 in the struct
	LSL	$4, R4, R4             // R4 = idx0 * 16
	ADD	R0, R4, R4             // R4 = &h.state[idx0]
	LSL	$4, R5, R5             // R5 = idx1 * 16  
	ADD	R0, R5, R5             // R5 = &h.state[idx1]
	LSL	$4, R6, R6             // R6 = idx3 * 16
	ADD	R0, R6, R6             // R6 = &h.state[idx3]
	LSL	$4, R7, R7             // R7 = idx9 * 16
	ADD	R0, R7, R7             // R7 = &h.state[idx9]
	LSL	$4, R8, R8             // R8 = idx13 * 16
	ADD	R0, R8, R8             // R8 = &h.state[idx13]
	
	// Load state blocks and input
	VLD1	(R4), [V0.B16]         // V0 = S0
	VLD1	(R5), [V1.B16]         // V1 = S1
	VLD1	(R6), [V2.B16]         // V2 = S3
	VLD1	(R7), [V3.B16]         // V3 = S9
	VLD1	(R8), [V4.B16]         // V4 = S13
	VLD1	(R1), [V5.B16]         // V5 = mi
	
	// t = AESL(S0 ^ S1) ^ mi using fused operation
	AESE	V1.B16, V0.B16         // V0 = AESE(S0, S1) = SubBytes(ShiftRows(S0 ^ S1))
	AESMC	V0.B16, V0.B16         // V0 = AESL(S0 ^ S1)
	VEOR	V5.B16, V0.B16, V0.B16 // V0 = t = AESL(S0 ^ S1) ^ mi
	
	// ci = t ^ S9
	VEOR	V3.B16, V0.B16, V6.B16 // V6 = ci = t ^ S9
	VST1	[V6.B16], (R2)         // Store ci
	
	// S0 = AESL(S13) ^ t
	VEOR	V7.B16, V7.B16, V7.B16 // V7 = zero vector
	AESE	V7.B16, V4.B16         // V4 = AESE(S13, 0) = SubBytes(ShiftRows(S13))
	AESMC	V4.B16, V4.B16         // V4 = AESL(S13)
	VEOR	V0.B16, V4.B16, V4.B16 // V4 = AESL(S13) ^ t
	VST1	[V4.B16], (R4)         // Store new S0
	
	// S3 = S3 ^ mi
	VEOR	V5.B16, V2.B16, V2.B16 // V2 = S3 ^ mi
	VST1	[V2.B16], (R6)         // Store new S3
	
	// S13 = S13 ^ mi (V4 was S13, but it's been overwritten, reload it)
	VLD1	(R8), [V4.B16]         // V4 = original S13
	VEOR	V5.B16, V4.B16, V4.B16 // V4 = S13 ^ mi
	VST1	[V4.B16], (R8)         // Store new S13
	
	// Rol() - increment offset
	MOVD	256(R0), R3            // Reload current offset
	ADD	$1, R3, R3             // Increment offset
	AND	$15, R3, R3            // offset = (offset + 1) % 16
	MOVD	R3, 256(R0)            // Store new offset
	
	RET

// updateDecARM64 performs ARM64-optimized decryption update
// func updateDecARM64(h *HiAE, ci, mi []byte)
TEXT ·updateDecARM64(SB), NOSPLIT, $0-72
	MOVD	h+0(FP), R0            // R0 = HiAE struct pointer
	MOVD	ci_base+24(FP), R1     // R1 = ci pointer
	MOVD	mi_base+48(FP), R2     // R2 = mi pointer
	
	// Load current offset
	MOVD	256(R0), R3            // R3 = h.offset
	
	// Calculate state indices
	AND	$15, R3, R4            // R4 = idx0 = offset % 16
	ADD	$1, R3, R5
	AND	$15, R5, R5            // R5 = idx1 = (1 + offset) % 16
	ADD	$3, R3, R6
	AND	$15, R6, R6            // R6 = idx3 = (3 + offset) % 16
	ADD	$9, R3, R7
	AND	$15, R7, R7            // R7 = idx9 = (9 + offset) % 16
	ADD	$13, R3, R8
	AND	$15, R8, R8            // R8 = idx13 = (13 + offset) % 16
	
	// Calculate state block addresses
	LSL	$4, R4, R4             // R4 = idx0 * 16
	ADD	R0, R4, R4             // R4 = &h.state[idx0]
	LSL	$4, R5, R5             // R5 = idx1 * 16
	ADD	R0, R5, R5             // R5 = &h.state[idx1]
	LSL	$4, R6, R6             // R6 = idx3 * 16
	ADD	R0, R6, R6             // R6 = &h.state[idx3]
	LSL	$4, R7, R7             // R7 = idx9 * 16
	ADD	R0, R7, R7             // R7 = &h.state[idx9]
	LSL	$4, R8, R8             // R8 = idx13 * 16
	ADD	R0, R8, R8             // R8 = &h.state[idx13]
	
	// Load state blocks and input
	VLD1	(R4), [V0.B16]         // V0 = S0
	VLD1	(R5), [V1.B16]         // V1 = S1
	VLD1	(R6), [V2.B16]         // V2 = S3
	VLD1	(R7), [V3.B16]         // V3 = S9
	VLD1	(R8), [V4.B16]         // V4 = S13
	VLD1	(R1), [V5.B16]         // V5 = ci
	
	// t = ci ^ S9
	VEOR	V3.B16, V5.B16, V6.B16 // V6 = t = ci ^ S9
	
	// mi = AESL(S0 ^ S1) ^ t using fused operation
	AESE	V1.B16, V0.B16         // V0 = AESE(S0, S1) = SubBytes(ShiftRows(S0 ^ S1))
	AESMC	V0.B16, V0.B16         // V0 = AESL(S0 ^ S1)
	VEOR	V6.B16, V0.B16, V7.B16 // V7 = mi = AESL(S0 ^ S1) ^ t
	VST1	[V7.B16], (R2)         // Store mi
	
	// S0 = AESL(S13) ^ t
	VEOR	V8.B16, V8.B16, V8.B16 // V8 = zero vector
	AESE	V8.B16, V4.B16         // V4 = AESE(S13, 0) = SubBytes(ShiftRows(S13))
	AESMC	V4.B16, V4.B16         // V4 = AESL(S13)
	VEOR	V6.B16, V4.B16, V4.B16 // V4 = AESL(S13) ^ t
	VST1	[V4.B16], (R4)         // Store new S0
	
	// S3 = S3 ^ mi
	VEOR	V7.B16, V2.B16, V2.B16 // V2 = S3 ^ mi
	VST1	[V2.B16], (R6)         // Store new S3
	
	// S13 = S13 ^ mi (reload original S13)
	VLD1	(R8), [V4.B16]         // V4 = original S13
	VEOR	V7.B16, V4.B16, V4.B16 // V4 = S13 ^ mi
	VST1	[V4.B16], (R8)         // Store new S13
	
	// Rol() - increment offset
	MOVD	256(R0), R3            // Reload current offset
	ADD	$1, R3, R3             // Increment offset
	AND	$15, R3, R3            // offset = (offset + 1) % 16
	MOVD	R3, 256(R0)            // Store new offset
	
	RET

// batchEncryptARM64 encrypts exactly 16 blocks using hardcoded indices for maximum performance
// func batchEncryptARM64(h *HiAE, msgs, cts *[256]byte)
TEXT ·batchEncryptARM64(SB), NOSPLIT, $0-24
	MOVD	h+0(FP), R0            // R0 = HiAE struct pointer
	MOVD	msgs+8(FP), R1         // R1 = message blocks pointer  
	MOVD	cts+16(FP), R2         // R2 = ciphertext blocks pointer
	
	// Verify offset is 0 (required for batch processing)
	MOVD	256(R0), R3            // R3 = h.offset
	CMP	$0, R3
	BNE	batch_enc_panic
	
	// Block 0: S0=state[0], S1=state[1], S3=state[3], S9=state[9], S13=state[13]
	// Use post-index addressing to load state blocks
	ADD	$0, R0, R4              // R4 = &state[0]
	VLD1.P	16(R4), [V0.B16]        // V0 = S0, R4 += 16 -> &state[1]
	VLD1.P	16(R4), [V1.B16]        // V1 = S1, R4 += 16 -> &state[2]
	ADD	$16, R4, R5             // R5 = &state[3]
	VLD1	(R5), [V2.B16]          // V2 = S3
	ADD	$96, R5, R6             // R6 = &state[9] (3 + 6*16)
	VLD1	(R6), [V3.B16]          // V3 = S9
	ADD	$64, R6, R7             // R7 = &state[13] (9 + 4*16)
	VLD1	(R7), [V4.B16]          // V4 = S13
	
	// Load message block 0
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[0], R1 += 16
	
	// t = AESL(S0 ^ S1) ^ mi
	AESE	V1.B16, V0.B16          // V0 = AESL(S0 ^ S1) part 1
	AESMC	V0.B16, V0.B16          // V0 = AESL(S0 ^ S1) complete
	VEOR	V5.B16, V0.B16, V0.B16  // V0 = t = AESL(S0 ^ S1) ^ mi
	
	// ci = t ^ S9, store result
	VEOR	V3.B16, V0.B16, V16.B16 // V16 = ci = t ^ S9
	VST1.P	[V16.B16], 16(R2)       // Store ci[0], R2 += 16
	
	// S0 = AESL(S13) ^ t
	VEOR	V6.B16, V6.B16, V6.B16  // Clear V6
	AESE	V6.B16, V4.B16          // V4 = AESL(S13) part 1
	AESMC	V4.B16, V4.B16          // V4 = AESL(S13) complete  
	VEOR	V0.B16, V4.B16, V4.B16  // V4 = new S0 = AESL(S13) ^ t
	VST1	[V4.B16], (R0)          // Store new S0
	
	// S3 = S3 ^ mi
	VEOR	V5.B16, V2.B16, V2.B16  // V2 = S3 ^ mi
	VST1	[V2.B16], (R5)          // Store new S3
	
	// S13 = S13 ^ mi (reload original S13 first)
	VLD1	(R7), [V8.B16]          // V8 = original S13
	VEOR	V5.B16, V8.B16, V8.B16  // V8 = S13 ^ mi
	VST1	[V8.B16], (R7)          // Store new S13
	
	// Continue with remaining 15 blocks...
	// For brevity, implementing pattern for just a few more blocks
	// Real implementation would continue for all 16 blocks
	
	// Block 1: S0=state[1], S1=state[2], S3=state[4], S9=state[10], S13=state[14]
	ADD	$16, R0, R4             // R4 = &state[1]
	VLD1.P	16(R4), [V0.B16]        // V0 = S1, R4 += 16 -> &state[2]
	VLD1.P	16(R4), [V1.B16]        // V1 = S2, R4 += 16 -> &state[3]
	ADD	$16, R4, R5             // R5 = &state[4]
	VLD1	(R5), [V2.B16]          // V2 = S4
	ADD	$96, R5, R6             // R6 = &state[10]
	VLD1	(R6), [V3.B16]          // V3 = S10
	ADD	$64, R6, R7             // R7 = &state[14]
	VLD1	(R7), [V4.B16]          // V4 = S14
	
	// Load message block 1
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[1], R1 += 16
	
	// Apply same pattern as block 0...
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$16, R0, R8             // R8 = &state[1]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)
	
	// Block 2: S0=state[2], S1=state[3], S3=state[5], S9=state[11], S13=state[15]
	ADD	$32, R0, R4             // R4 = &state[2]
	VLD1.P	16(R4), [V0.B16]        // V0 = S2, R4 += 16 -> &state[3]
	VLD1.P	16(R4), [V1.B16]        // V1 = S3, R4 += 16 -> &state[4]
	ADD	$16, R4, R5             // R5 = &state[5]
	VLD1	(R5), [V2.B16]          // V2 = S5
	ADD	$96, R5, R6             // R6 = &state[11]
	VLD1	(R6), [V3.B16]          // V3 = S11
	ADD	$64, R6, R7             // R7 = &state[15]
	VLD1	(R7), [V4.B16]          // V4 = S15
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[2], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$32, R0, R8             // R8 = &state[2]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 3: S0=state[3], S1=state[4], S3=state[6], S9=state[12], S13=state[0]
	ADD	$48, R0, R4             // R4 = &state[3]
	VLD1.P	16(R4), [V0.B16]        // V0 = S3, R4 += 16 -> &state[4]
	VLD1.P	16(R4), [V1.B16]        // V1 = S4, R4 += 16 -> &state[5]
	ADD	$16, R4, R5             // R5 = &state[6]
	VLD1	(R5), [V2.B16]          // V2 = S6
	ADD	$96, R5, R6             // R6 = &state[12]
	VLD1	(R6), [V3.B16]          // V3 = S12
	ADD	$0, R0, R7              // R7 = &state[0] (wraps around)
	VLD1	(R7), [V4.B16]          // V4 = S0
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[3], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$48, R0, R8             // R8 = &state[3]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 4: S0=state[4], S1=state[5], S3=state[7], S9=state[13], S13=state[1]
	ADD	$64, R0, R4             // R4 = &state[4]
	VLD1.P	16(R4), [V0.B16]        // V0 = S4, R4 += 16 -> &state[5]
	VLD1.P	16(R4), [V1.B16]        // V1 = S5, R4 += 16 -> &state[6]
	ADD	$16, R4, R5             // R5 = &state[7]
	VLD1	(R5), [V2.B16]          // V2 = S7
	ADD	$96, R5, R6             // R6 = &state[13]
	VLD1	(R6), [V3.B16]          // V3 = S13
	ADD	$16, R0, R7             // R7 = &state[1]
	VLD1	(R7), [V4.B16]          // V4 = S1
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[4], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$64, R0, R8             // R8 = &state[4]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 5: S0=state[5], S1=state[6], S3=state[8], S9=state[14], S13=state[2]
	ADD	$80, R0, R4             // R4 = &state[5]
	VLD1.P	16(R4), [V0.B16]        // V0 = S5, R4 += 16 -> &state[6]
	VLD1.P	16(R4), [V1.B16]        // V1 = S6, R4 += 16 -> &state[7]
	ADD	$16, R4, R5             // R5 = &state[8]
	VLD1	(R5), [V2.B16]          // V2 = S8
	ADD	$96, R5, R6             // R6 = &state[14]
	VLD1	(R6), [V3.B16]          // V3 = S14
	ADD	$32, R0, R7             // R7 = &state[2]
	VLD1	(R7), [V4.B16]          // V4 = S2
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[5], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$80, R0, R8             // R8 = &state[5]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 6: S0=state[6], S1=state[7], S3=state[9], S9=state[15], S13=state[3]
	ADD	$96, R0, R4             // R4 = &state[6]
	VLD1.P	16(R4), [V0.B16]        // V0 = S6, R4 += 16 -> &state[7]
	VLD1.P	16(R4), [V1.B16]        // V1 = S7, R4 += 16 -> &state[8]
	ADD	$16, R4, R5             // R5 = &state[9]
	VLD1	(R5), [V2.B16]          // V2 = S9
	ADD	$96, R5, R6             // R6 = &state[15]
	VLD1	(R6), [V3.B16]          // V3 = S15
	ADD	$48, R0, R7             // R7 = &state[3]
	VLD1	(R7), [V4.B16]          // V4 = S3
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[6], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$96, R0, R8             // R8 = &state[6]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 7: S0=state[7], S1=state[8], S3=state[10], S9=state[0], S13=state[4]
	ADD	$112, R0, R4            // R4 = &state[7]
	VLD1.P	16(R4), [V0.B16]        // V0 = S7, R4 += 16 -> &state[8]
	VLD1.P	16(R4), [V1.B16]        // V1 = S8, R4 += 16 -> &state[9]
	ADD	$16, R4, R5             // R5 = &state[10]
	VLD1	(R5), [V2.B16]          // V2 = S10
	ADD	$0, R0, R6              // R6 = &state[0]
	VLD1	(R6), [V3.B16]          // V3 = S0
	ADD	$64, R0, R7             // R7 = &state[4]
	VLD1	(R7), [V4.B16]          // V4 = S4
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[7], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$112, R0, R8            // R8 = &state[7]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 8: S0=state[8], S1=state[9], S3=state[11], S9=state[1], S13=state[5]
	ADD	$128, R0, R4            // R4 = &state[8]
	VLD1.P	16(R4), [V0.B16]        // V0 = S8, R4 += 16 -> &state[9]
	VLD1.P	16(R4), [V1.B16]        // V1 = S9, R4 += 16 -> &state[10]
	ADD	$16, R4, R5             // R5 = &state[11]
	VLD1	(R5), [V2.B16]          // V2 = S11
	ADD	$16, R0, R6             // R6 = &state[1]
	VLD1	(R6), [V3.B16]          // V3 = S1
	ADD	$80, R0, R7             // R7 = &state[5]
	VLD1	(R7), [V4.B16]          // V4 = S5
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[8], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$128, R0, R8            // R8 = &state[8]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 9: S0=state[9], S1=state[10], S3=state[12], S9=state[2], S13=state[6]
	ADD	$144, R0, R4            // R4 = &state[9]
	VLD1.P	16(R4), [V0.B16]        // V0 = S9, R4 += 16 -> &state[10]
	VLD1.P	16(R4), [V1.B16]        // V1 = S10, R4 += 16 -> &state[11]
	ADD	$16, R4, R5             // R5 = &state[12]
	VLD1	(R5), [V2.B16]          // V2 = S12
	ADD	$32, R0, R6             // R6 = &state[2]
	VLD1	(R6), [V3.B16]          // V3 = S2
	ADD	$96, R0, R7             // R7 = &state[6]
	VLD1	(R7), [V4.B16]          // V4 = S6
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[9], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$144, R0, R8            // R8 = &state[9]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 10: S0=state[10], S1=state[11], S3=state[13], S9=state[3], S13=state[7]
	ADD	$160, R0, R4            // R4 = &state[10]
	VLD1.P	16(R4), [V0.B16]        // V0 = S10, R4 += 16 -> &state[11]
	VLD1.P	16(R4), [V1.B16]        // V1 = S11, R4 += 16 -> &state[12]
	ADD	$16, R4, R5             // R5 = &state[13]
	VLD1	(R5), [V2.B16]          // V2 = S13
	ADD	$48, R0, R6             // R6 = &state[3]
	VLD1	(R6), [V3.B16]          // V3 = S3
	ADD	$112, R0, R7            // R7 = &state[7]
	VLD1	(R7), [V4.B16]          // V4 = S7
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[10], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$160, R0, R8            // R8 = &state[10]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 11: S0=state[11], S1=state[12], S3=state[14], S9=state[4], S13=state[8]
	ADD	$176, R0, R4            // R4 = &state[11]
	VLD1.P	16(R4), [V0.B16]        // V0 = S11, R4 += 16 -> &state[12]
	VLD1.P	16(R4), [V1.B16]        // V1 = S12, R4 += 16 -> &state[13]
	ADD	$16, R4, R5             // R5 = &state[14]
	VLD1	(R5), [V2.B16]          // V2 = S14
	ADD	$64, R0, R6             // R6 = &state[4]
	VLD1	(R6), [V3.B16]          // V3 = S4
	ADD	$128, R0, R7            // R7 = &state[8]
	VLD1	(R7), [V4.B16]          // V4 = S8
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[11], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$176, R0, R8            // R8 = &state[11]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 12: S0=state[12], S1=state[13], S3=state[15], S9=state[5], S13=state[9]
	ADD	$192, R0, R4            // R4 = &state[12]
	VLD1.P	16(R4), [V0.B16]        // V0 = S12, R4 += 16 -> &state[13]
	VLD1.P	16(R4), [V1.B16]        // V1 = S13, R4 += 16 -> &state[14]
	ADD	$16, R4, R5             // R5 = &state[15]
	VLD1	(R5), [V2.B16]          // V2 = S15
	ADD	$80, R0, R6             // R6 = &state[5]
	VLD1	(R6), [V3.B16]          // V3 = S5
	ADD	$144, R0, R7            // R7 = &state[9]
	VLD1	(R7), [V4.B16]          // V4 = S9
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[12], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$192, R0, R8            // R8 = &state[12]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 13: S0=state[13], S1=state[14], S3=state[0], S9=state[6], S13=state[10]
	ADD	$208, R0, R4            // R4 = &state[13]
	VLD1.P	16(R4), [V0.B16]        // V0 = S13, R4 += 16 -> &state[14]
	VLD1.P	16(R4), [V1.B16]        // V1 = S14, R4 += 16 -> &state[15]
	ADD	$0, R0, R5              // R5 = &state[0]
	VLD1	(R5), [V2.B16]          // V2 = S0
	ADD	$96, R0, R6             // R6 = &state[6]
	VLD1	(R6), [V3.B16]          // V3 = S6
	ADD	$160, R0, R7            // R7 = &state[10]
	VLD1	(R7), [V4.B16]          // V4 = S10
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[13], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$208, R0, R8            // R8 = &state[13]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 14: S0=state[14], S1=state[15], S3=state[1], S9=state[7], S13=state[11]
	ADD	$224, R0, R4            // R4 = &state[14]
	VLD1.P	16(R4), [V0.B16]        // V0 = S14, R4 += 16 -> &state[15]
	VLD1	(R4), [V1.B16]          // V1 = S15
	ADD	$16, R0, R5             // R5 = &state[1]
	VLD1	(R5), [V2.B16]          // V2 = S1
	ADD	$112, R0, R6            // R6 = &state[7]
	VLD1	(R6), [V3.B16]          // V3 = S7
	ADD	$176, R0, R7            // R7 = &state[11]
	VLD1	(R7), [V4.B16]          // V4 = S11
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[14], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	ADD	$224, R0, R8            // R8 = &state[14]
	VST1	[V4.B16], (R8)
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V5.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 15: S0=state[15], S1=state[0], S3=state[2], S9=state[8], S13=state[12]
	ADD	$240, R0, R4            // R4 = &state[15]
	VLD1	(R4), [V0.B16]          // V0 = S15
	ADD	$0, R0, R5              // R5 = &state[0]
	VLD1	(R5), [V1.B16]          // V1 = S0
	ADD	$32, R0, R6             // R6 = &state[2]
	VLD1	(R6), [V2.B16]          // V2 = S2
	ADD	$128, R0, R7            // R7 = &state[8]
	VLD1	(R7), [V3.B16]          // V3 = S8
	ADD	$192, R0, R8            // R8 = &state[12]
	VLD1	(R8), [V4.B16]          // V4 = S12
	VLD1.P	16(R1), [V5.B16]        // V5 = mi[15], R1 += 16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V5.B16, V0.B16, V0.B16
	VEOR	V3.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V6.B16, V6.B16, V6.B16
	AESE	V6.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V0.B16, V4.B16, V4.B16
	VST1	[V4.B16], (R4)          // Store to &state[15]
	VEOR	V5.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R6)
	VLD1	(R8), [V9.B16]
	VEOR	V5.B16, V9.B16, V9.B16
	VST1	[V9.B16], (R8)
	
	// Update offset to 0 (after 16 rotations we are back to start)
	MOVD	$0, R3
	MOVD	R3, 256(R0)
	
	RET

batch_enc_panic:
	// Panic if offset is not 0
	MOVD	$0, R0
	MOVD	R0, (R0)  // Cause segfault to trigger panic
	RET

// batchDecryptARM64 decrypts exactly 16 blocks using hardcoded indices for maximum performance  
// func batchDecryptARM64(h *HiAE, cts, msgs *[256]byte)
TEXT ·batchDecryptARM64(SB), NOSPLIT, $0-24
	MOVD	h+0(FP), R0            // R0 = HiAE struct pointer
	MOVD	cts+8(FP), R1          // R1 = ciphertext blocks pointer
	MOVD	msgs+16(FP), R2        // R2 = message blocks pointer
	
	// Verify offset is 0 (required for batch processing)
	MOVD	256(R0), R3            // R3 = h.offset
	CMP	$0, R3
	BNE	batch_dec_panic
	
	// Block 0: S0=state[0], S1=state[1], S3=state[3], S9=state[9], S13=state[13]
	ADD	$0, R0, R4              // R4 = &state[0]
	VLD1.P	16(R4), [V0.B16]        // V0 = S0, R4 += 16 -> &state[1]
	VLD1.P	16(R4), [V1.B16]        // V1 = S1, R4 += 16 -> &state[2]
	ADD	$16, R4, R5             // R5 = &state[3]
	VLD1	(R5), [V2.B16]          // V2 = S3
	ADD	$96, R5, R6             // R6 = &state[9]
	VLD1	(R6), [V3.B16]          // V3 = S9
	ADD	$64, R6, R7             // R7 = &state[13]
	VLD1	(R7), [V4.B16]          // V4 = S13
	
	// Load ciphertext block 0
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[0], R1 += 16
	
	// t = ci ^ S9
	VEOR	V3.B16, V5.B16, V6.B16  // V6 = t = ci ^ S9
	
	// mi = AESL(S0 ^ S1) ^ t
	AESE	V1.B16, V0.B16          // V0 = AESL(S0 ^ S1) part 1
	AESMC	V0.B16, V0.B16          // V0 = AESL(S0 ^ S1) complete
	VEOR	V6.B16, V0.B16, V16.B16 // V16 = mi = AESL(S0 ^ S1) ^ t
	VST1.P	[V16.B16], 16(R2)       // Store mi[0], R2 += 16
	
	// S0 = AESL(S13) ^ t
	VEOR	V7.B16, V7.B16, V7.B16  // Clear V7
	AESE	V7.B16, V4.B16          // V4 = AESL(S13) part 1
	AESMC	V4.B16, V4.B16          // V4 = AESL(S13) complete
	VEOR	V6.B16, V4.B16, V4.B16  // V4 = new S0 = AESL(S13) ^ t
	VST1	[V4.B16], (R0)          // Store new S0
	
	// S3 = S3 ^ mi
	VEOR	V16.B16, V2.B16, V2.B16 // V2 = S3 ^ mi
	VST1	[V2.B16], (R5)          // Store new S3
	
	// S13 = S13 ^ mi (reload original S13 first)
	VLD1	(R7), [V8.B16]          // V8 = original S13
	VEOR	V16.B16, V8.B16, V8.B16 // V8 = S13 ^ mi
	VST1	[V8.B16], (R7)          // Store new S13
	
	// Block 1: S0=state[1], S1=state[2], S3=state[4], S9=state[10], S13=state[14]
	ADD	$16, R0, R4             // R4 = &state[1]
	VLD1.P	16(R4), [V0.B16]        // V0 = S1, R4 += 16 -> &state[2]
	VLD1.P	16(R4), [V1.B16]        // V1 = S2, R4 += 16 -> &state[3]
	ADD	$16, R4, R5             // R5 = &state[4]
	VLD1	(R5), [V2.B16]          // V2 = S4
	ADD	$96, R5, R6             // R6 = &state[10]
	VLD1	(R6), [V3.B16]          // V3 = S10
	ADD	$64, R6, R7             // R7 = &state[14]
	VLD1	(R7), [V4.B16]          // V4 = S14
	
	// Load ciphertext block 1
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[1], R1 += 16
	
	// Apply same pattern as block 0...
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$16, R0, R8             // R8 = &state[1]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)
	
	// Block 2: S0=state[2], S1=state[3], S3=state[5], S9=state[11], S13=state[15]
	ADD	$32, R0, R4             // R4 = &state[2]
	VLD1.P	16(R4), [V0.B16]        // V0 = S2, R4 += 16 -> &state[3]
	VLD1.P	16(R4), [V1.B16]        // V1 = S3, R4 += 16 -> &state[4]
	ADD	$16, R4, R5             // R5 = &state[5]
	VLD1	(R5), [V2.B16]          // V2 = S5
	ADD	$96, R5, R6             // R6 = &state[11]
	VLD1	(R6), [V3.B16]          // V3 = S11
	ADD	$64, R6, R7             // R7 = &state[15]
	VLD1	(R7), [V4.B16]          // V4 = S15
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[2], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$32, R0, R8             // R8 = &state[2]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 3: S0=state[3], S1=state[4], S3=state[6], S9=state[12], S13=state[0]
	ADD	$48, R0, R4             // R4 = &state[3]
	VLD1.P	16(R4), [V0.B16]        // V0 = S3, R4 += 16 -> &state[4]
	VLD1.P	16(R4), [V1.B16]        // V1 = S4, R4 += 16 -> &state[5]
	ADD	$16, R4, R5             // R5 = &state[6]
	VLD1	(R5), [V2.B16]          // V2 = S6
	ADD	$96, R5, R6             // R6 = &state[12]
	VLD1	(R6), [V3.B16]          // V3 = S12
	ADD	$0, R0, R7              // R7 = &state[0]
	VLD1	(R7), [V4.B16]          // V4 = S0
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[3], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$48, R0, R8             // R8 = &state[3]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 4: S0=state[4], S1=state[5], S3=state[7], S9=state[13], S13=state[1]
	ADD	$64, R0, R4             // R4 = &state[4]
	VLD1.P	16(R4), [V0.B16]        // V0 = S4, R4 += 16 -> &state[5]
	VLD1.P	16(R4), [V1.B16]        // V1 = S5, R4 += 16 -> &state[6]
	ADD	$16, R4, R5             // R5 = &state[7]
	VLD1	(R5), [V2.B16]          // V2 = S7
	ADD	$96, R5, R6             // R6 = &state[13]
	VLD1	(R6), [V3.B16]          // V3 = S13
	ADD	$16, R0, R7             // R7 = &state[1]
	VLD1	(R7), [V4.B16]          // V4 = S1
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[4], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$64, R0, R8             // R8 = &state[4]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 5: S0=state[5], S1=state[6], S3=state[8], S9=state[14], S13=state[2]
	ADD	$80, R0, R4             // R4 = &state[5]
	VLD1.P	16(R4), [V0.B16]        // V0 = S5, R4 += 16 -> &state[6]
	VLD1.P	16(R4), [V1.B16]        // V1 = S6, R4 += 16 -> &state[7]
	ADD	$16, R4, R5             // R5 = &state[8]
	VLD1	(R5), [V2.B16]          // V2 = S8
	ADD	$96, R5, R6             // R6 = &state[14]
	VLD1	(R6), [V3.B16]          // V3 = S14
	ADD	$32, R0, R7             // R7 = &state[2]
	VLD1	(R7), [V4.B16]          // V4 = S2
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[5], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$80, R0, R8             // R8 = &state[5]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 6: S0=state[6], S1=state[7], S3=state[9], S9=state[15], S13=state[3]
	ADD	$96, R0, R4             // R4 = &state[6]
	VLD1.P	16(R4), [V0.B16]        // V0 = S6, R4 += 16 -> &state[7]
	VLD1.P	16(R4), [V1.B16]        // V1 = S7, R4 += 16 -> &state[8]
	ADD	$16, R4, R5             // R5 = &state[9]
	VLD1	(R5), [V2.B16]          // V2 = S9
	ADD	$96, R5, R6             // R6 = &state[15]
	VLD1	(R6), [V3.B16]          // V3 = S15
	ADD	$48, R0, R7             // R7 = &state[3]
	VLD1	(R7), [V4.B16]          // V4 = S3
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[6], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$96, R0, R8             // R8 = &state[6]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 7: S0=state[7], S1=state[8], S3=state[10], S9=state[0], S13=state[4]
	ADD	$112, R0, R4            // R4 = &state[7]
	VLD1.P	16(R4), [V0.B16]        // V0 = S7, R4 += 16 -> &state[8]
	VLD1.P	16(R4), [V1.B16]        // V1 = S8, R4 += 16 -> &state[9]
	ADD	$16, R4, R5             // R5 = &state[10]
	VLD1	(R5), [V2.B16]          // V2 = S10
	ADD	$0, R0, R6              // R6 = &state[0]
	VLD1	(R6), [V3.B16]          // V3 = S0
	ADD	$64, R0, R7             // R7 = &state[4]
	VLD1	(R7), [V4.B16]          // V4 = S4
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[7], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$112, R0, R8            // R8 = &state[7]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 8: S0=state[8], S1=state[9], S3=state[11], S9=state[1], S13=state[5]
	ADD	$128, R0, R4            // R4 = &state[8]
	VLD1.P	16(R4), [V0.B16]        // V0 = S8, R4 += 16 -> &state[9]
	VLD1.P	16(R4), [V1.B16]        // V1 = S9, R4 += 16 -> &state[10]
	ADD	$16, R4, R5             // R5 = &state[11]
	VLD1	(R5), [V2.B16]          // V2 = S11
	ADD	$16, R0, R6             // R6 = &state[1]
	VLD1	(R6), [V3.B16]          // V3 = S1
	ADD	$80, R0, R7             // R7 = &state[5]
	VLD1	(R7), [V4.B16]          // V4 = S5
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[8], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$128, R0, R8            // R8 = &state[8]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 9: S0=state[9], S1=state[10], S3=state[12], S9=state[2], S13=state[6]
	ADD	$144, R0, R4            // R4 = &state[9]
	VLD1.P	16(R4), [V0.B16]        // V0 = S9, R4 += 16 -> &state[10]
	VLD1.P	16(R4), [V1.B16]        // V1 = S10, R4 += 16 -> &state[11]
	ADD	$16, R4, R5             // R5 = &state[12]
	VLD1	(R5), [V2.B16]          // V2 = S12
	ADD	$32, R0, R6             // R6 = &state[2]
	VLD1	(R6), [V3.B16]          // V3 = S2
	ADD	$96, R0, R7             // R7 = &state[6]
	VLD1	(R7), [V4.B16]          // V4 = S6
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[9], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$144, R0, R8            // R8 = &state[9]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 10: S0=state[10], S1=state[11], S3=state[13], S9=state[3], S13=state[7]
	ADD	$160, R0, R4            // R4 = &state[10]
	VLD1.P	16(R4), [V0.B16]        // V0 = S10, R4 += 16 -> &state[11]
	VLD1.P	16(R4), [V1.B16]        // V1 = S11, R4 += 16 -> &state[12]
	ADD	$16, R4, R5             // R5 = &state[13]
	VLD1	(R5), [V2.B16]          // V2 = S13
	ADD	$48, R0, R6             // R6 = &state[3]
	VLD1	(R6), [V3.B16]          // V3 = S3
	ADD	$112, R0, R7            // R7 = &state[7]
	VLD1	(R7), [V4.B16]          // V4 = S7
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[10], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$160, R0, R8            // R8 = &state[10]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 11: S0=state[11], S1=state[12], S3=state[14], S9=state[4], S13=state[8]
	ADD	$176, R0, R4            // R4 = &state[11]
	VLD1.P	16(R4), [V0.B16]        // V0 = S11, R4 += 16 -> &state[12]
	VLD1.P	16(R4), [V1.B16]        // V1 = S12, R4 += 16 -> &state[13]
	ADD	$16, R4, R5             // R5 = &state[14]
	VLD1	(R5), [V2.B16]          // V2 = S14
	ADD	$64, R0, R6             // R6 = &state[4]
	VLD1	(R6), [V3.B16]          // V3 = S4
	ADD	$128, R0, R7            // R7 = &state[8]
	VLD1	(R7), [V4.B16]          // V4 = S8
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[11], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$176, R0, R8            // R8 = &state[11]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 12: S0=state[12], S1=state[13], S3=state[15], S9=state[5], S13=state[9]
	ADD	$192, R0, R4            // R4 = &state[12]
	VLD1.P	16(R4), [V0.B16]        // V0 = S12, R4 += 16 -> &state[13]
	VLD1.P	16(R4), [V1.B16]        // V1 = S13, R4 += 16 -> &state[14]
	ADD	$16, R4, R5             // R5 = &state[15]
	VLD1	(R5), [V2.B16]          // V2 = S15
	ADD	$80, R0, R6             // R6 = &state[5]
	VLD1	(R6), [V3.B16]          // V3 = S5
	ADD	$144, R0, R7            // R7 = &state[9]
	VLD1	(R7), [V4.B16]          // V4 = S9
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[12], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$192, R0, R8            // R8 = &state[12]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 13: S0=state[13], S1=state[14], S3=state[0], S9=state[6], S13=state[10]
	ADD	$208, R0, R4            // R4 = &state[13]
	VLD1.P	16(R4), [V0.B16]        // V0 = S13, R4 += 16 -> &state[14]
	VLD1.P	16(R4), [V1.B16]        // V1 = S14, R4 += 16 -> &state[15]
	ADD	$0, R0, R5              // R5 = &state[0]
	VLD1	(R5), [V2.B16]          // V2 = S0
	ADD	$96, R0, R6             // R6 = &state[6]
	VLD1	(R6), [V3.B16]          // V3 = S6
	ADD	$160, R0, R7            // R7 = &state[10]
	VLD1	(R7), [V4.B16]          // V4 = S10
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[13], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$208, R0, R8            // R8 = &state[13]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 14: S0=state[14], S1=state[15], S3=state[1], S9=state[7], S13=state[11]
	ADD	$224, R0, R4            // R4 = &state[14]
	VLD1.P	16(R4), [V0.B16]        // V0 = S14, R4 += 16 -> &state[15]
	VLD1	(R4), [V1.B16]          // V1 = S15
	ADD	$16, R0, R5             // R5 = &state[1]
	VLD1	(R5), [V2.B16]          // V2 = S1
	ADD	$112, R0, R6            // R6 = &state[7]
	VLD1	(R6), [V3.B16]          // V3 = S7
	ADD	$176, R0, R7            // R7 = &state[11]
	VLD1	(R7), [V4.B16]          // V4 = S11
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[14], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	ADD	$224, R0, R8            // R8 = &state[14]
	VST1	[V4.B16], (R8)
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R5)
	VLD1	(R7), [V8.B16]
	VEOR	V16.B16, V8.B16, V8.B16
	VST1	[V8.B16], (R7)

	// Block 15: S0=state[15], S1=state[0], S3=state[2], S9=state[8], S13=state[12]
	ADD	$240, R0, R4            // R4 = &state[15]
	VLD1	(R4), [V0.B16]          // V0 = S15
	ADD	$0, R0, R5              // R5 = &state[0]
	VLD1	(R5), [V1.B16]          // V1 = S0
	ADD	$32, R0, R6             // R6 = &state[2]
	VLD1	(R6), [V2.B16]          // V2 = S2
	ADD	$128, R0, R7            // R7 = &state[8]
	VLD1	(R7), [V3.B16]          // V3 = S8
	ADD	$192, R0, R8            // R8 = &state[12]
	VLD1	(R8), [V4.B16]          // V4 = S12
	VLD1.P	16(R1), [V5.B16]        // V5 = ci[15], R1 += 16
	VEOR	V3.B16, V5.B16, V6.B16
	AESE	V1.B16, V0.B16
	AESMC	V0.B16, V0.B16
	VEOR	V6.B16, V0.B16, V16.B16
	VST1.P	[V16.B16], 16(R2)
	VEOR	V7.B16, V7.B16, V7.B16
	AESE	V7.B16, V4.B16
	AESMC	V4.B16, V4.B16
	VEOR	V6.B16, V4.B16, V4.B16
	VST1	[V4.B16], (R4)          // Store to &state[15]
	VEOR	V16.B16, V2.B16, V2.B16
	VST1	[V2.B16], (R6)
	VLD1	(R8), [V9.B16]
	VEOR	V16.B16, V9.B16, V9.B16
	VST1	[V9.B16], (R8)
	
	// Update offset to 0 (after 16 rotations we are back to start)
	MOVD	$0, R3
	MOVD	R3, 256(R0)
	
	RET

batch_dec_panic:
	// Panic if offset is not 0
	MOVD	$0, R0
	MOVD	R0, (R0)  // Cause segfault to trigger panic
	RET
