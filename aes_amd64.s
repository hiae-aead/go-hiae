//go:build amd64 && !purego

#include "textflag.h"

// AESL(x) = AESENC(x, 0) = MixColumns(ShiftRows(SubBytes(x))).
// func aeslAsm(dst, src *byte)
TEXT ·aeslAsm(SB), NOSPLIT, $0-16
	MOVQ src+8(FP), AX
	MOVUPS (AX), X0
	PXOR X1, X1
	AESENC X1, X0
	MOVQ dst+0(FP), AX
	MOVUPS X0, (AX)
	RET

// SLOT(i, reg): reg = 16*((off+i)&15). off is R10.
#define SLOT(i, reg) \
	MOVL R10, reg \
	ADDL $i, reg \
	ANDL $15, reg \
	SHLL $4, reg

// func hiaeEncNI(s *byte, off *int, in, out *byte, n uint64)
// t = AESENC(S0⊕S1, m); c = t⊕S9; S0 = AESENC(S13, t); S3⊕=m; S13⊕=m; off++
TEXT ·hiaeEncNI(SB), NOSPLIT, $0-40
	MOVQ s+0(FP), R8
	MOVQ off+8(FP), R9
	MOVQ in+16(FP), SI
	MOVQ out+24(FP), DI
	MOVQ n+32(FP), R11
	MOVQ (R9), R10
	TESTQ R11, R11
	JZ encDone

encLoop:
	MOVUPS (SI), X2

	SLOT(0, AX)
	MOVUPS (R8)(AX*1), X0
	SLOT(1, BX)
	MOVUPS (R8)(BX*1), X1
	PXOR X1, X0
	AESENC X2, X0

	SLOT(9, DX)
	MOVUPS (R8)(DX*1), X1
	PXOR X0, X1
	MOVUPS X1, (DI)

	SLOT(13, DX)
	MOVUPS (R8)(DX*1), X4
	MOVUPS X4, X5
	AESENC X0, X4
	PXOR X2, X5
	MOVUPS X4, (R8)(AX*1)
	MOVUPS X5, (R8)(DX*1)

	SLOT(3, BX)
	MOVUPS (R8)(BX*1), X1
	PXOR X2, X1
	MOVUPS X1, (R8)(BX*1)

	ADDQ $16, SI
	ADDQ $16, DI
	ADDL $1, R10
	ANDL $15, R10
	SUBQ $1, R11
	JNZ encLoop

encDone:
	MOVQ R10, (R9)
	RET

// func hiaeDecNI(s *byte, off *int, in, out *byte, n uint64)
// t = c⊕S9; x = AESENC(S0⊕S1, t); S0 = AESENC(S13, t); S3⊕=x; S13⊕=x; off++
TEXT ·hiaeDecNI(SB), NOSPLIT, $0-40
	MOVQ s+0(FP), R8
	MOVQ off+8(FP), R9
	MOVQ in+16(FP), SI
	MOVQ out+24(FP), DI
	MOVQ n+32(FP), R11
	MOVQ (R9), R10
	TESTQ R11, R11
	JZ decDone

decLoop:
	MOVUPS (SI), X2

	SLOT(9, DX)
	MOVUPS (R8)(DX*1), X1
	MOVUPS X2, X0
	PXOR X1, X0

	SLOT(0, AX)
	MOVUPS (R8)(AX*1), X3
	SLOT(1, BX)
	MOVUPS (R8)(BX*1), X4
	PXOR X4, X3
	AESENC X0, X3
	MOVUPS X3, (DI)

	SLOT(13, DX)
	MOVUPS (R8)(DX*1), X4
	MOVUPS X4, X5
	AESENC X0, X4
	PXOR X3, X5
	MOVUPS X4, (R8)(AX*1)
	MOVUPS X5, (R8)(DX*1)

	SLOT(3, BX)
	MOVUPS (R8)(BX*1), X1
	PXOR X3, X1
	MOVUPS X1, (R8)(BX*1)

	ADDQ $16, SI
	ADDQ $16, DI
	ADDL $1, R10
	ANDL $15, R10
	SUBQ $1, R11
	JNZ decLoop

decDone:
	MOVQ R10, (R9)
	RET
