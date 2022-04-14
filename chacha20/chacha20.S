#include "chacha20.h"
.section .text
.globl QR
.type QR, @function

QR:
	ADD r0, r0, r1
	EOR r3, r0, r3
	ADD r2, r2, r3 ROR #16
	EOR r1, r2, r1
	ADD r0, r0, r1 ROR #20
	EOR r3, r0, r3 ROR #16
	ROR r3, r3, #24
	ADD r2, r2, r3
	EOR r1, r2, r1
	ROR r1, r1, #25
	POP
	bx lr


