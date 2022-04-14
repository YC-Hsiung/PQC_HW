#include "chacha20.h"
.section .text
.globl QR
.type QR, @function

QR:
	ADD $p1, $p1, $p2
	EOR $p4, $p1, $p4
	ADD $p3, $p3, $p4 ROR #16
	EOR $p2, $p3, $p2
	ADD $p1, $p1, $p2 ROR #20
	EOR $p4, $p1, $p4 ROR #16
	ROR $p4, $p4, #24
	ADD $p3, $p3, $p4
	EOR $p2, $p3, $p2
	ROR $p2, $p2, #25
	POP
	bx lr


