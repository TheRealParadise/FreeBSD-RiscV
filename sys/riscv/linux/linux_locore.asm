/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2018 Turing Robotic Industries Inc.
 * Copyright (C) 2020 Andrew Turner <andrew@FreeBSD.org>
 * Copyright (C) 2022 Dmitry Chagin <dchagin@FreeBSD.org>
 * Adapted for RiscV - 2026 by Stefan Rink
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * riscv64 Linux VDSO signal trampoline.
 */

#include <machine/asm.h>
#include <riscv/linux/linux_syscall.h>

	.data

	.globl linux_platform
linux_platform:
	.asciz "riscv64"

	.text

EENTRY(__kernel_rt_sigreturn)
	.cfi_startproc
	.cfi_signal_frame
	nop	/* This is what Linux calls a "Mysterious NOP". */

	.globl __user_rt_sigreturn
__user_rt_sigreturn:
	li	a7, LINUX_SYS_linux_rt_sigreturn
	ecall
	.cfi_endproc
EEND(__kernel_rt_sigreturn)
