/*-
 * Copyright (c) 1994-1996 Søren Schmidt
 * Copyright (c) 2018 Turing Robotic Industries Inc.
 * Copyright (c) 2022 Dmitry Chagin <dchagin@FreeBSD.org>
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

#ifndef _RISCV64_LINUX_SIGFRAME_H_
#define _RISCV64_LINUX_SIGFRAME_H_

/* Tagged header for extensions (FPU, Vector) */
struct _l_riscv64_ctx {
	uint32_t magic;
	uint32_t size;
};

/* RISC-V Linux FPU Magic */
#define L_PFIX_FRAME_MAGIC 0x53465001
#define L_PFIX_END_MAGIC   0x00000000

struct l_fp_state {
	struct _l_riscv64_ctx head;
	uint64_t fpregs[32];
	uint32_t fcsr;
	uint32_t reserved;
};

struct l_sigcontext {
	/* In Linux/RISC-V, this is 'struct user_regs_struct'
	*  pc + x1..x31 = 32 registers total.
	*/
	union {
		uint64_t sc_pc;
		uint64_t sc_regs[32];
	};
	uint64_t sstatus;
    
	/* Extension space starts here. Usually where we 
	*  place struct l_fp_state.
	*/
	uint8_t  sc_extspace[0] __aligned(16);
};

struct l_ucontext {
	unsigned long     uc_flags;
	struct l_ucontext *uc_link;
	l_stack_t         uc_stack;
	l_sigset_t        uc_sigmask; 

	uint8_t           unused[128 - sizeof(l_sigset_t)];	 // Glibc padding
	struct l_sigcontext uc_mcontext;
};

struct l_rt_sigframe {
	l_siginfo_t       sf_si;
	struct l_ucontext sf_uc;
} __attribute__((__aligned__(16)));

struct l_sigframe {
	struct l_rt_sigframe sf;

	// frame_record 
	uint64_t	fp;
	uint64_t	lr;
};

#define	LINUX_MINSIGSTKSZ	roundup(sizeof(struct l_sigframe), 16)

#endif /* _RISCV64_LINUX_SIGFRAME_H_ */

