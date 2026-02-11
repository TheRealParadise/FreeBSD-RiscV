/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Adapted for RiscV - 2026 - Stefan Rink
 * Copyright (c) 2018 Turing Robotic Industries Inc.
 * Copyright (c) 2000 Marcel Moolenaar
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/proc.h>
#include <sys/reg.h>

/* VM system headers */
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

/* Machine dependent */
#include <machine/pcb.h>
#include <machine/pcb.h>
#include <vm/vm_param.h>

#include <riscv/linux/linux.h>
#include <riscv/linux/linux_proto.h>
#include <compat/linux/linux_fork.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_util.h>


int kern_ptrace(struct thread *td, int req, pid_t pid, void *addr, int data);

#define	LINUX_ARCH_RISCV64		0xc00000F3


int linux_set_upcall(struct thread *td, register_t stack) {
	if (stack) td->td_frame->tf_sp = stack;

	/*
	 * The newly created Linux thread returns
	 * to the user space by the same path that a parent does.
	 * to make sure libc doesn't get an error from birth we make sure this is a0 is zero
	 */
	td->td_frame->tf_a[0] = 0;
	return (0);
}

int linux_set_cloned_tls(struct thread *td, void *desc) {
	struct trapframe *tf = td->td_frame;
	uintptr_t tls = (uintptr_t)desc;

	if (tls >= VM_MAXUSER_ADDRESS) return (EPERM);

	uintptr_t target_tls = tls - 16; 			// Make room for our TLS stuff.
	tf->tf_tp = (uintptr_t)target_tls;

	return(cpu_set_user_tls(td, (void *)target_tls, 0));
}

/*
 *    'Convert' the FreeBSD (general) registerset to Linux registerset
 */
void bsd_to_linux_regset(const struct reg *b_reg, struct linux_pt_regset *l_regset) {
	l_regset->zero= b_reg->sepc;		// Register 'sandwitch'
	l_regset->ra = b_reg->ra;
	l_regset->sp = b_reg->sp;
	l_regset->gp = b_reg->gp;
	l_regset->tp = b_reg->tp;
	l_regset->pc = b_reg->sepc;

	for (int i = 0; i < 3; i++) l_regset->t[i] = b_reg->t[i];

	l_regset->s[0] = b_reg->s[0];
	l_regset->s[1] = b_reg->s[1];

	for (int i = 1; i < 8; i++) l_regset->a[i] = b_reg->a[i];
	for (int i = 0; i < 10; i++) l_regset->s2[i] = b_reg->s[i + 2];
	for (int i = 0; i < 4; i++) l_regset->t3[i] = b_reg->t[i + 3];

}

/*
 *	'Convert' the Linux (general) registerset to FreeBSD registerset
 */
void linux_to_bsd_regset(struct reg *b_reg, const struct linux_pt_regset *l_regset) {

	b_reg->sepc = l_regset->pc;		// TODO: Still have to check what PC gdb changes

	b_reg->ra = l_regset->ra;
	b_reg->sp = l_regset->sp;
	b_reg->gp = l_regset->gp;
	b_reg->tp = l_regset->tp;

	for (int i = 0; i < 3; i++)  b_reg->t[i] = l_regset->t[i];

	b_reg->s[0] = l_regset->s[0];
	b_reg->s[1] = l_regset->s[1];

	for (int i = 0; i < 8; i++)  b_reg->a[i] = l_regset->a[i];
	for (int i = 0; i < 10; i++)  b_reg->s[i + 2] = l_regset->s2[i];
	for (int i = 0; i < 4; i++)  b_reg->t[i + 3] = l_regset->t3[i];


}


/**************** PTRACE ****************/

void linux_ptrace_get_syscall_info_machdep(const struct reg *reg, struct syscall_info *si) {

	si->arch = LINUX_ARCH_RISCV64;
	si->instruction_pointer = reg->sepc;
	si->stack_pointer = reg->sp;

}



int linux_ptrace_getregs_machdep(struct thread *td, pid_t pid __unused, struct linux_pt_regset *l_regset) {
	struct ptrace_lwpinfo lwpinfo;
	struct trapframe *tf = td->td_frame;
	int error;


	l_regset->pc = tf->tf_sepc;
	l_regset->ra = tf->tf_ra;
	l_regset->sp = tf->tf_sp;
	l_regset->gp = tf->tf_gp;
	l_regset->tp = tf->tf_tp;

	for (int i = 0; i < 8; i++) l_regset->a[i] = tf->tf_a[i];
	for (int i = 0; i < 3; i++) l_regset->t[i] = tf->tf_t[i];
	for (int i = 0; i < 4; i++) l_regset->t[i] = tf->tf_t[3+i];

	l_regset->s[0] = tf->tf_s[0];
	l_regset->s[1] = tf->tf_s[1];

	for (int i = 0; i < 10; i++) l_regset->s2[i] = tf->tf_s[2+i];

	error = kern_ptrace(td, PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));
	return (error);
}

/*
 * Not (yet) implemented stuff
 */
int linux_ptrace_peekuser(struct thread *td, pid_t pid, void *addr, void *data) {

	LINUX_RATELIMIT_MSG_OPT1("PTRACE_PEEKUSER offset %ld not implemented; returning EINVAL", (uintptr_t)addr);

	return (EINVAL);
}

int linux_ptrace_pokeuser(struct thread *td, pid_t pid, void *addr, void *data) {

	LINUX_RATELIMIT_MSG_OPT1("PTRACE_POKEUSER offset %ld not implemented; returning EINVAL", (uintptr_t)addr);

	return (EINVAL);
}
