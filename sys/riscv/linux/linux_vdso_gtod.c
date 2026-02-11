/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2012 Konstantin Belousov <kib@FreeBSD.org>
 * Copyright (c) 2021 Dmitry Chagin <dchagin@FreeBSD.org>
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

#define VDSO_TIMEHANDS_MD32 VDSO_TIMEHANDS_MD
#include <sys/elf.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/stdarg.h>
#include <sys/stddef.h>
#define	_KERNEL
#include <sys/vdso.h>
#undef	_KERNEL
#include <stdbool.h>

#include <machine/atomic.h>

#include <riscv/linux/linux.h>
#include <riscv/linux/linux_syscall.h>
#include <compat/linux/linux_errno.h>
#include <compat/linux/linux_time.h>

#include <sys/param.h>
#include <sys/imgact.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sysent.h>

#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_param.h>

#include <compat/linux/linux_vdso.h>
#include <stdio.h>



typedef int64_t         l_longlong;
typedef l_longlong      l_time64_t;
struct l_timespec64 {
        l_time64_t      tv_sec;
        l_longlong      tv_nsec;
};


/* The kernel fixup this at vDSO install */
uintptr_t *kern_timekeep_base = NULL;
uint32_t kern_tsc_selector = 0;


SLIST_HEAD(, linux_vdso_sym) elf64_linux_vdso_syms =
    SLIST_HEAD_INITIALIZER(elf64_linux_vdso_syms);
 
void elf64_linux_vdso_sym_initx(struct linux_vdso_sym *s){
 	if(s == NULL) return;
        SLIST_INSERT_HEAD(&elf64_linux_vdso_syms, s, sym);
}

#ifdef DEBUG_VDSO
static int write(int lfd, const void *lbuf, size_t lsize) {
	register long svc asm("a7") = LINUX_SYS_linux_write;
	register int fd asm("a0") = lfd;
	register const char *buf asm("a1") = lbuf;
	register long size asm("a2") = lsize;

	elf64_linux_vdso_sym_init(NULL);
	asm volatile("ecall" : "+r" (fd) : "r" (buf), "r" (size), "r" (svc) : "memory");
	return ((int)fd);
}
#endif

static int __vdso_getcpu_fallback(uint32_t *cpu, uint32_t *node, void *cache) {
	register long a7 asm("a7") = LINUX_SYS_linux_getcpu;
	register uint64_t a0 asm("a0") = (uint64_t)cpu;
	register uint32_t *a1 asm("a1") = node;
	register uint32_t *a2 asm("a2") = cache;

        asm volatile ("ecall" : "+r"(a0) : "r" (a1), "r"(a2), "r"(a7) : "memory");
        return ((int)a0);
}


static int __vdso_clock_gettime_fallback(clockid_t clock_id, struct l_timespec *lts) {
	register long svc asm("a7") = LINUX_SYS_linux_clock_gettime;
	register clockid_t clockid asm("a0") = clock_id;
	register struct l_timespec *ts asm("a1") = lts;


	asm volatile("ecall" : "+r" (clockid) : "r" (ts), "r" (svc) : "memory");
	return ((int)clockid);
}

static int __vdso_gettimeofday_fallback(l_timeval *ltv, struct timezone *ltz) {
	register long svc asm("a7") = LINUX_SYS_gettimeofday;
	register uint64_t tv asm("a0") = (uint64_t)ltv;
	register struct timezone *tz asm("a1") = ltz;

	asm volatile("ecall" : "+r" (tv) : "r" (tz), "r" (svc) : "memory");

	return ((int)tv);
}

static int __vdso_clock_getres_fallback(clockid_t clock_id, struct l_timespec *lts) {
	register long svc asm("a7") = LINUX_SYS_linux_clock_getres;
	register clockid_t clockid asm("a0") = clock_id;
	register struct l_timespec *ts asm("a1") = lts;

	asm volatile("ecall" : "+r" (clockid) : "r" (ts), "r" (svc) : "memory");

	return ((int)clockid);
}

int __vdso_gettc(const struct vdso_timehands *th, u_int *tc)
{
//	write("LINUX-TODO: __vdso_gettc\n");
	return(ENOSYS);
}


#include <compat/linux/linux_vdso_gtod.inc>
