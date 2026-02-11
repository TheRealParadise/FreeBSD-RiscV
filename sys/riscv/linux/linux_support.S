/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2018 Turing Robotic Industries Inc.
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

#include <sys/elf_common.h>

#include <machine/asm.h>
#include <machine/param.h>
//#include <machine/vmparam.h>

#include <sys/errno.h>
#include "/usr/src/sys/riscv/include/riscvreg.h"
#include "assym.inc"

.macro check_user_access user_arg, limit, bad_addr_func
//	ldr	x7, =(\limit)
//	cmp	x\user_arg, x7
//	b.cs	\bad_addr_func
.endm

futex_fault:
        SET_FAULT_HANDLER(zero, t1)
        li      t1, SSTATUS_SUM
        csrc    sstatus, t1             /* Clear SUM bit in sstatus */
futex_fault_nopcb:
        /* 3. Return the standard EFAULT error code */
        li      a0, -EFAULT
        ret

#define	LINUX_FUTEX_MAX_LOOPS	256

/*
 * int oparg, uint32_t *uaddr, int *oldval
 *
 * Return 0 on success, errno on failure,
 * EAGAIN is returned if LL/SC operation fails.
 *
 * XXX. VM_MAXUSER_ADDRESS is not applicable here, should be replaced
 * by something like LINUX_SHAREDPAGE.
 */

/* (int *)uaddr2 = oparg */
ENTRY(futex_xchgl)
	/* a0 = oparg (new value)
           a1 = uaddr (user space address)
           a2 = oldval_out (kernel pointer to store the old value)
        */

        // Setup Fault Handler
        la      t1, futex_fault
        SET_FAULT_HANDLER(t1, t0)

        // Enable User Memory Access (SUM bit)
        li      t2, SSTATUS_SUM
        csrrs   t3, sstatus, t2         // Save old sstatus in t3 */
1:      amoswap.w.aqrl t0, a0, (a1)
        csrw    sstatus, t3		// Disable User Access (Restore sstatus) 
       
        // Cleanup and Store Result
        SET_FAULT_HANDLER(zero, t1)     // Clear fault handler
        sw      t0, 0(a2)               // Write old value to the output pointer
        li      a0, 0                   // Return success (0)
        ret
END(futex_xchgl)


// TODO: FIX/CHECK ALL BELOW
/* (int *)uaddr2 += oparg */
ENTRY(futex_addl)
        // Setup Fault Handler
        la      t1, futex_fault
        SET_FAULT_HANDLER(t1, t0)
        
        // Enable User Access (SUM bit)
        li      t2, SSTATUS_SUM
        csrrs   t3, sstatus, t2         // Enable User Access, save old status in t3

        li      t4, LINUX_FUTEX_MAX_LOOPS
1:
	lr.w.aq t0, (a1)                // Load Reserved (oldval) from USER
	add     t1, t0, a0              // Calculate newval
	sc.w.rl t5, t1, (a1)            // Store Conditional to USER
	bnez    t5, 2f                  // Failed? Go to retry logic

	li      a0, 0			// SUCCESS PATH
	j       4f

2: 	// RETRY LOGIC
	addi    t4, t4, -1
	bnez    t4, 1b
	li      a0, -EFAULT             // If we can't hit it in X loops, something is wrong

4:      // Cleanup and Exit
        sw      t0, 0(a2)               // Store the captured oldval to *oldval_out
        csrw    sstatus, t3             // EXIT_USER_ACCESS: Restore sstatus
        SET_FAULT_HANDLER(zero, t1)     // Reset fault handler
        ret
END(futex_addl)

/* (int *)uaddr2 |= oparg */
ENTRY(futex_orl)
        la      t1, futex_fault
        SET_FAULT_HANDLER(t1, t0)      
        li      t2, SSTATUS_SUM
        csrrs   t3, sstatus, t2         // Enable User Access, save old status in t3
        li      t4, LINUX_FUTEX_MAX_LOOPS
1:      lr.w.aq t0, (a1)                // Load Reserved: t0 = *uaddr
        or      t1, t0, a0              // Bitwise AND: t1 = t0 & oparg
        sc.w.rl t5, t1, (a1)            // Store Conditional: *uaddr = t1
        beqz    t5, 3f                  // If t5 == 0, store succeeded
        addi    t4, t4, -1              // Decrement loop counter
        bnez    t4, 1b                  // Retry if counter > 0
        li      a0, -EAGAIN             // Loops exhausted, return EAGAIN
        j       4f
3:      li      a0, 0                   // Success return code
4:      sw      t0, 0(a2)               // Store the captured oldval to *oldval_out
        csrw    sstatus, t3             // EXIT_USER_ACCESS: Restore sstatus
        SET_FAULT_HANDLER(zero, t1)     // Reset fault handler
        ret
END(futex_orl)

/* (int *)uaddr2 &= oparg */
ENTRY(futex_andl)
        la      t1, futex_fault
        SET_FAULT_HANDLER(t1, t0)
        li      t2, SSTATUS_SUM
        csrrs   t3, sstatus, t2         // Enable User Access, save old status in t3
        li      t4, LINUX_FUTEX_MAX_LOOPS
1:      lr.w.aq t0, (a1)                // Load Reserved: t0 = *uaddr
        and     t1, t0, a0              // Bitwise AND: t1 = t0 & oparg
        sc.w.rl t5, t1, (a1)            // Store Conditional: *uaddr = t1
        beqz    t5, 3f                  // If t5 == 0, store succeeded
        addi    t4, t4, -1              // Decrement loop counter
        bnez    t4, 1b                  // Retry if counter > 0
        li      a0, -EAGAIN             // Loops exhausted, return EAGAIN
        j       4f
3:      li      a0, 0                   // Success return code
4:      sw      t0, 0(a2)               // Store the captured oldval to *oldval_out
        csrw    sstatus, t3             // EXIT_USER_ACCESS: Restore sstatus
        SET_FAULT_HANDLER(zero, t1)     // Reset fault handler
        ret
END(futex_andl)

/* (int *)uaddr2 ^= oparg */
ENTRY(futex_xorl)
        la      t1, futex_fault
        SET_FAULT_HANDLER(t1, t0)
        li      t2, SSTATUS_SUM
        csrrs   t3, sstatus, t2         // Enable User Access, save old status in t3
        li      t4, LINUX_FUTEX_MAX_LOOPS
1:      lr.w.aq t0, (a1)                // Load Reserved: t0 = *uaddr
        xor     t1, t0, a0              // Bitwise XOR: t1 = t0 & oparg
        sc.w.rl t5, t1, (a1)            // Store Conditional: *uaddr = t1
        beqz    t5, 3f                  // If t5 == 0, store succeeded
        addi    t4, t4, -1              // Decrement loop counter
        bnez    t4, 1b                  // Retry if counter > 0
        li      a0, -EAGAIN             // Loops exhausted, return EAGAIN
        j       4f
3:      li      a0, 0                   // Success return code
4:      sw      t0, 0(a2)               // Store the captured oldval to *oldval_out
        csrw    sstatus, t3             // EXIT_USER_ACCESS: Restore sstatus
        SET_FAULT_HANDLER(zero, t1)     // Reset fault handler
        ret
END(futex_xorl)

//GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
