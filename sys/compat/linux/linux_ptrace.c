/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2017 Edward Tomasz Napierala <trasz@FreeBSD.org>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

//#define DO_DEBUG_GETREGSETPR
//#define DO_DEBUG_GETREGS
//#define DO_DEBUG_GETFPREGS

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>

#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_errno.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_util.h>

#include <sys/mutex.h>

#define	LINUX_PTRACE_TRACEME		0
#define	LINUX_PTRACE_PEEKTEXT		1
#define	LINUX_PTRACE_PEEKDATA		2
#define	LINUX_PTRACE_PEEKUSER		3
#define	LINUX_PTRACE_POKETEXT		4
#define	LINUX_PTRACE_POKEDATA		5
#define	LINUX_PTRACE_POKEUSER		6
#define	LINUX_PTRACE_CONT		7
#define	LINUX_PTRACE_KILL		8
#define	LINUX_PTRACE_SINGLESTEP		9
#define	LINUX_PTRACE_GETREGS		12
#define	LINUX_PTRACE_SETREGS		13
#define	LINUX_PTRACE_GETFPREGS		14
#define	LINUX_PTRACE_SETFPREGS		15
#define	LINUX_PTRACE_ATTACH		16
#define	LINUX_PTRACE_DETACH		17
#define	LINUX_PTRACE_SYSCALL		24
#define	LINUX_PTRACE_SETOPTIONS		0x4200
#define	LINUX_PTRACE_GETEVENTMSG	0x4201
#define	LINUX_PTRACE_GETSIGINFO		0x4202
#define	LINUX_PTRACE_GETREGSET		0x4204
#define	LINUX_PTRACE_SEIZE		0x4206
#define	LINUX_PTRACE_GET_SYSCALL_INFO	0x420e


#define LINUX_PTRACE_EVENT_FORK          1
#define LINUX_PTRACE_EVENT_VFORK         2
#define LINUX_PTRACE_EVENT_CLONE         3
#define LINUX_PTRACE_EVENT_EXEC          4
#define LINUX_PTRACE_EVENT_VFORK_DONE    5
#define LINUX_PTRACE_EVENT_EXIT          6
#define LINUX_SIGTRAP 5

#define	LINUX_PTRACE_O_TRACESYSGOOD	1
#define	LINUX_PTRACE_O_TRACEFORK	2
#define	LINUX_PTRACE_O_TRACEVFORK	4
#define	LINUX_PTRACE_O_TRACECLONE	8
#define	LINUX_PTRACE_O_TRACEEXEC	16
#define	LINUX_PTRACE_O_TRACEVFORKDONE	32
#define	LINUX_PTRACE_O_TRACEEXIT	64
#define	LINUX_PTRACE_O_TRACESECCOMP	128
#define	LINUX_PTRACE_O_EXITKILL		1048576
#define	LINUX_PTRACE_O_SUSPEND_SECCOMP	2097152

#define	LINUX_NT_PRSTATUS		0x1
#define	LINUX_NT_PRFPREG		0x2
#define	LINUX_NT_X86_XSTATE		0x202

#define	LINUX_PTRACE_O_MASK	(LINUX_PTRACE_O_TRACESYSGOOD |	\
    LINUX_PTRACE_O_TRACEFORK | LINUX_PTRACE_O_TRACEVFORK |	\
    LINUX_PTRACE_O_TRACECLONE | LINUX_PTRACE_O_TRACEEXEC |	\
    LINUX_PTRACE_O_TRACEVFORKDONE | LINUX_PTRACE_O_TRACEEXIT |	\
    LINUX_PTRACE_O_TRACESECCOMP | LINUX_PTRACE_O_EXITKILL |	\
    LINUX_PTRACE_O_SUSPEND_SECCOMP)

#define	LINUX_PTRACE_SYSCALL_INFO_NONE	0
#define	LINUX_PTRACE_SYSCALL_INFO_ENTRY	1
#define	LINUX_PTRACE_SYSCALL_INFO_EXIT	2

static int
map_signum(int lsig, int *bsigp)
{
	int bsig;

	if (lsig == 0) {
		*bsigp = 0;
		return (0);
	}

	if (lsig < 0 || lsig > LINUX_SIGRTMAX)
		return (EINVAL);

	bsig = linux_to_bsd_signal(lsig);
	if (bsig == SIGSTOP)
		bsig = 0;

	*bsigp = bsig;
	return (0);
}

int linux_ptrace_status(struct thread *td, pid_t pid, int status) {
        struct ptrace_lwpinfo lwpinfo;
        struct linux_pemuldata *pem;
        register_t saved_retval;
        int error;

#ifdef DO_DEBUG_STATUS
	int in_status=status;

	char debug_name[100];
	if(pid != 0){
		struct proc *p = pfind(pid); 
		if(p){
			strcpy(debug_name, p->p_comm);
			PROC_UNLOCK(p);
		}
	}else debug_name[0]=0;

#endif


        saved_retval = td->td_retval[0];
        error = kern_ptrace(td, PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));
        td->td_retval[0] = saved_retval;

        if (error != 0) {
                linux_msg(td, "PT_LWPINFO failed with error %d", error);
		goto out;
        }

        pem = pem_find(td->td_proc);
        KASSERT(pem != NULL, ("%s: proc emuldata not found.\n", __func__));

        LINUX_PEM_SLOCK(pem);

        if ((pem->ptrace_flags & LINUX_PTRACE_O_TRACESYSGOOD) && lwpinfo.pl_flags & PL_FLAG_SCE)
                status |= (LINUX_SIGTRAP | 0x80) << 8;

        if ((pem->ptrace_flags & LINUX_PTRACE_O_TRACESYSGOOD) && lwpinfo.pl_flags & PL_FLAG_SCX) {
                if (lwpinfo.pl_flags & PL_FLAG_EXEC){
                        status |= (LINUX_SIGTRAP | LINUX_PTRACE_EVENT_EXEC << 8) << 8;
                }else{
                        status |= (LINUX_SIGTRAP | 0x80) << 8;
		}
        }

        if ((pem->ptrace_flags & LINUX_PTRACE_O_TRACEEXIT) && lwpinfo.pl_flags & PL_FLAG_EXITED){
		status |= (LINUX_SIGTRAP | LINUX_PTRACE_EVENT_EXIT << 8) << 8;
	}

        LINUX_PEM_SUNLOCK(pem);

out:
#ifdef DO_DEBUG_STATUS
	printf("< linux_ptrace_status('%s [%d]', %d [%s], 0x%x) = %d\n", td->td_name, td->td_proc->p_pid, pid, debug_name, in_status, status);
#endif
        return (status);
}




static int
linux_ptrace_peek(struct thread *td, pid_t pid, void *addr, void *data)
{
	int error;

#ifdef DO_DEBUG_PEEK
	char debug_name[100];
	debug_name[0]=0;
	if(pid != 0){
		struct proc *p = pfind(pid); 
		if(p){
			strcpy(debug_name, p->p_comm);
			PROC_UNLOCK(p);
		}
	}
#endif
	error = kern_ptrace(td, PT_READ_I, pid, addr, 0);
	if (error == 0){
		if(td->td_name[3] == 0){	// TODO FIX ME FOR GDB
			error = copyout(td->td_retval, data, sizeof(uint64_t));
		}else{
			error = copyout(td->td_retval, data, sizeof(l_int));
		}
	}else if (error == ENOMEM){
		error = EIO;
	}


#ifdef DO_DEBUG_PEEK
	printf("< linux_ptrace_peek('%s [%d]', %d [%s], %p, 0x%lx) = %d\n", td->td_name, td->td_proc->p_pid, pid, debug_name, addr, td->td_retval[0], error);
#endif

	td->td_retval[0] = error;
	return (error);
}

static int
linux_ptrace_setoptions(struct thread *td, pid_t pid, l_ulong data)
{
	struct linux_pemuldata *pem;
	int mask = 0, error = 0;

//	*** We needed this for GDB and we just make it work
//
//	if (data & (LINUX_PTRACE_O_TRACEFORK | LINUX_PTRACE_O_TRACEVFORK | LINUX_PTRACE_O_TRACECLONE)) {
//	    printf("LINUX_DEBUG: Rejecting Fork/Clone tracing request\n");
//	    return (EINVAL); 
//	}

	if (data & ~LINUX_PTRACE_O_MASK) {
		linux_msg(td, "unknown ptrace option %lx set; returning EINVAL", data & ~LINUX_PTRACE_O_MASK);
		goto out;
	}

	pem = pem_find(td->td_proc);
	KASSERT(pem != NULL, ("%s: proc emuldata not found.\n", __func__));

	 /*
	 * PTRACE_O_EXITKILL is ignored, we do that by default.
	 */

	LINUX_PEM_XLOCK(pem);
	pem->ptrace_flags = data;
	LINUX_PEM_XUNLOCK(pem);

	if (data & LINUX_PTRACE_O_TRACESYSGOOD) mask |= 1;
	if (data & LINUX_PTRACE_O_TRACEFORK) mask |= PTRACE_FORK;
	if (data & LINUX_PTRACE_O_TRACEVFORK) mask |= PTRACE_VFORK;
	if (data & LINUX_PTRACE_O_TRACECLONE) mask |= PTRACE_VFORK;
	if (data & LINUX_PTRACE_O_TRACEEXEC) mask |= PTRACE_EXEC;
	if (data & LINUX_PTRACE_O_TRACEEXIT) mask |= PTRACE_LWP; 
	if(1048576 == data) mask = PTRACE_EXEC;		// Some special GDB magic sause required here.

	error=kern_ptrace(td, PT_SET_EVENT_MASK, pid, &mask, sizeof(mask));
	if(error == 0 && pid != 0 && 1048576 == data){
		error = kern_ptrace(td, PT_CONTINUE, pid, (void *)1, 9);	// SIGSTOP
	}

out:
#ifdef DO_DEBUG_SETOPTIONS
	printf("< linux_ptrace_setoptions('%s [%d]', %d, 0x%lx) -> kern_ptrace(PT_SET_EVENT_MASK, 0x%x) = %d\n",td->td_name, td->td_proc->p_pid, pid, data, mask, error);
#endif
	return(error);
}

static int
linux_ptrace_geteventmsg(struct thread *td, pid_t pid, l_ulong data)
{
	return(EINVAL);
	struct ptrace_lwpinfo lwpinfo; 
	struct linux_pemuldata *pem = pem_find(td->td_proc);

	int error = kern_ptrace(td, PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));

        if (error != 0) return (error);


	l_ulong child_pid = (l_ulong)pem->cached_child_pid;
	if (child_pid != 0) {
            error = copyout(&child_pid, (void *)data, sizeof(child_pid));
	    pem->cached_child_pid=0;
	    //printf("LINUX_GETEVENTMSG: tracer=%d, reported_child=%lu\n", td->td_proc->p_pid, child_pid);

        } else {
            /* If no child info, return 0 as a fallback */
            l_ulong zero = 0;
            error = copyout(&zero, (void *)data, sizeof(zero));
        }

	
#ifdef DO_DEBUG_EVENTMSG
	printf("< linux_ptrace_geteventmsg('%s [%d]', %d, 0x%lx) = %d [child=%lu]\n", td->td_name, td->td_proc->p_pid, pid, data, error, child_pid);
#endif
	return(error);

}



static int linux_ptrace_getsiginfo(struct thread *td, pid_t pid, l_ulong data) {
        struct ptrace_lwpinfo lwpinfo;
        l_siginfo_t l_siginfo;
        int error, sig;

        error = kern_ptrace(td, PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));
        if (error != 0) {
                linux_msg(td, "PT_LWPINFO failed with error %d", error);
                return (error);
        }

        if ((lwpinfo.pl_flags & PL_FLAG_SI) == 0) {
                error = EINVAL;
                linux_msg(td, "no PL_FLAG_SI, returning %d", error);
                return (error);
        }

        sig = bsd_to_linux_signal(lwpinfo.pl_siginfo.si_signo);
        memset(&l_siginfo, 0, sizeof(l_siginfo));
        siginfo_to_lsiginfo(&lwpinfo.pl_siginfo, &l_siginfo, sig);
        error = copyout(&l_siginfo, (void *)data, sizeof(l_siginfo));
        return (error);
}


static int linux_ptrace_getregs(struct thread *td, pid_t pid, void *data) {
#ifdef DO_DEBUG_GETREGS
	char debug_name[100];
#endif
	struct reg b_reg;
	struct linux_pt_regset l_regset;
	int error;

	error = kern_ptrace(td, PT_GETREGS, pid, &b_reg, 0);
	if (error != 0) goto out;

	error = linux_ptrace_getregs_machdep(td, pid, &l_regset);
	if (error != 0) goto out;

	error = copyout(&l_regset, (void *)data, sizeof(l_regset));

out:
#ifdef DO_DEBUG_GETREGS
	printf("Getregs: Got PC=0x%lx, SP=0x%lx\n", l_regset.pc, l_regset.sp);

	debug_name[0]=0;
	if(pid != 0){
		struct proc *p = pfind(pid); 
		if(p){
			strcpy(debug_name, p->p_comm);
			PROC_UNLOCK(p);
		}
	}
	printf("< linux_ptrace_getregs('%s [%d]', %d [%s]) = %d\n", td->td_name, td->td_proc->p_pid, pid, debug_name, error);
#endif
	return (error);
}

static int linux_ptrace_setregs(struct thread *td, pid_t pid, void *data) {
	char debug_name[100];
	struct reg b_reg;
	struct linux_pt_regset l_regset;
	int error;

	error = copyin(data, &l_regset, sizeof(l_regset));
	if (error != 0) goto out;

	linux_to_bsd_regset(&b_reg, &l_regset);
	error = kern_ptrace(td, PT_SETREGS, pid, &b_reg, 0);

	debug_name[0]=0;
	if(pid != 0){
		struct proc *p = pfind(pid); 
		if(p){
			strcpy(debug_name, p->p_comm);
			PROC_UNLOCK(p);
		}
	}

out:
	printf("< linux_ptrace_setregs('%s [%d]', %d [%s]) = %d\n", td->td_name, td->td_proc->p_pid, pid, debug_name, error);
	return (error);
}

static int linux_ptrace_getfpregset_prstatus(struct thread *td, pid_t pid, l_ulong data) {
#ifdef DO_DEBUG_GETFPREGS
	char debug_name[100];
	int	oldlen=0;	
#endif
	struct fpreg bsd_fpregs;
	struct iovec iov;
	int error;

	struct {				// Juck.. TODO :-)
        	uint64_t fp_x[32];
		uint32_t fcsr;
	} __attribute__((packed)) linux_fpregs;

	error = copyin((const void *)data, &iov, sizeof(iov));
	if (error != 0) {
		linux_msg(td, "copyin error %d", error);
		goto out;
	}

	if(iov.iov_len < 200) return(EINVAL);
#ifdef DO_DEBUG_GETFPREGS
	oldlen=iov.iov_len;
#endif
	error = kern_ptrace(td, PT_GETFPREGS, pid, &bsd_fpregs, 0);
	if (error != 0)	goto out;


	for (int i = 0; i < 32; i++) linux_fpregs.fp_x[i] = bsd_fpregs.fp_x[i][0]; 
	linux_fpregs.fcsr = bsd_fpregs.fp_fcsr;

	iov.iov_len = sizeof(linux_fpregs); // MIN(iov.iov_len, sizeof(linux_fpregs));
	error = copyout(&linux_fpregs, (void *)iov.iov_base, iov.iov_len);
	if (error != 0) { 
		linux_msg(td, "copyout error %d", error); 
		goto out;
	}
	error = copyout(&iov, (void *)data, sizeof(iov)); 
	if (error != 0) { 
		linux_msg(td, "iov copyout error %d", error); 
	}

out:
#ifdef DO_DEBUG_GETFPREGS
	if(pid != 0){
		struct proc *p = pfind(pid); 
		if(p){
			strcpy(debug_name, p->p_comm);
			PROC_UNLOCK(p);
		}
	}else debug_name[0]=0;


	printf("< linux_ptrace_getfpregset_prstatus('%s [%d]', %d [%s], 0x%lx) = %d   lengths[%d/%ld]\n", td->td_name, td->td_proc->p_pid, pid, debug_name, data, error, oldlen, sizeof(linux_fpregs));
#endif
	return(error);
}

static int linux_ptrace_getregset_prstatus(struct thread *td, pid_t pid, l_ulong data) {
#ifdef DO_DEBUG_GETREGSETPR
	char debug_name[100];
	int oldlen=0;
#endif
	struct reg b_reg;
	struct linux_pt_regset l_regset;
	struct iovec iov;
	size_t len;
	int error;

	error = copyin((const void *)data, &iov, sizeof(iov));
	if (error != 0) {
		linux_msg(td, "copyin error %d", error);
		goto out;
	}

	error = kern_ptrace(td, PT_GETREGS, pid, &b_reg, 0);
	if (error != 0) goto out;

	bsd_to_linux_regset(&b_reg, &l_regset);
	error = linux_ptrace_getregs_machdep(td, pid, &l_regset);
	if (error != 0) goto out;

#ifdef DO_DEBUG_GETREGSETPR
	oldlen=iov.iov_len;
#endif
	len = MIN(iov.iov_len, sizeof(l_regset));
	error = copyout(&l_regset, (void *)iov.iov_base, len);
	if (error != 0) {
		linux_msg(td, "copyout error %d", error);
		goto out;
	}

	iov.iov_len = len;
	error = copyout(&iov, (void *)data, sizeof(iov));
	if (error != 0) {
		linux_msg(td, "iov copyout error %d", error);
	}

out:
#ifdef DO_DEBUG_GETREGSETPR
	printf("Getregset: Got PC=0x%lx, SP=0x%lx\n", l_regset.pc, l_regset.sp);
	if(pid != 0){
		struct proc *p = pfind(pid); 
		if(p){
			strcpy(debug_name, p->p_comm);
			PROC_UNLOCK(p);
		}
	}else debug_name[0]=0;

	printf("< linux_ptrace_getregset_prstatus('%s [%d]', %d [%s], 0x%lx) = %d  lengths=[%d/%lu]\n", td->td_name, td->td_proc->p_pid, pid, debug_name, data, error, oldlen, sizeof(l_regset));
#endif
	return (error);
}

static int linux_ptrace_getregset(struct thread *td, pid_t pid, l_ulong addr, l_ulong data) {

	switch (addr) {
	case LINUX_NT_PRSTATUS:
		return (linux_ptrace_getregset_prstatus(td, pid, data));
	case LINUX_NT_PRFPREG:
		return (linux_ptrace_getfpregset_prstatus(td, pid, data));
	case LINUX_NT_X86_XSTATE:
		linux_msg(td, "PTRAGE_GETREGSET NT_X86_XSTATE not implemented; "
		    "returning EINVAL");
		return (EINVAL);
	default:
		linux_msg(td, "PTRACE_GETREGSET request %#lx not implemented; "
		    "returning EINVAL", addr);
		return (EINVAL);
	}
}

static int linux_ptrace_seize(struct thread *td, pid_t pid, l_ulong addr, l_ulong data) {

	linux_msg(td, "PTRACE_SEIZE not implemented; returning EINVAL");
	return (EINVAL);
}

static int linux_ptrace_get_syscall_info(struct thread *td, pid_t pid, l_ulong len, l_ulong data) {
	struct ptrace_lwpinfo lwpinfo;
	struct ptrace_sc_ret sr;
	struct reg b_reg;
	struct syscall_info si;
	int error;

	error = kern_ptrace(td, PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));
	if (error != 0) {
		linux_msg(td, "PT_LWPINFO failed with error %d", error);
		return (error);
	}

	memset(&si, 0, sizeof(si));

	if (lwpinfo.pl_flags & PL_FLAG_SCE) {
		si.op = LINUX_PTRACE_SYSCALL_INFO_ENTRY;
		si.entry.nr = lwpinfo.pl_syscall_code;
		error = kern_ptrace(td, PTLINUX_GET_SC_ARGS, pid,
		    si.entry.args, sizeof(si.entry.args));
		if (error != 0) {
			linux_msg(td, "PT_LINUX_GET_SC_ARGS failed with error %d", error);
			return (error);
		}
	} else if (lwpinfo.pl_flags & PL_FLAG_SCX) {
		si.op = LINUX_PTRACE_SYSCALL_INFO_EXIT;
		error = kern_ptrace(td, PT_GET_SC_RET, pid, &sr, sizeof(sr));

		if (error != 0) {
			linux_msg(td, "PT_GET_SC_RET failed with error %d", error);
			return (error);
		}

		if (sr.sr_error == 0) {
			si.exit.rval = sr.sr_retval[0];
			si.exit.is_error = 0;
		} else if (sr.sr_error == EJUSTRETURN) {
			/*
			 * EJUSTRETURN means the actual value to return
			 * has already been put into td_frame; instead
			 * of extracting it and trying to determine whether
			 * it's an error or not just bail out and let
			 * the ptracing process fall back to another method.
			 */
			si.op = LINUX_PTRACE_SYSCALL_INFO_NONE;
		} else if (sr.sr_error == ERESTART) {
			si.exit.rval = -LINUX_ERESTARTSYS;
			si.exit.is_error = 1;
		} else {
			si.exit.rval = bsd_to_linux_errno(sr.sr_error);
			si.exit.is_error = 1;
		}
	} else {
		si.op = LINUX_PTRACE_SYSCALL_INFO_NONE;
	}

	error = kern_ptrace(td, PT_GETREGS, pid, &b_reg, 0);
	if (error != 0)
		return (error);

	linux_ptrace_get_syscall_info_machdep(&b_reg, &si);

	len = MIN(len, sizeof(si));
	error = copyout(&si, (void *)data, len);
	if (error == 0)
		td->td_retval[0] = sizeof(si);

	return (error);
}

int
linux_ptrace(struct thread *td, struct linux_ptrace_args *uap)
{
	void *addr;
	pid_t pid;
	int error, sig;

	if (!allow_ptrace)
		return (ENOSYS);

	pid  = (pid_t)uap->pid;
	addr = (void *)uap->addr;


#ifdef DO_DEBUG_PTRACE_MAIN
	char debug_name[100];
	debug_name[0]=0;
	if(pid != 0){
		struct proc *p = pfind(pid); 
		if(p){
			strcpy(debug_name, p->p_comm);
			PROC_UNLOCK(p);
		}
	}
#endif

	switch (uap->req) {
	case LINUX_PTRACE_TRACEME:
		error = kern_ptrace(td, PT_TRACE_ME, 0, 0, 0);
#ifdef DO_DEBUG_PTRACE_MAIN
		printf("< linux_ptrace_traceme('%s [%d]') = %d\n", td->td_name, td->td_proc->p_pid, error);
#endif
		break;

	case LINUX_PTRACE_PEEKTEXT:
	case LINUX_PTRACE_PEEKDATA:
		error = linux_ptrace_peek(td, pid, addr, (void *)uap->data);
		if (error != 0)
			goto out;
		/*
		 * Linux expects this syscall to read 64 bits, not 32.
		 */
		error = linux_ptrace_peek(td, pid,
		    (void *)(uap->addr + 4), (void *)(uap->data + 4));
		break;
	case LINUX_PTRACE_PEEKUSER:
		error = linux_ptrace_peekuser(td, pid, addr, (void *)uap->data);
#ifdef DO_DEBUG_PTRACE_MAIN
		printf("< linux_ptrace_peekuser('%s [%d]', %d [%s], %p) = %d\n", td->td_name, td->td_proc->p_pid, pid, debug_name, addr, error);
#endif
		break;
	case LINUX_PTRACE_POKETEXT:
	case LINUX_PTRACE_POKEDATA:
		error = kern_ptrace(td, PT_WRITE_D, pid, addr, uap->data);
		if (error != 0)
			goto out;
		/*
		 * Linux expects this syscall to write 64 bits, not 32.
		 */
		error = kern_ptrace(td, PT_WRITE_D, pid,
		    (void *)(uap->addr + 4), uap->data >> 32);
		break;
	case LINUX_PTRACE_POKEUSER:
		error = linux_ptrace_pokeuser(td, pid, addr, (void *)uap->data);
		break;
	case LINUX_PTRACE_CONT:
		error = map_signum(uap->data, &sig);
		if (error == 0){
			error = kern_ptrace(td, PT_CONTINUE, pid, (void *)1, sig);
#ifdef DO_DEBUG_PTRACE_MAIN
			printf("< linux_ptrace_continue('%s [%d]', %d [%s], 1, 0x%x) = %d\n", td->td_name, td->td_proc->p_pid, pid, debug_name, sig, error);
#endif
			//printf("DEBUG_CONT: pid=%d, pc=0x%lx, signal=%d, error=%d, a0=0x%lx, pc-4=0x%08x, a7=0x%lx\n",  pid, debuggee_pc ,sig, error, tmp0, prev_insn, tmp7);
		}

		break;
	case LINUX_PTRACE_KILL:
		error = kern_ptrace(td, PT_KILL, pid, addr, uap->data);
		break;
	case LINUX_PTRACE_SINGLESTEP:
		error = map_signum(uap->data, &sig);
		if (error != 0)
			break;
		error = kern_ptrace(td, PT_STEP, pid, (void *)1, sig);
		break;
	case LINUX_PTRACE_GETREGS:
		error = linux_ptrace_getregs(td, pid, (void *)uap->data);
		break;
	case LINUX_PTRACE_SETREGS:
		printf("DEBUG_SETREGS: pid=%d\n", pid);

		error = linux_ptrace_setregs(td, pid, (void *)uap->data);
		break;
	case LINUX_PTRACE_ATTACH:
		
		error = kern_ptrace(td, PT_ATTACH, pid, addr, uap->data);

#ifdef DO_DEBUG_PTRACE_MAIN
		printf("< linux_ptrace_attach('%s [%d]', %d [%s], %p, data=%ld) = %d\n", td->td_name, td->td_proc->p_pid, pid, debug_name, addr, uap->data, error);
#endif
		//if(error == EBUSY || error == EDEADLK){
		//	printf("NOKITEL BYPASS: Silencing error %d for cmd %ld\n", error, uap->req);
		//	error=0;
		//}

		break;
	case LINUX_PTRACE_DETACH:
		error = map_signum(uap->data, &sig);
		if (error == 0) error = kern_ptrace(td, PT_DETACH, pid, (void *)1, sig);

#ifdef DO_DEBUG_PTRACE_MAIN
		printf("< linux_ptrace_detach('%s [%d]', %d [%s], 1, 0x%x) = %d\n", td->td_name, td->td_proc->p_pid, pid, debug_name, sig, error);
#endif
		break;
	case LINUX_PTRACE_SYSCALL:
		error = map_signum(uap->data, &sig);
		if (error == 0) error = kern_ptrace(td, PT_SYSCALL, pid, (void *)1, sig);

#ifdef DO_DEBUG_PTRACE_MAIN
		printf("< linux_ptrace_syscall('%s [%d]', %d [%s], 1, 0x%x) = %d\n", td->td_name, td->td_proc->p_pid, pid, debug_name, sig, error);
#endif
		break;
	case LINUX_PTRACE_SETOPTIONS:
		error = linux_ptrace_setoptions(td, pid, uap->data);
		break;
	case LINUX_PTRACE_GETEVENTMSG:
		error = linux_ptrace_geteventmsg(td, pid, uap->data);
		break;
	case LINUX_PTRACE_GETSIGINFO:
		error = linux_ptrace_getsiginfo(td, pid, uap->data);
		break;
	case LINUX_PTRACE_GETREGSET:
		error = linux_ptrace_getregset(td, pid, uap->addr, uap->data);
		break;
	case LINUX_PTRACE_SEIZE:
		error = linux_ptrace_seize(td, pid, uap->addr, uap->data);
		break;
	case LINUX_PTRACE_GET_SYSCALL_INFO:
		error = linux_ptrace_get_syscall_info(td, pid, uap->addr, uap->data);
		break;
	default:
		linux_msg(td, "ptrace(%ld, ...) not implemented; "
		    "returning EINVAL", uap->req);
		error = EINVAL;
		break;
	}

out:
	if (error == EBUSY){		// TODO: test we still need this special req==7 case?
		if(uap->req == 7) error = EAGAIN; else error = ESRCH;
	}
	return (error);
}
