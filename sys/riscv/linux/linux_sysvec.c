/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1994-1996 Søren Schmidt
 * Copyright (c) 2018 Turing Robotic Industries Inc.
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

#define	__ELF_WORD_SIZE	64

#include <sys/param.h>
#include <sys/elf.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/stddef.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/types.h>
#include <sys/systm.h> 

#include <vm/vm.h>
#include <vm/vm_param.h>

#include <riscv/linux/linux.h>
#include <riscv/include/fpe.h>
#include <riscv/linux/linux_proto.h>
#include <compat/linux/linux_elf.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_fork.h>
#include <compat/linux/linux_ioctl.h>
#include <compat/linux/linux_mib.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_util.h>
#include <compat/linux/linux_vdso.h>

#include <riscv/linux/linux_sigframe.h>

#include <machine/md_var.h>
#include <machine/pcb.h>
#ifdef VFP
#include <machine/vfp.h>
#endif

extern u_long linux_elf_hwcap;
extern u_long linux_elf_hwcap2;
extern u_long linux_elf_hwcap3;
extern u_long linux_elf_hwcap4;

MODULE_VERSION(linux64elf, 1);

#define	LINUX_VDSOPAGE_SIZE	PAGE_SIZE * 2
#define	LINUX_VDSOPAGE		(VM_MAXUSER_ADDRESS - LINUX_VDSOPAGE_SIZE)
#define	LINUX_SHAREDPAGE	(LINUX_VDSOPAGE - PAGE_SIZE)
#define	LINUX_USRSTACK		LINUX_SHAREDPAGE
#define	LINUX_PS_STRINGS	(LINUX_USRSTACK - sizeof(struct ps_strings))
#define	AT_L1I_CACHELINESIZE	40
#define	AT_L1D_CACHELINESIZE	41

static int linux_szsigcode;
static vm_object_t linux_vdso_obj;
static char *linux_vdso_mapping;
extern char _binary_linux_vdso_so_o_start;
extern char _binary_linux_vdso_so_o_end;
static vm_offset_t linux_vdso_base;

extern struct sysent linux_sysent[LINUX_SYS_MAXSYSCALL];
extern const char *linux_syscallnames[];

SET_DECLARE(linux_ioctl_handler_set, struct linux_ioctl_handler);

static void	linux_vdso_install(const void *param);
static void	linux_vdso_deinstall(const void *param);
static void	linux_vdso_reloc(char *mapping, Elf_Addr offset);
static void	linux_set_syscall_retval(struct thread *td, int error);
static int	linux_fetch_syscall_args(struct thread *td);
static void	linux_exec_setregs(struct thread *td, struct image_params *imgp, uintptr_t stack);
static void	linux_exec_sysvec_init(void *param);
static int	linux_on_exec_vmspace(struct proc *p, struct image_params *imgp);

LINUX_VDSO_SYM_CHAR(linux_platform);
LINUX_VDSO_SYM_INTPTR(kern_timekeep_base);
LINUX_VDSO_SYM_INTPTR(__user_rt_sigreturn);


/* 
 * Syscall from Linuxland comes trough here
 */
static int linux_fetch_syscall_args(struct thread *td) {
	struct proc *p;
	struct syscall_args *sa;
	register_t *ap;

	p = td->td_proc;
        ap = &td->td_frame->tf_a[0];
	sa = &td->td_sa;

	sa->code = td->td_frame->tf_a[7];
	sa->original_code = sa->code;
	td->td_orig_t0=td->td_frame->tf_t[0]; // FreeBSD uses this as syscall number and syscal success

	if (sa->callp->sy_narg > nitems(sa->args))
		panic("RISCVTODO: Could we have more than %zu args?", nitems(sa->args));

	memcpy(sa->args, ap, nitems(sa->args) * sizeof(register_t));

	if (sa->code >= p->p_sysent->sv_size){
		sa->callp = &nosys_sysent;
	}else{
		sa->callp = &p->p_sysent->sv_table[sa->code];
	}
	td->td_retval[0] = 0;

	return (0);
}

/* 
 * Returning to Linuxland here
 */
static void linux_set_syscall_retval(struct thread *td, int error) {
        struct trapframe *frame=td->td_frame;
 
        if (__predict_true(error == 0)) {
                frame->tf_a[0] = td->td_retval[0];
		frame->tf_a[1] = td->td_retval[1];
                return;
        }

        switch (error) {
        case ERESTART:
                frame->tf_sepc -= 4;            /* prev instruction */
                return;
        case EJUSTRETURN:
                return;
        default:
                frame->tf_a[0] = bsd_to_linux_errno(error);
                return;
        }
}

// TODO Where is the include for this struct, counldn't find it. 

struct elf64_auxargs {
        Elf_Ssize       execfd;
        Elf_Size        phdr;
        Elf_Size        phent;
        Elf_Size        phnum;
        Elf_Size        pagesz;
        Elf_Size        base;
        Elf_Size        flags;
        Elf_Size        entry;
        Elf_Word        hdr_eflags;             /* e_flags field from ehdr */
};

struct elf_args {
    u_long  arg_entry;     /* Entry address */
    u_long  arg_interp;    /* Interpreter load address */
    u_long  arg_phaddr;    /* Program header address */
    u_long  arg_phentsize; /* Program header entity size */
    u_long  arg_phnum;     /* Program header number */
};

    
/*
 * Some AUXV stuff we require to get Linux up-to-speed.
 */

void linux64_arch_copyout_auxargs(struct image_params *imgp, Elf_Auxinfo **pos) {
	AUXARGS_ENTRY((*pos), LINUX_AT_SYSINFO_EHDR, linux_vdso_base);
	AUXARGS_ENTRY((*pos), LINUX_AT_HWCAP, *imgp->sysent->sv_hwcap);			// Todo ^^ overwritten because this gets us 0
	if (*imgp->sysent->sv_hwcap2 != 0) {
        	AUXARGS_ENTRY((*pos), LINUX_AT_HWCAP2, *imgp->sysent->sv_hwcap2);
	}
	AUXARGS_ENTRY((*pos), LINUX_AT_PLATFORM, PTROUT(linux_platform));
	AUXARGS_ENTRY((*pos), AT_L1I_CACHELINESIZE, 64); // SiFive/U74 specific TODO: get this some way else
	AUXARGS_ENTRY((*pos), AT_L1D_CACHELINESIZE, 64);
}

/*
 * Reset registers to default values on exec.
 */
static void linux_exec_setregs(struct thread *td, struct image_params *imgp, uintptr_t stack) {
	struct trapframe *regs = td->td_frame;

	memset(regs, 0, sizeof(*regs));
	regs->tf_s[6]=1;
	regs->tf_sp = stack;
	regs->tf_sepc = imgp->entry_addr;
	regs->tf_sstatus |= (SSTATUS_FS_INITIAL); 

#ifdef VFP
	vfp_reset_state(td, pcb);
#endif
}

struct l_riscv_ctx_hdr {
	uint32_t magic;
	uint32_t size;
};

typedef struct {
        struct l_riscv_ctx_hdr fpu_hdr;
        uint64_t regs[32];
        uint64_t fcsr;
        struct l_riscv_ctx_hdr end_hdr;
} __packed kbuf_t;

#define LINUX_END_MAGIC   0x0
#define LINUX_FPU_D_MAGIC 0x51645346
#define LINUX_FPU_D_SIZE  (sizeof(struct l_riscv_ctx_hdr) + (32 * 8) + 8)

int linux_membarrier(struct thread *td, struct linux_membarrier_args *args) {
	/* * Gluster/Go/URCU use this to synchronize memory. 
	* On a single-core or simple RISC-V setup, returning 0 
	* is usually enough to trick the app into thinking 
	* the barrier happened.
	*/
	return (0); 
}


static int linux_restore_fpcontext(struct thread *td, struct l_sigcontext *ctx) {
	struct pcb *pcb = td->td_pcb;
	int i;

	void *ext_ptr = (void *)ctx->sc_extspace;
	kbuf_t *k_buf=(kbuf_t *)ext_ptr;


	if (k_buf->fpu_hdr.magic != LINUX_FPU_D_MAGIC) return(0);

	for (i = 0; i < 32; i++) pcb->pcb_x[i][0]=k_buf->regs[i];

	pcb->pcb_fcsr = k_buf->fcsr;   
	pcb->pcb_fpflags |= PCB_FP_STARTED;

	critical_enter();
	register_t sstatus = intr_disable();
	register_t old_sstatus = csr_read(sstatus);
	csr_set(sstatus, SSTATUS_FS_CLEAN); 
	fpe_restore((struct fpreg *)&pcb->pcb_x); 
    

	td->td_frame->tf_sstatus &= ~SSTATUS_FS_MASK;
	td->td_frame->tf_sstatus |= SSTATUS_FS_INITIAL;

	if (PCPU_GET(fpcurthread) == td) PCPU_SET(fpcurthread, NULL);
	csr_write(sstatus, old_sstatus);
	intr_restore(sstatus);
	critical_exit();
	return(0);
}

// Little union helper
typedef union {
	struct l_rt_sigframe frame;
	uint64_t	     raw[128];
} l_rt_fullsigframe;

static int linux_restore_sigframe(struct thread *td , struct l_rt_sigframe *l_frame){
	struct trapframe *tf=td->td_frame;
	
	tf->tf_ra = l_frame->sf_uc.uc_mcontext.sc_regs[1];
	tf->tf_sp = l_frame->sf_uc.uc_mcontext.sc_regs[2];
	tf->tf_gp = l_frame->sf_uc.uc_mcontext.sc_regs[3];
	tf->tf_tp = l_frame->sf_uc.uc_mcontext.sc_regs[4];

	for (int i = 0; i < 3; i++) tf->tf_t[i]=l_frame->sf_uc.uc_mcontext.sc_regs[5 + i];
	for (int i = 0; i < 2; i++) tf->tf_s[i]=l_frame->sf_uc.uc_mcontext.sc_regs[8 + i];
	for (int i = 0; i < 8; i++) tf->tf_a[i]=l_frame->sf_uc.uc_mcontext.sc_regs[10 + i];
	for (int i = 0; i < 10; i++) tf->tf_s[2+i]=l_frame->sf_uc.uc_mcontext.sc_regs[18 + i];
	for (int i = 0; i < 4; i++) tf->tf_t[3+i]=l_frame->sf_uc.uc_mcontext.sc_regs[28 + i];


	uint64_t safe_sstatus = csr_read(sstatus);
	safe_sstatus &= ~SSTATUS_FS_MASK; 
	safe_sstatus |= (l_frame->sf_uc.uc_mcontext.sstatus & SSTATUS_FS_MASK);
	csr_write(sstatus, safe_sstatus);
	tf->tf_sepc=l_frame->sf_uc.uc_mcontext.sc_pc;
	
	int error=linux_restore_fpcontext(td, &l_frame->sf_uc.uc_mcontext);
	if(error != 0) return(error);

	td->td_sigstk.ss_sp=(void*)l_frame->sf_uc.uc_stack.ss_sp;
	td->td_sigstk.ss_size=l_frame->sf_uc.uc_stack.ss_size;

	return(EJUSTRETURN);
}


/*
 * When the Linux binary is done with a signal we pass trough this
 */

int linux_rt_sigreturn(struct thread *td, struct linux_rt_sigreturn_args *args){
	sigset_t bmask;
	struct trapframe *tf = td->td_frame;
	struct l_rt_sigframe *sf = (struct l_rt_sigframe *)tf->tf_sp;

	l_rt_fullsigframe framer;
	struct l_rt_sigframe *frame=&framer.frame;

	if (copyin(sf, frame, sizeof(struct l_rt_sigframe)+288) != 0) return (EFAULT);

	linux_to_bsd_sigset(&frame->sf_uc.uc_sigmask, &bmask);		// Restore sigmask
	kern_sigprocmask(td, SIG_SETMASK, &bmask, NULL, 0);
	return (linux_restore_sigframe(td, frame));
}

/*
 * Save the contents of the floatingpoint
 */
static int linux_save_fpcontext(struct thread *td, struct l_sigcontext *u_ctx) {

	struct pcb *pcb = td->td_pcb;
	int i;
	kbuf_t *k_buf=(kbuf_t*)&u_ctx->sc_extspace[0];

	k_buf->fpu_hdr.magic = LINUX_END_MAGIC;

	// Sync hardware to PCB 
	if (!(pcb->pcb_fpflags & PCB_FP_STARTED)) return(0);

	critical_enter();
	 fpe_state_save(td); 
	 csr_clear(sstatus, SSTATUS_FS_MASK);
	 csr_set(sstatus, SSTATUS_FS_CLEAN);
	critical_exit();

	for (i = 0; i < 32; i++) k_buf->regs[i] = pcb->pcb_x[i][0]; 

	k_buf->fpu_hdr.magic = LINUX_FPU_D_MAGIC;
	k_buf->fpu_hdr.size = LINUX_FPU_D_SIZE;
	k_buf->fcsr = pcb->pcb_fcsr;

	// Add the terminator
	k_buf->end_hdr.magic = LINUX_END_MAGIC;
	k_buf->end_hdr.size = 0;
	return(0);

}

/*
 * when someone is brave enough to send a Linux process a signal (HUP, HUB, USR1, etc) it will get here
 */
static int linux_create_sigframe(struct thread *td , struct l_rt_sigframe *l_frame){
	struct trapframe *tf=td->td_frame;
	
	l_frame->sf_uc.uc_mcontext.sc_regs[1] = tf->tf_ra;
	l_frame->sf_uc.uc_mcontext.sc_regs[2] = tf->tf_sp;
	l_frame->sf_uc.uc_mcontext.sc_regs[3] = tf->tf_gp;
	l_frame->sf_uc.uc_mcontext.sc_regs[4] = tf->tf_tp;

	for (int i = 0; i < 3; i++) l_frame->sf_uc.uc_mcontext.sc_regs[5 + i] = tf->tf_t[i];
	for (int i = 0; i < 2; i++) l_frame->sf_uc.uc_mcontext.sc_regs[8 + i] = tf->tf_s[i];
	for (int i = 0; i < 8; i++) l_frame->sf_uc.uc_mcontext.sc_regs[10 + i] = tf->tf_a[i];
	for (int i = 0; i < 10; i++) l_frame->sf_uc.uc_mcontext.sc_regs[18 + i] = tf->tf_s[2+i];
	for (int i = 0; i < 4; i++) l_frame->sf_uc.uc_mcontext.sc_regs[28 + i] = tf->tf_t[3+i];

	l_frame->sf_uc.uc_mcontext.sstatus = csr_read(sstatus);
	l_frame->sf_uc.uc_mcontext.sc_pc = tf->tf_sepc;
	
	int error=linux_save_fpcontext(td, &l_frame->sf_uc.uc_mcontext);
	if(error != 0) return(error);

	l_frame->sf_uc.uc_stack.ss_sp = PTROUT(td->td_sigstk.ss_sp);
	l_frame->sf_uc.uc_stack.ss_size = td->td_sigstk.ss_size;

	return(0);
}

static void linux_rt_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask) {
	struct thread *td;
	struct proc *p;
	struct trapframe *tf;
	struct l_rt_sigframe *fp;
	struct sigacts *psp;
	int onstack, sig;

	td = curthread;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);

	sig = ksi->ksi_signo;
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);

	int issiginfo = SIGISMEMBER(psp->ps_siginfo, sig);

	tf = td->td_frame;
	onstack = sigonstack(tf->tf_sp);

	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !onstack && SIGISMEMBER(psp->ps_sigonstack, sig)) {
		fp = (struct l_rt_sigframe *)((uintptr_t)td->td_sigstk.ss_sp + td->td_sigstk.ss_size);
	} else {
		fp = (struct l_rt_sigframe *)tf->tf_sp;
	}

	fp--;
	fp = (struct l_rt_sigframe *)((uintptr_t)fp - 288);
	fp = (struct l_rt_sigframe *)STACKALIGN(fp);

	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(p);

	l_rt_fullsigframe framer;
	struct l_rt_sigframe *frame=&framer.frame;

	int error=linux_create_sigframe(td, frame);
	if(error != 0) goto out; 


	/* Translate signal and siginfo */
	sig = bsd_to_linux_signal(sig);
	siginfo_to_lsiginfo(&ksi->ksi_info, &frame->sf_si, sig);
	bsd_to_linux_sigset(mask, &frame->sf_uc.uc_sigmask);

	frame->sf_uc.uc_stack.ss_flags = (td->td_pflags & TDP_ALTSTACK) != 0 ? (onstack ? LINUX_SS_ONSTACK : 0) : LINUX_SS_DISABLE;

	// Copyout the finished frame to user space
	if (copyout(frame, fp, sizeof(struct l_rt_sigframe)+288) != 0) {
		PROC_LOCK(p);
		sigexit(td, SIGSEGV);
		goto out_locked;
	}

	tf->tf_a[0] = (register_t)sig;	          /* Arg 0: signal number */
	if(issiginfo){
		tf->tf_a[1] = (register_t)&fp->sf_si;     /* Arg 1: siginfo pointer */
		tf->tf_a[2] = (register_t)&fp->sf_uc;     /* Arg 2: ucontext pointer */
	}else{
		tf->tf_a[1] = 0;
		tf->tf_a[2] = 0;
	}    

	tf->tf_sepc = (register_t)catcher;        /* Jump to Linux handler */
	tf->tf_sp = (register_t)fp;               /* Move stack pointer */
	tf->tf_ra = (register_t)__user_rt_sigreturn; 

out:
        /* Restore locks before returning to ast_sig */
	PROC_LOCK(p);
out_locked:
	mtx_lock(&psp->ps_mtx);
}


/*
 * Helper for loading elves.
 */
static int linux64_elf64_fixup(uintptr_t *stack_base, struct image_params *imgp) {
	Elf_Addr *base, *destp;
	int64_t val;
	int error;
    
	base = (Elf_Addr *)*stack_base;
	base--;
	if (suword(base, imgp->args->argc) == -1) return (EFAULT);

	*stack_base = (uintptr_t)base;
	destp = base;
	destp++; /* Skip argc */


	// Skip argv[] pointers until we hit the NULL sentinel
	for (;;) {
		val = fuword64(destp++);
		if (val == -1) return (EFAULT);
		if (val == 0) break;
	}

	// Skip envp[] pointers until we hit the NULL sentinel
	for (;;) {
		val = fuword64(destp++);
		if (val == -1) return (EFAULT);
		if (val == 0) break;
	}

	// Now destp is pointing to the space after the environment. This is the "canonical" home of the Auxiliary Vector.
	if (imgp->auxargs != NULL) {
		error = copyout(imgp->auxargs, (void *)destp, sizeof(Elf64_Auxinfo) * 20);	// TODO: Numbers in code like this are bad
		if (error) return (error);
	}
	return (0);

}

static int linux_elf64_coredump(struct thread *td, struct coredump_writer *cdw, off_t offset, int flags){
	return(elf64_coredump(td, cdw, offset, flags));
}


struct sysentvec elf_linux_sysvec = {
	.sv_size	= LINUX_SYS_MAXSYSCALL,
	.sv_table	= linux_sysent,
	.sv_fixup	= __linuxN(elf64_fixup),
	.sv_sendsig	= linux_rt_sendsig,
	.sv_sigcode	= &_binary_linux_vdso_so_o_start,
	.sv_szsigcode	= &linux_szsigcode,
	.sv_name	= "Linux ELF64",
	.sv_coredump	= linux_elf64_coredump,
	.sv_elf_core_osabi = ELFOSABI_NONE,
	.sv_elf_core_abi_vendor = LINUX_ABI_VENDOR,
	.sv_elf_core_prepare_notes = linux64_prepare_notes,
	.sv_minsigstksz	= LINUX_MINSIGSTKSZ,
	.sv_minuser	= VM_MIN_ADDRESS,
	.sv_maxuser	= VM_MAXUSER_ADDRESS,
	.sv_usrstack	= LINUX_USRSTACK,
	.sv_psstrings	= LINUX_PS_STRINGS,
	.sv_psstringssz	= sizeof(struct ps_strings),
	.sv_stackprot	= VM_PROT_READ | VM_PROT_WRITE,
	.sv_copyout_auxargs = __linuxN(copyout_auxargs),
	.sv_copyout_strings = __linuxN(copyout_strings),
	.sv_setregs	= linux_exec_setregs,
	.sv_fixlimit	= NULL,
	.sv_maxssiz	= NULL,
	.sv_flags	= SV_ABI_LINUX | SV_LP64 | SV_SHP | SV_SIG_DISCIGN | SV_SIG_WAITNDQ | SV_TIMEKEEP,
	.sv_set_syscall_retval = linux_set_syscall_retval,
	.sv_fetch_syscall_args = linux_fetch_syscall_args,
	.sv_syscallnames = linux_syscallnames,
	.sv_shared_page_base = LINUX_SHAREDPAGE,
	.sv_shared_page_len = PAGE_SIZE,
	.sv_schedtail	= linux_schedtail,
	.sv_thread_detach = linux_thread_detach,
	.sv_trap	= NULL,
	.sv_hwcap	= &linux_elf_hwcap,
	.sv_hwcap2	= &linux_elf_hwcap2,
	.sv_hwcap3	= &linux_elf_hwcap3,
	.sv_hwcap4	= &linux_elf_hwcap4,
	.sv_onexec	= linux_on_exec_vmspace,
	.sv_onexit	= linux_on_exit,
	.sv_ontdexit	= linux_thread_dtor,
	.sv_setid_allowed = &linux_setid_allowed_query,
};

static int
linux_on_exec_vmspace(struct proc *p, struct image_params *imgp)
{
	int error;

	error = linux_map_vdso(p, linux_vdso_obj, linux_vdso_base, LINUX_VDSOPAGE_SIZE, imgp);
	if (error == 0) error = linux_on_exec(p, imgp);

	return (error);
}

/*
 * linux_vdso_install() and linux_exec_sysvec_init() must be called
 * after exec_sysvec_init() which is SI_SUB_EXEC (SI_ORDER_ANY).
 */
static void linux_exec_sysvec_init(void *param) {
	l_uintptr_t *ktimekeep_base;
	struct sysentvec *sv;
	ptrdiff_t tkoff;

	sv = param;
	/* Fill timekeep_base */
	exec_sysvec_init(sv);

	tkoff = kern_timekeep_base - linux_vdso_base;
	ktimekeep_base = (l_uintptr_t *)(linux_vdso_mapping + tkoff);
	*ktimekeep_base = sv->sv_shared_page_base + sv->sv_timekeep_offset;



}
SYSINIT(elf_linux_exec_sysvec_init, SI_SUB_EXEC + 1, SI_ORDER_ANY, linux_exec_sysvec_init, &elf_linux_sysvec);

static void linux_vdso_install(const void *param) {
	char *vdso_start = &_binary_linux_vdso_so_o_start;
	char *vdso_end = &_binary_linux_vdso_so_o_end;

	linux_szsigcode = vdso_end - vdso_start;
	MPASS(linux_szsigcode <= LINUX_VDSOPAGE_SIZE);

	linux_vdso_base = LINUX_VDSOPAGE;

	__elfN(linux_vdso_fixup)(vdso_start, linux_vdso_base);

	linux_vdso_obj = __elfN(linux_shared_page_init)
	    (&linux_vdso_mapping, LINUX_VDSOPAGE_SIZE);
	bcopy(vdso_start, linux_vdso_mapping, linux_szsigcode);

	linux_vdso_reloc(linux_vdso_mapping, linux_vdso_base);

}

SYSINIT(elf_linux_vdso_init, SI_SUB_EXEC + 1, SI_ORDER_FIRST,
    linux_vdso_install, NULL);

static void linux_vdso_deinstall(const void *param) {
	__elfN(linux_shared_page_fini)(linux_vdso_obj, linux_vdso_mapping, LINUX_VDSOPAGE_SIZE);
}

SYSUNINIT(elf_linux_vdso_uninit, SI_SUB_EXEC, SI_ORDER_FIRST, linux_vdso_deinstall, NULL);

static void linux_vdso_reloc(char *elf, Elf_Addr offset) {
    Elf_Ehdr *ehdr = (Elf_Ehdr *)elf;
    Elf_Phdr *phdr = (Elf_Phdr *)(elf + ehdr->e_phoff);
    Elf_Dyn *dyn = NULL;
    Elf_Rela *rela = NULL;
    Elf_Size relasz = 0;
    Elf_Addr *where;
    Elf_Addr loadaddr = 0;
    int i;

    // Find the load address (base VADDR) of the ELF.
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            loadaddr = phdr[i].p_vaddr;
            break;
        }
    }

    // Find the Dynamic section
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf_Dyn *)(elf + phdr[i].p_offset);
            break;
        }
    }
    if (dyn == NULL) return;

    // Extract relocation table info. 
    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
        case DT_RELA:
            // Translate VA to buffer pointer: (VA - link_time_base) + buffer_start
            rela = (Elf_Rela *)(elf + (dyn->d_un.d_ptr - loadaddr));
            break;
        case DT_RELASZ:
            relasz = dyn->d_un.d_val;
            break;
        }
    }

    if (rela == NULL || relasz == 0) return;

    // Perform the relocations 
    for (i = 0; i < relasz / sizeof(Elf_Rela); i++) {
        uint64_t type = ELF_R_TYPE(rela[i].r_info);
        
        if (type == R_RISCV_RELATIVE) {
		where = (Elf_Addr *)(elf + (rela[i].r_offset - loadaddr));	// r_offset is also a VA. Translate it to a pointer within our buffer.
		*where = offset + rela[i].r_addend;	            		// The actual magic: store the final runtime address.
        }
    }
}


static Elf_Brandnote linux64_brandnote = {
	.hdr.n_namesz	= sizeof(GNU_ABI_VENDOR),
	.hdr.n_descsz	= 16,
	.hdr.n_type	= 1,
	.vendor		= GNU_ABI_VENDOR,
	.flags		= BN_TRANSLATE_OSREL,
	.trans_osrel	= linux_trans_osrel
};

static Elf64_Brandinfo linux_glibc2brand = {
	.brand		= ELFOSABI_LINUX,
	.machine	= EM_RISCV,
	.compat_3_brand	= "Linux",
	.interp_path	= "/lib/ld-linux-riscv64-lp64d.so.1",
	.sysvec		= &elf_linux_sysvec,
	.interp_newpath	= NULL,
	.brand_note	= &linux64_brandnote,
	.flags		= BI_CAN_EXEC_DYN | BI_BRAND_NOTE | LINUX_BI_FUTEX_REQUEUE
};

Elf64_Brandinfo *linux_brandlist[] = {
	&linux_glibc2brand,
	NULL
};

static int
linux64_elf_modevent(module_t mod, int type, void *data)
{
	Elf64_Brandinfo **brandinfo;
	struct linux_ioctl_handler**lihp;
	int error;

	error = 0;
	switch(type) {
	case MOD_LOAD:
		for (brandinfo = &linux_brandlist[0]; *brandinfo != NULL; ++brandinfo)
			if (elf64_insert_brand_entry(*brandinfo) < 0)
				error = EINVAL;
		if (error == 0) {
			SET_FOREACH(lihp, linux_ioctl_handler_set) linux_ioctl_register_handler(*lihp);

			stclohz = (stathz ? stathz : hz);
			if (bootverbose) printf("Linux RiscV64 ELF exec handler installed\n");

			uint32_t hwcap = 0;
			hwcap |= (1 << ('I' - 'A'));	// TODO fix me, make me dynamic
			hwcap |= (1 << ('M' - 'A'));
			hwcap |= (1 << ('A' - 'A'));
			hwcap |= (1 << ('F' - 'A'));
			hwcap |= (1 << ('D' - 'A'));
			hwcap |= (1 << ('C' - 'A'));
			linux_elf_hwcap=hwcap;
		}
		break;
	case MOD_UNLOAD:
		for (brandinfo = &linux_brandlist[0]; *brandinfo != NULL;
		    ++brandinfo)
			if (elf64_brand_inuse(*brandinfo))
				error = EBUSY;
		if (error == 0) {
			for (brandinfo = &linux_brandlist[0];
			    *brandinfo != NULL; ++brandinfo)
				if (elf64_remove_brand_entry(*brandinfo) < 0)
					error = EINVAL;
		}
		if (error == 0) {
			SET_FOREACH(lihp, linux_ioctl_handler_set)
				linux_ioctl_unregister_handler(*lihp);
			if (bootverbose)
				printf("Linux RiscV64 ELF exec handler removed\n");
		} else
			printf("Could not deinstall Linux RiscV64 ELF interpreter entry\n");
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (error);
}

static moduledata_t linux64_elf_mod = {
	"linux64elf",
	linux64_elf_modevent,
	0
};

DECLARE_MODULE_TIED(linux64elf, linux64_elf_mod, SI_SUB_EXEC, SI_ORDER_ANY);
MODULE_DEPEND(linux64elf, linux_common, 1, 1, 1);
FEATURE(linux64, "RiscV Linux 64bit support");
