#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/reg.h>

#include <vm/vm_param.h>

#include <riscv/linux/linux.h>
#include <riscv/linux/linux_proto.h>
#include <compat/linux/linux_fork.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_util.h>

