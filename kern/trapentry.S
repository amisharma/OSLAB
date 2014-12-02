/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>
#include <kern/macro.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushq $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushq $0;							\
	pushq $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
   Find the PUSHA,POPA macros in kern/macro.h. Since amd64 doesn't support
   pusha,popa so you will find these macros handy.
 */

TRAPHANDLER(xt_dblflt, T_DBLFLT)	
TRAPHANDLER(xt_tss, T_TSS)	
TRAPHANDLER(xt_segnp, T_SEGNP)	
TRAPHANDLER(xt_stack, T_STACK)	
TRAPHANDLER(xt_gpflt, T_GPFLT)	
TRAPHANDLER(xt_pgflt, T_PGFLT)	
TRAPHANDLER_NOEC(xt_syscall, T_SYSCALL)
TRAPHANDLER_NOEC(xt_divide, T_DIVIDE)	
TRAPHANDLER_NOEC(xt_debug, T_DEBUG)	
TRAPHANDLER_NOEC(xt_nmi, T_NMI)   
TRAPHANDLER_NOEC(xt_brkpt, T_BRKPT)   
TRAPHANDLER_NOEC(xt_oflow, T_OFLOW) 
TRAPHANDLER_NOEC(xt_bound, T_BOUND) 
TRAPHANDLER_NOEC(xt_illop, T_ILLOP) 
TRAPHANDLER_NOEC(xt_device, T_DEVICE) 
TRAPHANDLER_NOEC(xt_fperr, T_FPERR)
TRAPHANDLER_NOEC(xt_align, T_ALIGN)
TRAPHANDLER_NOEC(xt_mchk, T_MCHK)
TRAPHANDLER_NOEC(xt_simderr, T_SIMDERR)

TRAPHANDLER_NOEC(xi_timer_0, IRQ_OFFSET)
TRAPHANDLER_NOEC(xi_timer_1, IRQ_OFFSET+1)
TRAPHANDLER_NOEC(xi_timer_2, IRQ_OFFSET+2)
TRAPHANDLER_NOEC(xi_timer_3, IRQ_OFFSET+3)
TRAPHANDLER_NOEC(xi_timer_4, IRQ_OFFSET+4)
TRAPHANDLER_NOEC(xi_timer_5, IRQ_OFFSET+5)
TRAPHANDLER_NOEC(xi_timer_6, IRQ_OFFSET+6)
TRAPHANDLER_NOEC(xi_timer_7, IRQ_OFFSET+7)
TRAPHANDLER_NOEC(xi_timer_8, IRQ_OFFSET+8)
TRAPHANDLER_NOEC(xi_timer_9, IRQ_OFFSET+9)
TRAPHANDLER_NOEC(xi_timer_10, IRQ_OFFSET+10)
TRAPHANDLER_NOEC(xi_timer_11, IRQ_OFFSET+11)
TRAPHANDLER_NOEC(xi_timer_12, IRQ_OFFSET+12)
TRAPHANDLER_NOEC(xi_timer_13, IRQ_OFFSET+13)
TRAPHANDLER_NOEC(xi_timer_14, IRQ_OFFSET+14)
TRAPHANDLER_NOEC(xi_timer_15, IRQ_OFFSET+15)


/*
 * Lab 3: Your code here for _alltraps
 *
 * Hint: Be sure to review the x64 calling convention from lab1
 *       for how to pass a pointer to the trapframe.
 */
_alltraps:
        movw %ds, %r15;
        pushq %r15;
        movw %es, %r15;
        pushq %r15;
        PUSHA;
        movw $GD_KD, %r15
        movw %r15, %ds
        movw %r15, %es
        movq %rsp,%rdi
        call trap;
	POPA_
	popq %r15
	movw %r15, %es
	popq %r15
	movw %r15, %ds
	iret
