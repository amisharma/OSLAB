/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>
#include <kern/time.h>
#include<kern/e1000.h>
// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.

	// LAB 3: Your code here.
		user_mem_assert(curenv, (const void*)s, len, PTE_U);

	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;
	cprintf("envid for sys_env_destroy[%08x],env[%08x]\n",envid,curenv->env_id);
	if ((r = envid2env(envid, &e, 1)) < 0)
{
		cprintf("envid for condition 1 sys_env_destroy%d\n",envid);
		return r;}
	if (e == curenv)
		cprintf("[%08x] exiting gracefully\n", curenv->env_id);
	else
		cprintf("[%08x] destroying %08x\n", curenv->env_id, e->env_id);
	 //cprintf("entering env_destroy[%08x]\n",envid);
	env_destroy(e);
	//cprintf("exiting sys_env_destroy[%08x]\n",envid);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
//	cprintf("enterting sys_yield\n");
	sched_yield();
//	cprintf("exiting sys_yield\n");
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.

	// LAB 4: Your code here.
	struct Env * child,*parent;
	int r;
	r=env_alloc(&child,curenv->env_id);
	//if(r==-E_NO_FREE_ENV)
	//	return -E_NO_FREE_ENV;
	//cprintf("entering sys_exofork env=%x,child=%x\n",curenv->env_id,child->env_id);
	if(r<0)
	{
		if(r==-E_NO_FREE_ENV)
		{
			cprintf("error1=%e\n",r);
                	return -E_NO_FREE_ENV;
		}
		else
		{
			cprintf("error1=%r\n",r); 
			return -E_NO_MEM;
		}
	}
	child->env_status=ENV_NOT_RUNNABLE;
	child->env_tf=curenv->env_tf;
//	memcpy(&child->env_tf, &curenv->env_tf, sizeof(curenv->env_tf));
	child->env_tf.tf_regs.reg_rax=0;
//	child->env_parent_id=curenv->env_id;
	return child->env_id;
	panic("sys_exofork not implemented");
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
static int
sys_env_set_status(envid_t envid, int status)
{
	// Hint: Use the 'envid2env' function from kern/env.c to translate an
	// envid to a struct Env.
	// You should set envid2env's third argument to 1, which will
	// check whether the current environment has permission to set
	// envid's status.

	// LAB 4: Your code here.
	int r;
	struct Env * new_env;
	r=envid2env(envid,&new_env,1);
	if(r<0)
		{
			cprintf("error in sys_env_set=%e for env_id=%x\n",status,envid);
			return r;
		}
	else if((status!=ENV_RUNNABLE)&&(status!=ENV_NOT_RUNNABLE))
		return -E_INVAL;
	new_env->env_status=status;
	return 0;
	panic("sys_env_set_status not implemented");
}
//// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3) with interrupts enabled.
//
// Returns 0 on success, < 0 on error.  Errors are:
//      -E_BAD_ENV if environment envid doesn't currently exist,
//              or the caller doesn't have permission to change envid.
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{	// LAB 5: Your code here.
        // Remember to check whether the user has supplied us with a good
        // address!
	struct Env *e;
	int r = envid2env(envid,&e,1);
	if(r<0)
	{
		cprintf("error while converting envid to env\n");
		return r;
	}
	//user_mem_assert(e,tf,sizeof(struct Trapframe),PTE_U);
	tf->tf_cs|=0x3;
	tf->tf_eflags|=FL_IF;
	e->env_tf=*tf;	
	return 0;
	panic("sys_env_set_trapframe not implemented");
}
// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
	struct Env *new_env;
	int status;
	status=envid2env(envid,&new_env,1);
//	cprintf("set upcall for envid=%x\n",envid);
	if(status==-E_BAD_ENV)
	{
		cprintf("bad env in sys_env_set_pgfault error=%e envid=%x\n",status,envid);
		return -E_BAD_ENV;
	}
//	cprintf("page upcall\n");
	new_env->env_pgfault_upcall=func;
	return 0;

	panic("sys_env_set_pgfault_upcall not implemented");
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!

	// LAB 4: Your code here.
	struct PageInfo * newpage,*test_page;
	struct Env * new_env;
	int r1,r2;
	pte_t *pte_test_page;
//	cprintf("entering page alloc\n");
	r1=envid2env(envid,&new_env,1);
	if(!(perm&(PTE_U|PTE_P)))
	{
                cprintf("error=-E_INVAL, perm not proper in sys_page_alloc for envid=%d\n",envid);
                        return -E_INVAL;
        }
	if(((uint64_t)va>=UTOP)||((uint64_t)va%PGSIZE))
	{
                cprintf("error=-E_INVAL, va not proper in sys_page_alloc for envid=%d\n",envid);
                	return -E_INVAL;
	}
	if(r1<0)
	{
		cprintf("error=%e in sys_page_alloc for envid=%d\n",r1,envid);
		return r1;
	}
//	cprintf("checking page alloc\n");
	newpage=page_alloc(ALLOC_ZERO);
if(r1==0)
{	if(!newpage)
	{
                cprintf("error=-E_NO_MEM in sys_page_alloc for envid=%d\n",envid);
                return -E_NO_MEM;
        }
	page_remove(new_env->env_pml4e,va);
	r2=page_insert(new_env->env_pml4e,newpage,va,perm);
//	cprintf("page alloc 3 va=%08x, pml4e=%08x\n",va,new_env->env_pml4e);
	if(r2<0)
	{
                cprintf("error=%e while page insert in sys_page_alloc for envid=%d\n",r2,envid);
                page_free(newpage);
		return r2;
        }
	return 0;
}	panic("sys_page_alloc not implemented");
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.
	struct Env *src_env,*dst_env;
	int r1,r2;
	// LAB 4: Your code here.
	if(!(perm&(PTE_P|PTE_U)))
        {       
                cprintf("error=-E_INVAL, perm not proper in sys_page_alloc for envid=%d\n",srcenvid);
                        return -E_INVAL;
        }
	if(((uint64_t)srcva>=UTOP)||((uint64_t)srcva%PGSIZE))
        {
                cprintf("error=-E_INVAL, srcva not proper in sys_page_alloc for envid=%d\n",srcenvid);
                        return -E_INVAL;
        }
	if(((uint64_t)dstva>=UTOP)||((uint64_t)dstva%PGSIZE))
        {
                cprintf("error=-E_INVAL, dstva not proper in sys_page_alloc for envid=%d\n",dstenvid);
                        return -E_INVAL;
        }
	r1=envid2env(srcenvid,&src_env,1);
	if(r1<0)
        {
                cprintf("error=%e in sys_page_alloc for srcenvid=%d\n",r1,srcenvid);
                return r1;
        }
	 r1=envid2env(dstenvid,&dst_env,1);
        if(r1<0)
        {
                cprintf("error=%e in sys_page_alloc for dstenvid=%d\n",r1,dstenvid);
                return r1;
        }
	/*r1=user_mem_check(src_env,srcva,PGSIZE,perm);
	if(r1<0)
        {
                cprintf("error=srcva not mapped to srcenvid  in sys_page_alloc for srcenvid=%d\n",srcenvid);
                return -E_INVAL;
        }
	if(perm&PTE_W)
	{
		r2=user_mem_check(src_env,srcva,PGSIZE,perm|PTE_W);
		if(r2<0)
		{
			cprintf("error=srcenv doesn't have write perm on srva  to  in sys_page_alloc for srcenvid=%d\n",srcenvid);
                return -E_INVAL;
		}
	}*/
	
	pte_t *pte_test_page;
	struct PageInfo *newpage,*src_page,*test_page;
	src_page=page_lookup(src_env->env_pml4e,srcva,&pte_test_page);
	if(src_page==NULL)
	{
		cprintf("error=no page mapped at srcva in sys_page_alloc for srcenvid=%d\n",srcenvid);
                return -E_INVAL;
	}
	if(((perm & PTE_W)) && (!(*(pte_test_page) & PTE_W)))
	{
		cprintf("\nNo write permissions\n");
		return -E_INVAL;
	}
        r2=page_insert(dst_env->env_pml4e,src_page,dstva,perm);
        if(r2<0)
        {
                cprintf("error=%e while page insert in sys_page_alloc for envid=%d\n",r2,dstenvid);
                return r2;
        }
	return 0;	
	panic("sys_page_map not implemented");
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().

	// LAB 4: Your code here.
	int r1;
	struct Env *new_env;
	r1=envid2env(envid,&new_env,1);
        if(((uint64_t)va>=UTOP)||((uint64_t)va%PGSIZE))
        {
                cprintf("error=-E_INVAL, va not proper in sys_page_alloc for envid=%d\n",envid);
                        return -E_INVAL;
        }
        if(r1<0)
        {
                cprintf("error=%e in sys_page_alloc for envid=%d\n",r1,envid);
                return r1;
        }
	page_remove(new_env->env_pml4e,va);
	return 0;
	panic("sys_page_unmap not implemented");
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	// LAB 4: Your code here.
	struct Env* e;
        int r;
        struct PageInfo *pp;
        pte_t *pte;
//	cprintf("entering sys_ipc_try_send\n");
        r = envid2env(envid, &e, 0);
        if(r<0)
                return -E_BAD_ENV;
//	cprintf("entering 2 sys_ipc_try_send\n");
        if(e->env_ipc_recving==0)
                return -E_IPC_NOT_RECV;
//	cprintf("entering 3 sys_ipc_try_send\n");
        if((uint64_t )srcva < UTOP)
        {
                if((uint64_t)srcva % PGSIZE != 0)
                        return -E_INVAL;
		if((uint64_t)srcva>=UTOP)
			return -E_INVAL;
                if (!(perm & (PTE_U|PTE_P)))
                return -E_INVAL;

                pp = page_lookup(curenv->env_pml4e, srcva, &pte);
                if (pp == NULL)
                        return -E_INVAL;

                if( (perm & PTE_W) && !(*pte & PTE_W) )
                        return -E_INVAL;
		if(((uint64_t)e->env_ipc_dstva >= UTOP) || (((uint64_t)e->env_ipc_dstva % PGSIZE) != 0))
		return -E_INVAL;
                if ((uint64_t )e->env_ipc_dstva < UTOP)
                {
                        r = page_insert(e->env_pml4e, pp, e->env_ipc_dstva, perm);
                	//r=sys_page_map(curenv->env_id,srcva,e->env_id,e->env_ipc_dstva,perm);        
//		cprintf("entering 4 sys_ipc_try_send\n");
		if(r<0)
                        {
                                page_free(pp);
                                return r;
                        }
                        e->env_ipc_perm = perm;
                }
        }
        e->env_ipc_recving = 0;
        e->env_ipc_from = curenv->env_id;
        e->env_ipc_value = value;
        e->env_status = ENV_RUNNABLE;
//	cprintf("entering 5 sys_ipc_try_send val=%08x\n",value);
	return 0;
	panic("sys_ipc_try_send not implemented");
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	// LAB 4: Your code here.
	//cprintf("entering sys_ipc_recv\n");
	if((dstva>(void *)UTOP))
		return -E_INVAL;
	if((dstva<(void *)UTOP))
	{
		if((((uint64_t)dstva)%PGSIZE)!=0)
		{cprintf("sys_ipc_recv error dstva= %x,utop=%x\n",dstva,UTOP);
		return -E_INVAL;}
//		curenv->env_ipc_dstva = dstva;
//		curenv->env_ipc_perm = 0;
	}
//	cprintf("entering 2 sys_ipc_recv dstva=%08x\n",dstva);
	curenv->env_ipc_recving=1;
	curenv->env_ipc_dstva=dstva;
	curenv->env_status=ENV_NOT_RUNNABLE;
	curenv->env_tf.tf_regs.reg_rax=0;
//	curenv->env_ipc_perm=0;
//	curenv->env_ipc_from=0;
	sched_yield();
//	panic("sys_ipc_recv not implemented");
	return 0;
}


// Return the current time.
static int
sys_time_msec(void)
{
	// LAB 6: Your code here.
	return time_msec();
	panic("sys_time_msec not implemented");
}

static int sys_transmit(const char *a1,size_t a2)
{
	if((uint64_t)a1>=UTOP)
		return -E_INVAL;
	return transmit(a1,a2);	
}


// Dispatches to the correct kernel function, passing the arguments.
int64_t
syscall(uint64_t syscallno, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.

//	panic("syscall not implemented");
//	 cprintf("syscallno=%d\n",syscallno);
	switch (syscallno) {
//		cprintf("syscallno=%d\n",syscallno);
	case SYS_cputs:
		sys_cputs((char *)a1,a2);
		return 0;
	case SYS_transmit:
		return sys_transmit((const char*)a1,(size_t)a2);
	case SYS_cgetc:
		return sys_cgetc();
	case SYS_getenvid:
		return sys_getenvid();
	case SYS_env_destroy:
//		cprintf("calling sys_env_destroy\n");
		return sys_env_destroy(a1);
	case SYS_yield:
		sys_yield();
		return 0; 
	case SYS_exofork:
                return sys_exofork();
	case SYS_page_alloc:
                return sys_page_alloc(a1,(void *)a2,a3);
	case SYS_env_set_status:
                return sys_env_set_status(a1,a2);
	case SYS_page_unmap:
                return sys_page_unmap(a1,(void *)a2);
	case SYS_page_map:
                return sys_page_map(a1,(void *)a2,a3,(void *)a4,a5);
	case SYS_env_set_pgfault_upcall:
//		cprintf("syscall pgfault\n");
		return sys_env_set_pgfault_upcall(a1,(void *)a2);
	case SYS_ipc_try_send:
		return sys_ipc_try_send(a1,a2,(void *)a3,a4);
	case SYS_ipc_recv:
		return sys_ipc_recv((void *)a1);		
	case SYS_env_set_trapframe:
		return sys_env_set_trapframe(a1,(struct Trapframe *)a2);
	case SYS_time_msec:
		return sys_time_msec();
	default:
		cprintf("\nSYS_error%d",syscallno);
		return -E_NO_SYS;
	}
}

