// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;
	int perm=PTE_P|PTE_U|PTE_W;
	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if(!(err&FEC_WR))
		panic("page fault not on write access %08x %e",(uint64_t)addr,err);
	else if	(!(uvpt[VPN(addr)]&PTE_COW))
		panic("page fault not on copy on write ");
	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.
	r=sys_page_alloc(0,(void *)PFTEMP,perm);
	if(r<0)
		panic("error=%e in pgfault during page alloc\n",r); 
	memmove(PFTEMP,(void *)ROUNDDOWN(addr,PGSIZE),PGSIZE);
	r=sys_page_map(0,(void *)PFTEMP,0,(void *)ROUNDDOWN(addr,PGSIZE),perm);
	if(r<0)
                panic("error=%e in pgfault during page map\n",r);
	//panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
//	cprintf("entering duppage \n");	
uintptr_t addr;
	addr=(uintptr_t)(pn<<PGSHIFT);
	pte_t entry=uvpt[pn];
	int cow_perm=entry&PTE_SYSCALL;
	pte_t pte=uvpt[pn];
	if((entry&PTE_SYSCALL)&PTE_SHARE)
	{
		r=sys_page_map(0,(void*)addr,envid,(void *)addr,(entry&PTE_SYSCALL)|PTE_SHARE);
		if(r<0)
			panic("error in duppage while sys_page_map share");
		return 0;
	}
	if(!((pte&PTE_W)||( pte & PTE_COW)))
	{
		r=sys_page_map(0,(void *)addr,envid,(void *)addr,PTE_P|PTE_U);
		if(r<0)
			panic("error in duppage while sys_page_map");
		return 0;
	}
	else 
	{
		r=sys_page_map(0,(void *)addr,envid,(void *)addr,PTE_P|PTE_U|PTE_COW);
		if(r<0)
                        panic("error in duppage while sys_page_map 2");
	

	r=sys_page_map(0,(void *)addr,0,(void *)addr,PTE_P|PTE_U|PTE_COW);
	if(r<0)
                        panic("error in duppage while sys_page_map 3");
	
//	panic("duppage not implemented");
	return 0;
	}
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	envid_t envid;
	set_pgfault_handler(pgfault);
	envid=sys_exofork();
	if(envid<0)
        {
                panic("error in fork while sys_exofork");
		return envid;
	}
	else if(envid==0)
	{
		thisenv=&envs[ENVX(sys_getenvid())];
		return envid;
	}
	uint64_t pn,x;
	for(pn=PPN(UTEXT);pn<PPN(UXSTACKTOP-PGSIZE);)
	{
		if(!((uvpml4e[VPML4E(pn)]&PTE_P)&&(uvpde[pn>>18]&PTE_P)&&(uvpd[pn>>9]&PTE_P)))
		{
			pn+=NPTENTRIES;
			continue;
		}
		for(x=pn+NPTENTRIES;pn<x;pn++)
		{
			if((uvpt[pn]&PTE_P)!=PTE_P)
				continue;
			if(pn==PPN(UXSTACKTOP-1))
				continue;
			duppage(envid,pn);
		}
	}
	int r;
	r=sys_page_alloc(envid,(void *)(UXSTACKTOP-PGSIZE),PTE_P|PTE_U|PTE_W);
	if(r<0)
		panic("error while page alloc in fork");
	extern void _pgfault_upcall(void);
	r=sys_env_set_pgfault_upcall(envid,_pgfault_upcall);
	if(r<0)
		panic("error during setting up pgfault upcall in fork");
	r=sys_env_set_status(envid,ENV_RUNNABLE);
	if(r<0)
                panic("error during env set status in fork");
	return envid;
	panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
