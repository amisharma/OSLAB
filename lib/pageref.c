#include <inc/lib.h>

int
pageref(void *v)
{
	pte_t pte;
	cprintf("entering pageref \n");
	if (!(uvpd[VPD(v)] & PTE_P))
		return 0;
	pte = uvpt[PGNUM(v)];
	if (!(pte & PTE_P))
		return 0;
	cprintf("exiting pageref \n");
	return pages[PPN(pte)].pp_ref;
}
