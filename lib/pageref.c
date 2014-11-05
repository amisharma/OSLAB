#include <inc/lib.h>

int
pageref(void *v)
{
	pte_t pte;
//	cprintf("entering pageref page=%08x pages =%p\n",v, pages);
	if (!(uvpd[VPD(v)] & PTE_P))
		return 0;
//	cprintf("entering pageref uvpd[VPD(v)]=%08x \n",uvpd[VPD(v)]);
	pte = uvpt[PGNUM(v)];
	if (!(pte & PTE_P))
		return 0;
//	return 0;
	int x;
//	cprintf("exiting pageref PPN(pte)=%08x pte=%08x %p pages %p\n",PPN(pte),pte, &pages[PPN(pte)], pages);
	x= pages[PPN(pte)].pp_ref;
//	cprintf("exiting pageref \n");
	return x;
}
