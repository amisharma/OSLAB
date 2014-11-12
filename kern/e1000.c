#include <kern/e1000.h>

int attachE1000(struct pci_func *pcif)
{
	pci_func_enable(pcif);
	return 0;
}
// LAB 6: Your driver code here
