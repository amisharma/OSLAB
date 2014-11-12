#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H
#include<kern/pci.h>
# define VENDOR_E1000 0x8086
# define DEV_E1000 0x100e
int attachE1000(struct pci_func *pcif);
#endif	// JOS_KERN_E1000_H
