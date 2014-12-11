#include <kern/e1000.h>
#include<inc/stdio.h>
#include<inc/string.h>
#include<inc/error.h>
volatile uint32_t *loc_mmio;
struct trans_desc tx_que[MAXTX_DESC]__attribute__ ((aligned (16)));
struct trans_pkt pkt_que[MAXTX_DESC];
struct rcv_desc rx_que[MAXTX_DESC]__attribute__ ((aligned (16)));
struct rcv_pkt rpkt_que[MAXTX_DESC];
int attachE1000(struct pci_func *pcif)
{
	int i;
	pci_func_enable(pcif);
	loc_mmio=(uint32_t *)mmio_map_region((physaddr_t)pcif->reg_base[0] ,(size_t)pcif->reg_size[0]); 
	memset(tx_que, 0x0, sizeof(struct trans_desc) * MAXTX_DESC);
	memset(pkt_que, 0x0, sizeof(struct trans_pkt) * MAXTX_DESC);
	
	for( i=0; i<MAXTX_DESC; i++)
	{
		tx_que[i].addr = PADDR(pkt_que[i].arr);
		tx_que[i].status |= E1000_TXD_STAT_DD;
	}
	       memset(rx_que, 0x0, sizeof(struct rcv_desc) * MAXTX_DESC);
        memset(rpkt_que, 0x0, sizeof(struct rcv_pkt) * MAXTX_DESC);

        for( i=0; i<MAXTX_DESC; i++)
        {
                rx_que[i].addr = PADDR(rpkt_que[i].arr);
                //tx_que[i].status |= E1000_TXD_STAT_DD;
        }

	loc_mmio[E1000_RAL] = 0x52;
        loc_mmio[E1000_RAL] |= (0x54) << 8;
        loc_mmio[E1000_RAL] |= (0x00) << 16;
        loc_mmio[E1000_RAL] |= (0x12) << 24;
        loc_mmio[E1000_RAH] |= (0x34);
        loc_mmio[E1000_RAH] |= (0x56) << 8;
        loc_mmio[E1000_RAH] |= 0x80000000;

        //initialization of various registers
        loc_mmio[E1000_TDBAH] = 0x0;
        loc_mmio[E1000_TDBAL] = PADDR(tx_que);
        loc_mmio[E1000_TDLEN] = sizeof(struct trans_desc) * MAXTX_DESC;
        loc_mmio[E1000_TDH] = 0x0;
        loc_mmio[E1000_TDT] = 0x0;


        loc_mmio[E1000_RDBAH] = 0x0;
        loc_mmio[E1000_RDBAL] = PADDR(rx_que);
        loc_mmio[E1000_RDLEN] = sizeof(struct rcv_desc) * MAXTX_DESC;
        loc_mmio[E1000_RDH] = 0x0;
        loc_mmio[E1000_RDT] = 0x0;


        loc_mmio[E1000_TCTL] |=  E1000_TCTL_EN|E1000_TCTL_PSP|(E1000_TCTL_CT & (0x10 << 4))|(E1000_TCTL_COLD & (0x40 << 12));


        loc_mmio[E1000_RCTL] |= E1000_RCTL_EN;
        loc_mmio[E1000_RCTL] &= ~E1000_RCTL_LPE;
        loc_mmio[E1000_RCTL] &= ~(E1000_RCTL_LBM_MAC | E1000_RCTL_LBM_SLP |E1000_RCTL_LBM_TCVR);
        loc_mmio[E1000_RCTL] &= ~(E1000_RCTL_RDMTS_QUAT | E1000_RCTL_RDMTS_EIGTH);
        loc_mmio[E1000_RCTL] &= ~(E1000_RCTL_MO_3);
        loc_mmio[E1000_RCTL] &= ~E1000_RCTL_BAM;
        loc_mmio[E1000_RCTL] &= ~(E1000_RCTL_BSEX);
        loc_mmio[E1000_RCTL] &= ~(E1000_RCTL_SZ_256);

        loc_mmio[E1000_RCTL] |= E1000_RCTL_SECRC;

 //       loc_mmio[E1000_TIPG] = 0x0;
   //     loc_mmio[E1000_TIPG] |= 0xA;
     //   loc_mmio[E1000_TIPG] |= (0x6) << 20;
       // loc_mmio[E1000_TIPG] |= (0x4) << 10;
	
	return 0;
}
int transmit(const char * addr, size_t bytes)
{
	if(bytes >PKT_SIZE)
		return -E_LONG_PACKET;
	uint32_t tdt=loc_mmio[E1000_TDT];
	if(tx_que[tdt].status & E1000_TXD_STAT_DD)
	{
		memmove(pkt_que[tdt].arr,addr,bytes);
		tx_que[tdt].status&=~E1000_TXD_STAT_DD;
		tx_que[tdt].cmd|=E1000_TXD_CMD_EOP;
		tx_que[tdt].length=bytes;
		tx_que[tdt].cmd|=E1000_TXD_CMD_RS;
		tdt++;
		loc_mmio[E1000_TDT]=tdt%MAXTX_DESC;
		return 0;
	}
	else
		return -E_QUEUE_FULL;

}
int receive(const char *addr)
{
	uint32_t rdt=loc_mmio[E1000_RDT];
	if((rx_que[rdt].status&E1000_RXD_STAT_DD)&&(rx_que[rdt].status&E1000_RXD_STAT_EOP))
	{
		int bytes=rx_que[rdt].length;
		memmove((void *)addr,(void *)rpkt_que[rdt].arr,bytes);
		rx_que[rdt].status&=~E1000_RXD_STAT_DD;
		rx_que[rdt].status&=~E1000_RXD_STAT_EOP;
		rdt++;
		loc_mmio[E1000_RDT]=rdt%MAXTX_DESC;
		return bytes;
	}
	else
		return -1;
}	
