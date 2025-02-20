/* Predecrypt all pages ahead of time so that they are decrypted by the time the proccess accesses it */

#include "../pmo.h"

/* This is performed when the pmo attach argument is 'p' */
void pmo_predecrypt_all_pages(struct vpma_area_struct *vpma, size_t size_in_pages)
{
	int i;
	printk(KERN_INFO "Performing predecryption on pages 0-%lX\n", 
			size_in_pages);

	for (i = 0; i < size_in_pages; i++) {
		if (PMO_DRAM_IS_ENABLED() && vpma->working_data[i].phys_addr == 0)
			pmo_init_dram_working_data(vpma, i);
		pmo_handle_page(vpma, i * PAGE_SIZE); 
	}
	return;
}
