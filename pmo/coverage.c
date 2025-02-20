/*************************************************************************** 
 * Copyright (C) 2023 Derrick Greenspan and the University of Central	   *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA.               *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY   *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or       *
 * FITNESS FOR A PARTICULAR PURPOSE.                                       *
 ***************************************************************************
 * PMO encryption coverage statistics and helper functions.		   *
 ***************************************************************************/

#include "pmo.h"

extern long long int towards_inert_count,
       set_access_count;
void dump_coverage_statistics(struct vpma_area_struct *vpma)
{
	struct pmo_entry *pmo = vpma->pmo_ptr;
	size_t mispredict = atomic_read(&vpma->mispredict),
	       exposed_pages = atomic_read(&vpma->exposed_pages),
	       total_predictions = atomic_read(&vpma->total_predictions),
	       size_in_pages = pmo->size_in_pages; 

	printk(KERN_INFO "======================================\n");
	printk(KERN_INFO "For PMO %s... and process %s\n", pmo->name, current->comm);
	printk(KERN_INFO "======================================\n");

	printk(KERN_INFO "Number of improperly predicted inert pages accessed: %lld\n",
			mispredict);

	printk(KERN_INFO "Total number of predictions generated: %lld\n",
			total_predictions);


	printk(KERN_INFO "Number of extant pages at detach: %lld\n",
			exposed_pages);

	printk(KERN_INFO "Total number of pages within the PMO: %lld\n", 
			size_in_pages);

	/*
	printk(KERN_INFO "Total Inerts... %lld\n Total Accesses...%lld\n", towards_inert_count, set_access_count);
	*/
	return;

}

void pmo_init_tracking(struct vpma_area_struct *vpma)
{
	atomic_set(&vpma->mispredict, 0);
	atomic_set(&vpma->exposed_pages, 0);
	atomic_set(&vpma->total_predictions, 0);
	return;
}

void pmo_inc_mispredict(struct vpma_area_struct *vpma)
{
	atomic_inc(&vpma->mispredict);
	return;
}

void pmo_inc_exposed_pages(struct vpma_area_struct *vpma)
{
	atomic_inc(&vpma->exposed_pages);
	return;
}

void pmo_inc_total_predictions(struct vpma_area_struct *vpma)
{
	atomic_inc(&vpma->total_predictions);
	return;
}

