/*************************************************************************** 
 * Copyright (C) 2021-2023 Derrick Greenspan and the University of Central *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA.               *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY   *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or       *
 * FITNESS FOR A PARTICULAR PURPOSE.                                       *
 ***************************************************************************
 * PMO creation and helper functions. 					   *
 ***************************************************************************/

#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/skcipher.h>
#include "pmo.h"

void do_create(char *name, __u64 size, char *key)
{
	void *pmo_mapping;
        struct pmo_entry *pmo;
	char local_key[64];

	struct mm_struct *mm = current->mm;
	loff_t pos;
        __u64 address, hash, 
	      pmolist_start = metadata_start + sizeof(union pmo_header) + sizeof(__u64);

	pmo_stats_start_create_time(&mm->pmo_stats);
	trace_printk("[Create_start: %lld]", mm->pmo_stats.createtime_start);
	memset(local_key, 0, 64);
	strncpy(local_key, key, 64);

	hash = djb2_hash(name) % MAX_NODES;

       	address = pmolist_start + sizeof(struct pmo_entry) * hash;
	pos = address;

        pmo_mapping = pmo_memremap(name); //address, sizeof(struct pmo_entry), MEMREMAP_WB);

        pmo = (struct pmo_entry *)pmo_mapping;

        strcpy(pmo->name, name);

	pmo->size_in_pages = PAGE_ALIGN(size)/PAGE_SIZE;
        pmo->pm_primary = get_available_pmo_location(size);
	/* NOTE: If we're using allocation, then the bitfield starts at the end
	 * of the primary. Effectively, we're saying that each PMO is size + 
	 * size/64 large for its primary. */

	pmo->state = 1;

	pmo_test_and_lock(6, pmo);

	/* Assign random 16 bytes to pmo iv */
	get_random_bytes(pmo->iv, 16);

	if(PMO_BLOCK_IS_ENABLED()) {
		printk("Writing to %s\n", name);
		kernel_write(PMO_FILE_PTR, pmo, sizeof (struct pmo_entry), &pos);
	}
	pmo_sync(pmo->iv, 16);
	pmo_barrier();

	pmo_stats_stop_create_time(&mm->pmo_stats);
	trace_printk("[Create_end: %lld]", mm->pmo_stats.createtime);
	return; 
}
