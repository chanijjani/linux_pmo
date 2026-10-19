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

/*
 * Does the calling process already map the space at @location?  Attach finds
 * its VPMA by name, so a process that re-creates a PMO it has attached keeps
 * using the space (and the page hashes) of its first attach.
 */
static bool pmo_location_mapped_by_current(__u64 location)
{
	__u64 address = location * PAGE_SIZE + metadata_start;
	struct rb_node *node;

	for (node = rb_first(&current->mm->pmo_rb); node; node = rb_next(node))
		if (rb_entry(node, struct vpma_area_struct, node)->phys_primary ==
				address)
			return true;
	return false;
}

/*
 * A newly created PMO has no valid page hashes.  Reset the per-page hash slots
 * of its primary and shadow (2 * size_in_pages contiguous slots, as the shadow
 * follows the primary) to PMO_EMPTY_CHECKSUM, which the fault-time check
 * accepts.  Otherwise a PMO created on reused space is checked against the
 * previous owner's hashes, and every page of its first attach fails.
 */
static void pmo_reset_page_hashes(__u64 location, __u64 size_in_pages)
{
	__u64 address = location * PAGE_SIZE + metadata_start;
	size_t first, count = 2 * size_in_pages, i;

	if (!sha256_region || address < header->this.pmo_region_location)
		return;

	first = pmo_address_to_sha_offset(address);
	if ((first + count) * sizeof(struct pmo_sha256) > sha256size) {
		printk(KERN_ERR "PMO: hash slots of location %llu out of range\n",
				location);
		return;
	}

	for (i = 0; i < count; i++)
		memset(OFFSET_TO_SHA(first + i), 0xFF, sizeof(struct pmo_sha256));
	pmo_sync(OFFSET_TO_SHA(first), count * sizeof(struct pmo_sha256));
	pmo_barrier();
}

int do_create(char *name, __u64 size, char *key)
{
	void *pmo_mapping;
        struct pmo_entry *pmo;
	char local_key[64];

	struct mm_struct *mm = current->mm;
	loff_t pos;
        __u64 address, hash, location,
	      pmolist_start = metadata_start + sizeof(union pmo_header) + sizeof(__u64);

	pmo_stats_start_create_time(&mm->pmo_stats);
	trace_printk("[Create_start: %lld]\n", mm->pmo_stats.createtime_start);
	memset(local_key, 0, 64);
	strncpy(local_key, key, 64);

	hash = djb2_hash(name) % MAX_NODES;

       	address = pmolist_start + sizeof(struct pmo_entry) * hash;
	pos = address;

        pmo_mapping = pmo_memremap(name); //address, sizeof(struct pmo_entry), MEMREMAP_WB);

        pmo = (struct pmo_entry *)pmo_mapping;

	/* Decide the location before touching the entry, so a failed create
	 * leaves whatever PMO was there intact */
	location = get_pmo_location(pmo, name, size);
	if (location == PMO_NO_LOCATION) {
		printk(KERN_ERR "PMO: cannot create %s: no space left\n", name);
		pmo_stats_stop_create_time(&mm->pmo_stats);
		return -ENOSPC;
	}

	if (!pmo_location_mapped_by_current(location))
		pmo_reset_page_hashes(location, PAGE_ALIGN(size) / PAGE_SIZE);

        strcpy(pmo->name, name);

	pmo->size_in_pages = PAGE_ALIGN(size)/PAGE_SIZE;
        pmo->pm_primary = location;
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
	trace_printk("[Create_end: %lld]\n", mm->pmo_stats.createtime);
	return 0;
}
