/*************************************************************************** 
 * Copyright (C) 2023 Derrick Greenspan and the University of Central	   *
 * Florida (UCF).							   *
 ***************************************************************************
 * ABEND and PANIC() handling						   *
 ***************************************************************************/

#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/libnvdimm.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/libnvdimm.h>
#include <linux/perf_event.h>
#include <crypto/skcipher.h>
#include "../mm/internal.h"
#include "pmo.h"

/* This performs a similar action to memcpy_flushcache_dirtypages,
 * except we cannot know which pages have been properly copied over and
 * which have not. The dirtypage structure may also be destroyed, and at any
 * rate, is not accessible to us from this environment. Therefore, we have to
 * check each page and determine if there is data in the shadow; if so, we either
 * copy or encrypt it into the primary, depending on whether we are using
 * encryption. */
void pmo_handle_shadow_abend(struct vpma_area_struct *vpma)
{
	int i;
	__maybe_unused struct crypto_skcipher *tfm = NULL;
	__maybe_unused struct skcipher_request *req = NULL;
	__maybe_unused struct scatterlist *sg_primary = NULL,
		       *sg_shadow = NULL;
	struct pmo_entry *pmo = vpma->pmo_ptr;
	unsigned int size_in_pages = pmo->size_in_pages;
	char local_iv[16];

	printk(KERN_WARNING "Handling ABEND for PMO %s -- shadow is valid",
			pmo->name);

	if(PMO_PPs_IS_ENABLED()) {
		tfm = pmo_get_tfm(vpma);
		req = skcipher_request_alloc(tfm, GFP_KERNEL);
		memcpy(local_iv, pmo_get_iv(vpma), 16);
	}

	for(i = 0; i < size_in_pages; i++) { /* pmo_size is in pages */
		/* Check if page has data */
		if(memcmp(vpma->shadow + i * PAGE_SIZE, ZEROED_PAGE, PAGE_SIZE) != 0) {
			/* If we're using crypto, we should init the
			 * scatterlist... */
			if(PMO_PPs_IS_ENABLED()) {
				sg_primary = kmalloc(sizeof(struct scatterlist),
						GFP_KERNEL);
				sg_shadow = kmalloc(sizeof(struct scatterlist),
						GFP_KERNEL);
				sg_init_one(sg_shadow,
						vpma->shadow + i * PAGE_SIZE,
						PAGE_SIZE); 
				sg_init_one(sg_primary,
						vpma->primary + i * PAGE_SIZE,
						PAGE_SIZE);
			}
			/* Now pass in the scatterlist (or the NULL pointer) */
			pmo_handle_memcpy_sync(req, vpma, i, local_iv,
					sg_primary, sg_shadow);
		}
	}

	if(PMO_PPs_IS_ENABLED())
		skcipher_request_free(req);
	

	return;
	
}

void pmo_destroy_shadow_abend(struct vpma_area_struct *vpma)
{
	struct pmo_entry *pmo = vpma->pmo_ptr;
	int size_in_pages = pmo->size_in_pages, i;

	printk(KERN_WARNING "Destroying shadow for %s\n", pmo->name);
	for(i = 0; i < size_in_pages; i++) {
		/* Check if this page even exists... */
		if(memcmp (vpma->shadow + i * PAGE_SIZE,
					ZEROED_PAGE, PAGE_SIZE) != 0) {
			memcpy(vpma->shadow + i * PAGE_SIZE, ZEROED_PAGE, PAGE_SIZE);
			pmo_sync(vpma->shadow + i * PAGE_SIZE,
					PAGE_SIZE);
		}
	}
	pmo_barrier();
	return;
}

void pmo_handle_abend(struct vpma_area_struct *vpma, size_t start_vma_address)
{
	struct pmo_entry *pmo = vpma->pmo_ptr;

	printk("Handled abend\n");

	/* We were copying pages from the shadow to the primary, so the shadow
	 * copy is valid. We don't know *which* pages were going to be copied,
	 * nor do we know which pages have already been copied, so we must
	 * copy or encrypt all of the pages within the shadow that were faulted
	 * in, by checking whether a page is NULL. Finally, we destroy the
	 * shadow. */
	if(pmo_bit_is_set(3, pmo)) 
		pmo_handle_shadow_abend(vpma);
	
	/* We haven't yet started copying pages from the shadow to the primary,
	 * so the primary is valid. Just drop the shadow. */
	if(pmo_bit_is_set(3,pmo) || pmo_bit_is_set(2, pmo))
		pmo_destroy_shadow_abend(vpma);

	pmo_unlock_bit(4, pmo);
	pmo_unlock_bit(3, pmo);

	return;
}
