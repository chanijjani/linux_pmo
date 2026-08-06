/*************************************************************************** 
 * Copyright (C) 2023 Derrick Greenspan and the University of Central	   *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA.               *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY   *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or       *
 * FITNESS FOR A PARTICULAR PURPOSE.                                       *
 ***************************************************************************
 * PMO encryption functions.						   *
 ***************************************************************************/

#include "pmo.h"
void pmo_handle_memcpy_sync_noenc(struct skcipher_request *req,
                struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
                struct scatterlist *sg_primary, struct scatterlist *sg_shadow)
{
        void *primary = vpma->primary + pagenum * PAGE_SIZE,
             *shadow = vpma->shadow + pagenum * PAGE_SIZE;
        memcpy_flushcache(primary, shadow, PAGE_SIZE);
        return;
}

void pmo_handle_page_noenc (struct vpma_area_struct *vpma, size_t offset)
{
	void *primary = vpma->primary + offset,
	     *shadow = vpma->shadow + offset;

	/*
	 * If bypass shadow is true, do not do anything here... just return 
	 * ex:		if (PMO_BYPASS_SHADOW())
	 * 			return;
	 */

	memcpy_flushcache (shadow, primary, PAGE_SIZE);
	pmo_barrier();
	return;
}
