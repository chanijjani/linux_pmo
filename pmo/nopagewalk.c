/*
 * Copyright (C) 2023 Derrick Greenspan and the University of Central 
 * Florida (UCF).                                                           
 *
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA. It is          
 * distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A   
 * PARTICULAR PURPOSE.                                                      
 *
 * Functions specific to the non PMO Pagewalk design.
 */

#include "pmo.h"
#include <linux/list.h>
#include <asm/pgtable.h>
#include "../mm/internal.h"
#include <asm/tlbflush.h>
#include <linux/hugetlb.h>
#include "nopagewalk.h"

/* In the no pagewalk case, we will only traverse a subset of the entire PMO,
 * these are the pages that have been faulted in. We check whether they are
 * present with pte_present(). */




void _traverse_handle_pmo_entry(struct vpma_area_struct *vpma,
		pte_t *pte, unsigned long pagenum, char flag)
{
	size_t offset = pagenum * PAGE_SIZE;
	struct vm_area_struct *vma = vpma->vma;
	unsigned long shadow = (unsigned long) vpma->shadow;

	/* Should I persist the page? */
	if (flag & DB_PERSIST) {
		pmo_sync ((void *) shadow + offset, PAGE_SIZE);
		pmo_obtain_shadow_hash (vpma, pagenum);
		pmo_inc_encrypted_pages (vpma);
	}

	if (IS_ENABLED (CONFIG_PMO_USE_PREDICTION)) 
		pmo_handle_prediction_pte(vpma, shadow + offset, pte);
	else if (IS_ENABLED (CONFIG_PMO_PARANOID_MODE)) 
		pmo_invalidate_pte(shadow + offset, pte);
	else if (flag & DB_CLEAR) 
		pmo_clear_dirty(pte);
	return;
}

/* Instead of performing a walk, we traverse the linked list of dirty pages
 * produced from page fault */
struct pmo_pages * _pmo_traverse(struct vpma_area_struct *vpma,
		unsigned long address, char flag, struct pmo_pages **dirty_ll)
{
	struct vm_area_struct *vma = vpma->vma;
	struct pmo_pages *cursor, *dirty_pages_ll = vpma->dirty_pages_ll;
	size_t start = vma->vm_start, end = vma->vm_end, page = 0;


	WARN_ON(!vpma->dirty_pages_ll);

	flush_cache_range(vma, address, end);

	inc_tlb_flush_pending(vma->vm_mm);
	
	list_for_each_entry(cursor, &dirty_pages_ll->list, list)  {
		flush_tlb_batched_pending(vma->vm_mm);
		arch_enter_lazy_mmu_mode();

		spin_lock(cursor->ptl);
		likely(pte_present(*cursor->pte)) ? 
			_traverse_handle_pmo_entry(vpma, cursor->pte,
				       	cursor->pagenum, flag) : 
			printk(KERN_WARNING "PTE not present\n");
		spin_unlock(cursor->ptl);

		arch_leave_lazy_mmu_mode();

		page++;
	}

	if(page)
		flush_tlb_range(vma, start, end);

	dec_tlb_flush_pending(vma->vm_mm);
	return vpma->dirty_pages_ll;
}

inline void pmo_persist(struct vpma_area_struct *vpma,
		unsigned long int address, struct pmo_pages **dirty_ll)
{
	*dirty_ll = vpma->dirty_pages_ll;
	_pmo_traverse(vpma, address, DB_PERSIST | DB_CLEAR, dirty_ll);
	return;
}

inline void pmo_unset_dirtybits(struct vpma_area_struct *vpma)
{
	_pmo_traverse(vpma, vpma->vma->vm_start, DB_CLEAR, NULL);
	return;
}

inline void add_to_dirtypages(struct vpma_area_struct *vpma,
                struct pmo_pages *page_to_add)
{
	if(!vpma->dirty_pages_ll)
		vpma->dirty_pages_ll = create_pages_ll(-1, -1);
	list_add_tail(&page_to_add->list, &vpma->dirty_pages_ll->list);
	return;
}


inline void vpma_clear(struct vpma_area_struct *vpma)
{
	if(vpma->phys_primary)
		pmo_unmap(vpma->primary);
	if(vpma->phys_shadow)
		pmo_unmap(vpma->shadow);

	if(vpma->faulted_pages_ll)
		kvfree(vpma->faulted_pages_ll);
        vpma->faulted_pages_ll = 0;

	if(vpma->dirty_pages_ll)
	        kvfree(vpma->dirty_pages_ll);
        vpma->dirty_pages_ll = 0;

	vpma->pmo_ptr = 0;
	vpma->phys_shadow = 0;
	vpma->phys_primary = 0;

	kmem_cache_free(pmo_area_cachep, vpma);
        return;
}


inline void vpma_init(struct vpma_area_struct *vpma)
{
        pmo_init_tracking(vpma);
        vpma->faulted_pages_ll = NULL;
	vpma->dirty_pages_ll = NULL;
        vpma->vma = NULL;
        vpma->primary = NULL;
        vpma->shadow = NULL;
        vpma->phys_shadow = 0;
        vpma->current_mm = NULL;
        mutex_init(&vpma->psync_mutex);
        mutex_init(&vpma->page_mutex);
        return;
}

struct pmo_pages * vpma_insert_into_dirtypages(struct vpma_area_struct *vpma,
		unsigned long pfn, size_t offset, pte_t *pte, spinlock_t *ptl)
{
	struct pmo_pages *tmp_ptr = create_dirty_ll(offset, vpma->primary, vpma->shadow,
			PMO_DRAM_IS_ENABLED() ? vpma->working : NULL);
	if(!vpma->dirty_pages_ll)
		vpma->dirty_pages_ll = create_pages_ll(-1, -1);

	tmp_ptr->pfn = pfn;

	if(pte) 
		tmp_ptr->pte = pte;
	if(ptl)
		tmp_ptr->ptl = ptl;

	list_add_tail(&tmp_ptr->list, &vpma->dirty_pages_ll->list);

	return tmp_ptr;
}

