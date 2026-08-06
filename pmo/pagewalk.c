/*
 * Copyright (C) 2021-2023 Derrick Greenspan and the University of Central 
 * Florida (UCF).                                                           
 *
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA. It is          
 * distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A   
 * PARTICULAR PURPOSE.                                                      
 *
 * Functions specific to PMO pagewalking.
 */

#include <linux/hugetlb.h>
#include <asm/tlbflush.h>
#include <linux/hugetlb.h>
#include <asm/tlbflush.h>
#include "../mm/internal.h"
#include "pagewalk.h"
#include "pmo.h"


/* TODO: this ought to be a NOP for a pagewalk system..
 * Set the pfn and pte for the struct pmo_pages */
void fix_pmo_page_entry(struct vm_area_struct *vma, unsigned long address,
                struct pmo_pages *entry)
{
        return;
}


/* Walks through the pagetable address, checking the pages for VM_SOFTDIRTY*
 * Pagewalking done as in change_protection_range (see mm/mprotect.c:324).  */
void _pmo_pagewalk(struct vpma_area_struct *vpma, unsigned long address, int flag,
                struct pmo_pages ** dirty_ll)
{
        struct vm_area_struct *vma = vpma->vma;
        struct mm_struct *mm = vma->vm_mm;
        pgd_t *pgd = pgd_offset(mm, address);
        size_t next, end = address + vpma->attached_size, start = address,
               page = 0;

        /* I don't think this is possible, but I want to assert that it isn't
         * for now, so we don't get a kernel bug. */
        BUG_ON(vpma->attached_size == 0 || address >= end);

        /* This is probably not needed since we're using x86, and as far as
         * I can tell, it's a no-op. But I'll include it just to be safe. */
        flush_cache_range(vma, address, end);

        inc_tlb_flush_pending(mm);
        do {
                next = pgd_addr_end(address, end);
                if(pgd_none_or_clear_bad(pgd))
                        continue;
                page++;
                p4d_range_dirtybits(vma, pgd, address, next, flag, dirty_ll);
        } while (pgd++, address = next, address != end);

        if(page)
                flush_tlb_range(vma, start, end);
        dec_tlb_flush_pending(mm);
        return;
}

inline void pmo_persist(struct vpma_area_struct *vpma, unsigned long int address,
                struct pmo_pages **dirty_ll)
{
	*dirty_ll = create_dirty_sentinel();
	_pmo_pagewalk(vpma, address, DB_PERSIST | DB_CLEAR, dirty_ll);
	return;
}

inline void pmo_unset_dirtybits(struct vpma_area_struct *vpma)
{
	_pmo_pagewalk(vpma, vpma->vma->vm_start, DB_CLEAR, NULL);
	return;
}

inline void add_to_dirtypages(struct vpma_area_struct *vpma,
		struct pmo_pages *page_to_add)
{
	return;
}

inline void vpma_clear(struct vpma_area_struct *vpma)
{
	pmo_kill_disable_thread(vpma);
	/*
	 * TODO: ... this should be part of zapvpma, probably
        if(vpma->faulted_pages_ll)
                kvfree(vpma->faulted_pages_ll);

        vpma->faulted_pages_ll = 0;
	*/
        vpma->pmo_ptr = 0;
        vpma->phys_shadow = 0;
        vpma->phys_primary = 0;

        if(vpma->phys_primary)
                pmo_unmap(vpma->primary);
        if(vpma->phys_shadow)
                pmo_unmap(vpma->shadow);



        kmem_cache_free(pmo_area_cachep, vpma);
        return;
}


inline void vpma_init(struct vpma_area_struct *vpma)
{
	vpma->faulted_pages_ll = NULL;
        vpma->vma = NULL;
        vpma->primary = NULL;
        vpma->shadow = NULL;
        vpma->phys_shadow = 0;
        vpma->current_mm = NULL;
        mutex_init(&vpma->psync_mutex);
        mutex_init(&vpma->page_mutex);
	return;
}

inline __always_inline void _pmo_handle_db_dirty(struct vm_area_struct *vma,
                struct pmo_pages **dirty_ll, unsigned long offset)
{
        struct pmo_pages *new_dirty_ll = NULL;
        struct vpma_area_struct *vpma = vma->vpma;
	unsigned long int pagenum = offset/PAGE_SIZE;

	/* If we have a page that was predicted (but not accessed),
	 * the system will inappropriately consider it dirty, since it's present.
	 * TODO: Verify this is actually a thing that happens... */
	WARN_ON(PMO_PRED_IS_ENABLED() && !PMO_TEST_IS_FAULTED(vpma, pagenum));


        new_dirty_ll = create_dirty_ll(offset, vpma->primary, vpma->shadow,
			(PMO_DRAM_IS_ENABLED() && !PMO_DRAM_AS_BUFFER_IS_ENABLED())
		       	? vpma->working_data[pagenum].vaddr : NULL);
        list_add_tail(&new_dirty_ll->list, &(*dirty_ll)->list);
	if(PMO_PPs_IS_ENABLED())
		pmo_inc_encrypted_pages(vpma);


	if (PMO_DRAM_AS_BUFFER_IS_ENABLED() || !PMO_DRAM_IS_ENABLED()) {
       	 	/* Persist page. */
	        pmo_sync(vpma->shadow + offset, PAGE_SIZE);
		if(PMO_IV_PSYNC_IS_ENABLED())
		        pmo_obtain_shadow_hash(vpma, offset/PAGE_SIZE);
	}
	else  {
		/* If bypass shadow...
		 * Then copy from working data to primary */
		memcpy_flushcache(vpma->shadow + offset,
				vpma->working_data[pagenum].vaddr, PAGE_SIZE);
		if(PMO_IV_PSYNC_IS_ENABLED()) {
			PMO_ASYNC_CHECKSUM_IS_ENABLED() ? 
				pmo_async_obtain_shadow_hash(vpma,
						offset/PAGE_SIZE) :
				pmo_obtain_shadow_hash(vpma, offset/PAGE_SIZE);
		}
	}


        return;
}

void _pmo_handle_pte_present(pte_t *pte, int flag, struct vm_area_struct *vma,
                struct pmo_pages **dirty_ll, unsigned long address, size_t offset)
{

        struct vpma_area_struct *vpma = vma->vpma;
	/*
	 * Before, we took the pte and got the page, and then from the page to
	 * the phys, but this lead to segmentation faults as the kernel
	 * attempted to persist randomly generated offsets. This is because
	 * the pte does not contain a struct page since we are mapping the PMO
	 * pages with no management whatsoever (this is also why swap is
	 * impossible). To fix this, we just don't get the struct page of the
	 * associated PTE anymore.
	 */
	        /* Should I persist the page? */
        if((flag & DB_PERSIST) && pte_dirty(*pte)) {
                /* FIXME: This works, but it will break if PMOs can ever be
                 * non-contiguous in physical memory */
                _pmo_handle_db_dirty(vma, dirty_ll, offset);
		pmo_clear_dirty(pte);

		pmo_towards_access(vpma,offset/PAGE_SIZE);
		goto out;
        }

	/* This page is present, but not dirty, which means that it has
	 * not been written since last access. We will check if 
	 * the access bit is set... */
	if(pte_young(*pte)) {
		/* Since the access bit is set, we need to clear it */
		pmo_clear_dirty(pte);
		pmo_clear_access(pte);

		/* This macro is ignored when not using predictive
		 * encryption. Transition towards not destroying the 
		 * shadow  */
		pmo_towards_access(vpma, offset/PAGE_SIZE);
		goto out;
	}
	
	pmo_towards_or_set_inert(vpma, offset/PAGE_SIZE);
	/* The page is old, so move towards destroy*/
	pmo_clear_access(pte);

out:
	if(PMO_SHOULD_CLEAR_WRITE(vpma)) {
		printk("The flag to clear the write is enabled\n");
		 pmo_clear_write(pte);
	}

	if(PMO_SHOULD_CLEAR_READWRITE(vpma)) {
		printk("The flag to clear all permissions are enabled\n");
		 pmo_clear_write(pte);
		 pmo_clear_read(pte);
	}

        return;
}


/* This is where the magic (should) happen
 * TODO: May want to move most of this out of here. Walking the page table like
 * this can be expensive */
void pte_range_dirtybits(struct vm_area_struct *vma, pmd_t *pmd,
                unsigned long address, unsigned long end, int flag,
                struct pmo_pages **dirty_ll)
{
	size_t offset;
	struct mm_struct *mm = vma->vm_mm;
        pte_t *pte = NULL;
        spinlock_t *ptl;
	/* Might need to move flush_tlb_batched_pending out of this thing...*/

        pte = pte_offset_map_lock(mm, pmd, address, &ptl);
	flush_tlb_batched_pending(mm);
	arch_enter_lazy_mmu_mode();
        do {
		if((long long) address - (long long) vma->vm_start < 0)
			printk(KERN_WARNING "Offset is negative...\n");
                if(pte_present(*pte)) {
			offset = PAGE_ALIGN(address) - vma->vm_start;
                        _pmo_handle_pte_present(pte, flag, vma, dirty_ll, address, offset);
		}
        } while (pte++, address += PAGE_SIZE, address < end);

	arch_leave_lazy_mmu_mode();
        pte_unmap_unlock(pte -1, ptl);
        return;
}


/* pmds "fold into" puds. But we still need this for compatibility. */
void pmd_range_dirtybits(struct vm_area_struct *vma, pud_t *pud,
               unsigned long address, unsigned long end, int flag,
               struct pmo_pages ** dirty_ll)
{
        unsigned long next, i = 0;
        pmd_t *pmd = pmd_offset(pud, address);
        do {
                next = pmd_addr_end(address, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
                pte_range_dirtybits(vma, pmd, address, next, flag, dirty_ll);
        } while (pmd++, i++, address = next, address != end);
        return;
}

void pud_range_dirtybits(struct vm_area_struct *vma, p4d_t *p4d,
                unsigned long address, unsigned long end, int flag,
                struct pmo_pages ** dirty_ll)
{
        pud_t *pud = pud_offset(p4d, address);
        unsigned long next;
        do {
                next = pud_addr_end(address, end);
                if (pud_none_or_clear_bad(pud))
                        continue;
                pmd_range_dirtybits(vma, pud, address, next, flag, dirty_ll);
        } while(pud++, address = next, address != end);
        return;
}

void p4d_range_dirtybits(struct vm_area_struct *vma, pgd_t *pgd,
                unsigned long address, unsigned long end, int flag,
                struct pmo_pages ** dirty_ll)
{
        p4d_t *p4d;
        unsigned long next;
        p4d = p4d_offset(pgd, address);
        do {
                next = p4d_addr_end(address, end);
                if(p4d_none_or_clear_bad(p4d))
                        continue;
                pud_range_dirtybits(vma, p4d, address, next, flag, dirty_ll);
        } while (p4d++, address = next, address != end);
        return;
}

inline struct pmo_pages * vpma_insert_into_faulted_pages(struct vpma_area_struct *vpma,
                unsigned long pfn, size_t offset, pte_t *pte, spinlock_t *ptl)
{
	return NULL;
}
inline struct pmo_pages * vpma_insert_into_dirtypages(struct vpma_area_struct *vpma,
               unsigned long pfn, size_t offset, pte_t *pte, spinlock_t *ptl)
{
	return NULL;
}
