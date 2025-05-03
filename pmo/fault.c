/*************************************************************************** 
 * Copyright (C) 2021-2023 Derrick Greenspan and the University of Central *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * Pagefault handling.			 				   *
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
#include <linux/swap.h>
#include <asm/io.h>
#include <asm/tlbflush.h>
#include "../mm/internal.h"
#include "pmo.h"

void pmo_debug_print_faulting_page(unsigned long int phys_addr, unsigned long int virt_addr)
{

	printk ("Phys:%ld\tVirt:%ld\n", phys_addr, virt_addr);
	//atomic_inc(&vpma->fault_order);
	return;
}

struct pmo_pages *create_pages_ll(unsigned long int address,
		unsigned long int offset)
{
        struct pmo_pages *faulted_pages_ll = 
		kmalloc(sizeof(struct pmo_pages), GFP_KERNEL);

	INIT_LIST_HEAD(&faulted_pages_ll->list);
        faulted_pages_ll->faulted_address = address;
	faulted_pages_ll->pagenum = offset;
	
        return faulted_pages_ll;
}

void _pmo_handle_pf_detached(struct vm_area_struct *vma, unsigned long address)
{
	/* We are in the detached state, so change permissions, and prepare for
	 * a segmentation fault... */
	printk(KERN_WARNING "Page Fault on detached PMO!\n");
	vma->vm_flags &= ~(VM_READ|VM_WRITE|VM_EXEC);
	vma_set_page_prot(vma);
	change_protection(vma, address, address + PAGE_SIZE,
			vma->vm_page_prot, 0);
	return;
}

void _pmo_change_pagefault_permissions(struct vm_area_struct *vma,
		unsigned long address, char type)
{
	vma->vm_flags |= (type == 'w' || type == 'W') ? VM_WRITE : VM_READ;
	vma_set_page_prot(vma);
	change_protection(vma, address&PAGE_MASK, (address&PAGE_MASK) + PAGE_SIZE,
			vma->vm_page_prot, 0);

	perf_event_mmap(vma);
	return;
}

/* Like follow_pfn, but also return the pte */
int _pmo_follow_pfn(struct vm_area_struct *vma, unsigned long address,
		unsigned long *pfn, pte_t **ptep, spinlock_t **ptlp)
{
	int ret = -EINVAL;

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP))) 
		return ret;

	ret = follow_pte(vma->vm_mm, address, ptep, ptlp);
	if (ret) 
		return ret;
	*pfn = pte_pfn(**ptep);
	pte_unmap_unlock(*ptep, *ptlp);
	return 0;
}

void _pmo_pred_run(struct vpma_area_struct *vpma,
		struct skcipher_request *req, unsigned long int pagenum,
		size_t size_in_pages, unsigned long int num_predicts,
		char *local_iv)
{
	int i;
	unsigned long int new_pagenum = pagenum;

	for (i = 1; i < num_predicts; i++) {
		new_pagenum = PMO_STREAM_IS_ENABLED() ?
			pagenum + i :
			PMO_MARKOV_IS_ENABLED() ? 
			pmo_decide_best_markov_path(vpma, new_pagenum) : 
			PMO_STRIDE_IS_ENABLED() ?
			pmo_decide_best_stride(vpma, new_pagenum) + new_pagenum : -1;

		if (new_pagenum >= size_in_pages)
			break;

		if (!PMO_TEST_AND_SET_IS_HANDLED(vpma, new_pagenum)) {
			PMO_PAGE_LOCK(vpma, new_pagenum);
			PMO_SET_IS_PREDICTED(vpma, new_pagenum);
			PMO_SET_PAGE_IN_BUFFER(vpma, new_pagenum);
		}
		else 
			continue;

		WARN_ON(PMO_PRED_IS_ENABLED() && vpma->working_data[new_pagenum].phys_addr == 0);

		PMO_NOENC_IS_ENABLED() ? 
			pmo_handle_page_prediction_noenc(vpma, new_pagenum):
			pmo_handle_page_prediction_enc(req, vpma, local_iv,
				&vpma->working_data[new_pagenum].sg_primary,
				PMO_DRAM_IS_ENABLED() ?
					&vpma->working_data[new_pagenum].sg_working :
					&vpma->working_data[new_pagenum].sg_shadow,
					new_pagenum);
	}
	return;
}

void _pmo_perform_prediction(struct vpma_area_struct *vpma, unsigned long int pagenum, unsigned int num_predicts)
{
	size_t size_in_pages = vpma->pmo_ptr->size_in_pages;
	struct skcipher_request *req;
       
	char local_iv[16];


	if (PMO_NOPRED_IS_ENABLED())
		return;

	if (!PMO_STREAM_IS_ENABLED())
		WARN_ON_ONCE(!atomic_read(&vpma->markov_table.initialized));

	memcpy(local_iv, vpma->crypto.pmo_iv, 16);
	req = skcipher_request_alloc (vpma->crypto.tfm,
			GFP_KERNEL);


	_pmo_pred_run(vpma, req, pagenum, size_in_pages, num_predicts, local_iv);
	skcipher_request_free(req);

	return;
}


/* Add a decrypted page entry to a linked list, to prepare for detach */
void pmo_insert_faulted_pages(struct vpma_area_struct *vpma,
		unsigned long int offset)
{
	struct vm_area_struct *vma = vpma->vma;
	unsigned long int address = vma->vm_start + offset;
	struct pmo_pages *temp = create_pages_ll(address, offset);
	init_completion(&temp->pte_nonzero);

	down_write(&vpma->pm_sem);
	if (!vpma->faulted_pages_ll)
		vpma->faulted_pages_ll = create_pages_ll(-1, -1);

	list_add_tail(&temp->list,
			&vpma->faulted_pages_ll->list);

	up_write(&vpma->pm_sem);

	return;
}

void _pmo_handle_waiting_for_page(struct vpma_area_struct *vpma)
{
	struct mm_struct *mm = vpma->current_mm;
	atomic64_inc(&mm->pmo_stats.total_waits);

	return;
}

void _handle_markov_or_stride(struct vpma_area_struct *vpma, unsigned long int pagenum)
{

	if (PMO_MARKOV_IS_ENABLED())
		pmo_increment_markov_entry(vpma, pagenum);
	else if (PMO_STRIDE_IS_ENABLED())
		pmo_increment_stride_entry(vpma,
			pagenum - atomic_read(&vpma->markov_table.last_page_accessed));

	atomic_set(&vpma->markov_table.last_page_accessed, pagenum);
	return;
}

/* The entry point to handling a PMO page fault */
struct pmo_pages * pmo_handle_pagefault(struct vm_area_struct *vma, size_t address)
{
	struct pmo_pages *temp_dirtypage;
	struct vpma_area_struct *vpma = vma->vpma;
	/* TODO, FIXME. If PMO_DRAM_IS_ENABLED() is true,
	 * then kern_address should equal the physical address
	 * of the start of the mapped memory... */
	unsigned long int offset = (address&PAGE_MASK) - vma->vm_start,
		      pagenum = offset/PAGE_SIZE, size_in_pages = 
			      vpma->pmo_ptr->size_in_pages, kern_address, pfn;
      	pte_t *pte;
	spinlock_t *ptl;

        int err = 0, not_mapped;

	struct mm_struct *mm = current->mm;
	unsigned long long int tick, tock;

	/* Page is handled, but it's not timely */
	if ( PMO_PRED_IS_ENABLED() && !PMO_TEST_PAGE_IS_TIMELY(vpma, pagenum) 
			&& PMO_TEST_IS_HANDLED(vpma, pagenum) &&
			!PMO_TEST_AND_SET_WAITING_HANDLED(vpma, pagenum)) 
		_pmo_handle_waiting_for_page(vpma);

	PMO_PAGE_LOCK(vpma, pagenum);
	/* This has to be behind the lock because it's possible that 
	 * multiple threads might be servicing the same fault otherwise! */

	pmo_stats_start_fault_time(&mm->pmo_stats, &tick);
	trace_printk("PMO: Page fault at %lX, pagenum %ld, offset %ld\n",
			address, pagenum, offset);

	if (PMO_PRED_IS_ENABLED() && vpma->working_data[pagenum].phys_addr == 0) 
		pmo_init_pred_working_data(vpma, pagenum);

       	not_mapped = _pmo_follow_pfn(vma, address, &pfn, &pte, &ptl);
	if(vpma->calling_pid == INT_MIN){
		//PMO_PAGE_LOCK(vpma, pagenum);
		_pmo_handle_pf_detached(vma, address);
		PMO_PAGE_UNLOCK(vpma, pagenum);
		return NULL;
	}
	else if(vpma->calling_pid < 0) {
		printk(KERN_WARNING "PID < 0 && PID != INT_MIN!\n");
		goto handle_pagefault_failure;
	}
	else { 
		if(not_mapped) {
		 	kern_address = (PMO_DRAM_IS_ENABLED() && !PMO_DRAM_AS_BUFFER_IS_ENABLED()) ?
			      vpma->working_data[pagenum].phys_addr : 
			      vpma->phys_shadow + offset;

			pfn = PMO_DAX_IS_ENABLED() ? kern_address >> PAGE_SHIFT :
				vmalloc_to_pfn(vpma->shadow + offset);

			if  (PMO_BLOCK_IS_ENABLED() || PMO_NOPRED_IS_ENABLED() || 
					PMO_DRAM_AS_BUFFER_IS_ENABLED() || 
					(PMO_PRED_IS_ENABLED() &&
					 !PMO_TEST_AND_SET_IS_HANDLED(vpma, pagenum))) 
				pmo_handle_page(vpma, pagenum);

			err = remap_pfn_range(vma, address&PAGE_MASK, pfn,
					PAGE_SIZE, vma->vm_page_prot);

			if (PMO_PRED_IS_ENABLED())
				PMO_SET_IS_FAULTED(vpma, pagenum);


			_pmo_perform_prediction(vpma, pagenum, PMO_GET_PREDICTION_DEPTH());

			pmo_inc_faulted_pages(vpma);
			if(PMO_PAGE_IS_DESTROYED(vpma, pagenum)) {
				pmo_inc_mispredict(vpma);
				goto handle_page_destroyed;
			}
			inc_pages_touched(vpma);
			current->mm->pmo_stats.pages_dirtied++; 

			if (PMO_MARKOV_IS_ENABLED() || PMO_STRIDE_IS_ENABLED())
				_handle_markov_or_stride(vpma, pagenum);

		}
		else  {
			/* This is mapped, but we're faulting.
			 * This shouldn't happen UNLESS vpma->flags has
			 * PMO_CLEAR_WRITE | PMO_CLEAR_READWRITE. In those
			 * cases, we should verify the page's checksum since
			 * last psync call */
			WARN_ON(!PMO_SHOULD_CLEAR_WRITE(vpma) &&
					!PMO_SHOULD_CLEAR_READWRITE(vpma));

			/* We're faulting on a mapped page, caused by either
			 * the write permissions being cleared or both the read
			 * and write permissions being cleared. 
			 * In either case, we should skip changing the
			 * page fault permissions.
			 *
			 * TODO: If we're  using the nopagewalk model, we will
			 * need to detect whether this was a fault from read
			 * or not, and only skip if it was a fault from read,
			 * otherwise it needs to be inserted into dirty pages. 
			 * But since we aren't using the nopagewalk model right
			 * now, there's no need to do this yet. -- DG */
			goto out2;
		}

		if(err)
			goto handle_pagefault_failure;
	}

handle_page_destroyed:
	PMO_CLEAR_PAGE_DESTROYED(vpma, pagenum);
	_pmo_change_pagefault_permissions(vma, address, vpma->type);

        
	/* If we're using the no pagewalk model, we'll add this to the
	 * dirtypages as well, If we've got the PTE, we'll add that as well. 
	 * This function does nothing when not using this model.*/
	temp_dirtypage = vpma_insert_into_dirtypages(vpma, pfn, offset,
			not_mapped ? NULL : pte, not_mapped ? NULL : ptl); 
	

out2:

	if (PMO_IV_IS_ENABLED() && PMO_NOENC_IS_ENABLED()) {
		/* Check whether hash matches stored hash */
	       	PMO_ASYNC_CHECKSUM_IS_ENABLED() ?
			nonblocking_verify_fault(vpma, pagenum) :
			handle_pmo_hash_identical(vpma,
					vpma->shadow + pagenum * PAGE_SIZE,
					pagenum, false);
	}

	pmo_stats_stop_fault_time(&mm->pmo_stats, &tick, &tock);

	PMO_PAGE_UNLOCK(vpma, offset/PAGE_SIZE);

	/* Return the entry in the list if it's not mapped and we have not
	 * enabled the pagewalk subsystem... */ 
	return not_mapped && IS_ENABLED(CONFIG_PMO_NO_PAGEWALK) ?
		temp_dirtypage : NULL;

	handle_pagefault_failure:
		pmo_stats_stop_fault_time(&mm->pmo_stats, &tick, &tock);
		printk("[fault_start_time: %llu,  fault_end_time: %llu], PMO_IV_IS_ENABLED() = %d\n",
			tick, tock, PMO_IV_IS_ENABLED());
		PMO_PAGE_UNLOCK(vpma, offset/PAGE_SIZE);
    		return NULL;
}
