/*
 * Copyright (C) 2021-2022 Derrick Greenspan and the University of Central 
 * Florida (UCF).                                                           
 *
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA. It is 	    
 * distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A   
 * PARTICULAR PURPOSE.                                       		    
 *
 * PMO Access functions, system calls, helpers.				    
 */

#include <asm/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/radix-tree.h>
#include <linux/mutex.h>
#include <linux/syscalls.h>
#include <linux/libnvdimm.h>
#include <linux/ctype.h>
#include "pmo.h"



DEFINE_MUTEX(pmo_system_mutex);
RADIX_TREE(pmo_radix_tree, GFP_KERNEL);

/* Former DAX start */
__u64 metadata_start = ULONG_MAX, 
      metadata_end = ULONG_MAX;

size_t sha256size = 0;
struct pmo_sha256 *sha256region = (struct pmo_sha256 *) ULONG_MAX;

EXPORT_SYMBOL(metadata_start);
EXPORT_SYMBOL(metadata_end);

struct kmem_cache *pmo_area_cachep = NULL;
union pmo_header *header;
char ZEROED_PAGE[PAGE_SIZE];

char * _build_pmo_name(char *pmo_name, size_t size, size_t page_offset)
{
	int i;
	char *name = kcalloc(sizeof(char), 50, GFP_KERNEL);;

	/* Store the size of the attached portion of the PMO as a multiple of
	 * the page size */
	name[0] = size == 0 ? 254 : size/PAGE_SIZE;

	/* Store the page offset */
	name[1] = page_offset == 0 ? 254 : page_offset;

	/* The name consists of protection (read or write) + page_offset + 
	 * size + name. For example, attempting to read 2 pages of a PMO named
	 * "PMO" and with no offset, would result in "r0\2PMO" (where \2 is
	 * the ASCII binary 0x2) */

	for (i = 0; i < 20; i++) {
		if (pmo_name[i] == 0)
			break;
		name[i+2] = pmo_name[i];
	}

	return name;
}
void * do_attach(struct pmo_entry *pmo, char prot_type, size_t size, size_t page_offset,
		char * key, unsigned char flags)
{
	struct mm_struct *mm = current->mm;
	unsigned long long int address = pmo->pm_primary * PAGE_SIZE +
		metadata_start + PAGE_SIZE * page_offset;

	char *name;

	unsigned long long int end_ktyime, start_ktime;

	struct vpma_area_struct *vpma;
	size_t length = (size == 0 ? pmo->size_in_pages * PAGE_SIZE : size);

	char mode[20];
	pmo_get_mode(mode);
	printk("Attach flags for PMO is %lX, Async: %d, PMO MODE: [%s]\n", flags, PMO_GET_ASYNC_WOKRER_NUM(), mode);
	
	name = _build_pmo_name(pmo->name, size, page_offset);

	pmo_stats_start_attachtime_other(&mm->pmo_stats);
	trace_printk("[Attach_Total_start: %lld]\n", mm->pmo_stats.attachtime_other_start);

	vpma = vpma_search(&(mm->pmo_rb), name);

	pmo_stats_start_attachtime_wait(&mm->pmo_stats);
	trace_printk("[Attach_wait_start: %lld]\n", mm->pmo_stats.attachtime_wait_start);

	if (vpma)
		down_write(&vpma->pm_sem);
	/*
	else
		mmap_read_lock(mm);
		*/

	pmo_stats_stop_attachtime_wait(&mm->pmo_stats);
	trace_printk("[Attach_wait_elapsed: %lld]\n", mm->pmo_stats.attachtime_wait);

	/* Check if we need to recover anything. Don't recover a new PMO */
	if (!pmo_bit_is_set(6, pmo) && pmo->state && pmo->state != 1) {
		if (recover (pmo, prot_type, key) == -1) {
			pmo_stats_stop_attachtime_other(&mm->pmo_stats);
			trace_printk("[Attach_wait_elapsed: %lld]\n", mm->pmo_stats.attachtime_wait);
			return NULL; /* Bail out */
		}
	}

	/* Now we need to lock the PMO */
	pmo_test_and_lock(0, pmo);

	/* toggle if we are writing, otherwise, don't do anything */
	((prot_type == 'w') || (prot_type == 'W')) ?
		pmo_set_bit(1, pmo) : pmo_unlock_bit(1, pmo);

	/* Set up the VPMA if it doesn't already exist */
	if (!vpma) {
		/* This will be treated differently if we're using an NVMe vs
		 * DAX */
		vpma = create_vpma_for_pmo(address, length, pmo->name,
				name, prot_type, key);
		pmo_update_metadata(vpma);
		down_write(&vpma->pm_sem);

	  	/* Expand the total size of the mm_struct's virtual memory  */
         	mm->total_vm += length >> PAGE_SHIFT;
	}

          vpma->attached_size = length;
          vpma->attached_offset = PAGE_SIZE * page_offset;
	  vpma->flags = flags;
	 if(enable_vpma_access(vpma, length, PAGE_SIZE * page_offset, prot_type, key)) {
		 printk(KERN_WARNING "Enable VPMA access failed!\n");
		pmo_stats_stop_attachtime_other(&mm->pmo_stats);
		trace_printk("[Attach_Total_elapsed: %lld]\n", mm->pmo_stats.attachtime_other);
		return 0;
	 }

	 kvfree(name);

	 pmo_stats_stop_attachtime_other(&mm->pmo_stats);
	 trace_printk("[Attach_Total_elapsed: %lld]\n", mm->pmo_stats.attachtime_other);

	 pmo_update_metadata(vpma);
	 pmo_stats_stop_attachtime_end(&mm->pmo_stats);

	 return (void *) vpma->vma->vm_start;

}

/* Is the PID currently active? */
int is_alive_pid(int pid)
{
	struct task_struct *task;
	for_each_process(task) {
		if(task->pid == pid) 
			return 1;
	}
	return 0;
}

int get_boot_id(void)
{
	int boot_id = atomic_read(&header->this.boot_id);
	return boot_id;
}

int enable_vpma_access(struct vpma_area_struct *vpma, __u64 size,
		__u64 offset, char prot_type, char *key) {

        struct vm_area_struct *vma = vpma->vma;
	struct pmo_entry *pmo = vpma->pmo_ptr;
	int i;
	__u64 phys_primary = vpma->phys_primary;
	pmo_init_tracking(vpma);


	vma->vm_flags = ((((prot_type == 'w')||(prot_type == 'W')) ?
				VM_WRITE : VM_READ)
			| VM_MAYSHARE | VM_SHARED | VM_NOHUGEPAGE| VM_PFNMAP);

	vma_set_page_prot(vma);



	inc_total_pages(vpma, size/PAGE_SIZE);
	if(!vpma->phys_shadow) {
		/* The size of the free area will produce a gap between
		 * the end of phys primary and the beginning of the shadow */
		vpma->phys_shadow = get_phys_shadow_from_size(phys_primary, size);  
		vpma->shadow = pmo_map(vpma->phys_shadow, PAGE_ALIGN(size));
			
		vpma->current_mm = current->mm;

		if (PMO_PRED_IS_ENABLED() || PMO_IV_IS_ENABLED() || PMO_DRAM_IS_ENABLED()) {
			vpma->working_data = 
				kvmalloc (size/PAGE_SIZE * sizeof (struct working_page),
						GFP_KERNEL);
			pmo_initialize_verify_thread(vpma);
			for (i = 0; i < size/PAGE_SIZE; i++)  {
				/*
				vpma->working_data[i].phys_addr = 0;
				vpma->working_data[i].vaddr = 0;
				*/
				pmo_init_pred_working_data(vpma, i);

				PMO_CLEAR_WAITING_HANDLED(vpma, i);
				PMO_CLEAR_IS_FAULTED(vpma, i);
				PMO_CLEAR_IS_PREDICTED(vpma, i);
				PMO_CLEAR_IS_HANDLED(vpma, i);
				PMO_CLEAR_PAGE_TIMELY(vpma, i);
			}
			wmb();
		}
	}

	if(PMO_WHOLE_IS_ENABLED()) {
		whole_enable_vpma_access(vpma);
		goto out;
	}

	if (PMO_DEBUG_MODE_IS_ENABLED())
		printk (KERN_INFO "attach:%d\n", atomic_read(&vpma->fault_order));

	vpma_set_sha_ranges(vpma);

	/* Indicate shadow is invalid -- but primay valid and encrypted */
	/* PMO is decrypted! */
	BUG_ON(pmo_bit_is_set(7, pmo)); /* This shouldn't happen,
					       recovery should have detected
					       this condition and prevented it. */

	pmo_set_bit(2, pmo);
out: 
	if(prot_type == 'w') {
		if(!IS_ENABLED(CONFIG_PMO_NO_PREDICTION)) 
			pmo_set_predict_init_state(vpma, pmo->size_in_pages);
		atomic_set(&pmo->pid, task_pid_vnr(current));
		atomic_set(&pmo->boot_id, get_boot_id());
	}

	vpma->calling_pid = task_pid_vnr(current);
	pmo_unlock_bit(2, pmo);
	pmo_unlock_bit(3, pmo);
	pmo_update_metadata(vpma);
	up_write(&vpma->pm_sem);

	return 0;
}

/*
 * Tear down a vpma's mappings and release the PMO.
 *
 * Takes vpma->pm_sem itself: the caller must NOT hold it.  This used to be
 * entered with the semaphore already held by do_detach() and released here,
 * which meant that under CONFIG_PMO_NONBLOCKING the lock was acquired by the
 * detaching task and dropped by the detach kthread.  An rw_semaphore records
 * its owner and cannot be handed between tasks: doing so corrupted the
 * semaphore's count, after which a later down_write() either blocked forever
 * (silent machine hang) or failed to exclude at all (two tasks mutating one
 * vpma, seen as a stray digest write through a dangling pointer).
 */
int disable_vpma_access(struct vpma_area_struct *vpma)
{
	size_t size;
	struct pmo_pages *conductor = NULL;
	struct pmo_entry *pmo;

	down_write(&vpma->pm_sem);

	pmo = vpma->pmo_ptr;
        size = pmo->size_in_pages * PAGE_SIZE;

	if(PMO_WHOLE_IS_ENABLED()) {
		whole_disable_vpma_access(vpma);
		goto out;
	}

	conductor = vpma->faulted_pages_ll;

	if(!conductor) 
		goto out;

	PMO_PPb_IS_ENABLED() ? 
		pmo_encrypt_primary_destroy_shadow(vpma, conductor) :
		pmo_destroy_shadow(vpma, conductor, false);
	

	

out:
//	vpma->faulted_pages_ll = NULL;
	vpma->calling_pid = INT_MIN;

	atomic_set(&pmo->pid, 0);

	atomic_set(&pmo->boot_id, 0);

	pmo_unlock_bit(1, pmo);
	pmo_unlock_bit(2, pmo);
	pmo_unlock_bit(3, pmo);
	pmo_unlock_bit(6, pmo);

	pmo_update_metadata(vpma);
	up_write(&vpma->pm_sem);
	return 0;
}


int do_detach(struct mm_struct *mm, char *path)
{
	struct vpma_area_struct *vpma;
	struct pmo_entry *pmo;
	struct vm_area_struct *vma;
	mmap_read_lock(mm);
	vma = find_vma(mm, (long unsigned int)path);
	vpma = vma->vpma;
	mmap_read_unlock(mm);

	if(unlikely(!vpma)) {
		printk(KERN_INFO "No associated vpma found that is suitable for detach\n");
		return -ENOENT;
	}

	if (PMO_ASYNC_CHECKSUM_IS_ENABLED()) {
		/* Push out the partial batch, then wait for every queued
		 * verification to finish: the work items hold a raw vpma
		 * pointer and must not outlive the detach. */
		pmo_flush_verify_batch(vpma);
		pmo_wait_verify_work();
		trace_printk("Verification work drained before detach.\n");
	}

	pmo = vpma->pmo_ptr;

	if(unlikely(!pmo)){
		printk(KERN_ERR "WARNING: pmo not found\n");
		return 0;
	}
	
	mm->pmo_stats.all_pages += pmo->size_in_pages;

	pmo_stats_start_detach_time(&mm->pmo_stats);
	trace_printk("[Detach_start: %lld]\n", mm->pmo_stats.detachtime_start);

	/* Revoke access and publish the detached state while serialised against
	 * the fault path, then drop the lock.  disable_vpma_access() re-takes it
	 * on whichever task ends up running the teardown -- it must not be
	 * inherited from here (see disable_vpma_access). */
	down_write(&vpma->pm_sem);
        vma->vm_flags &= ~(VM_READ|VM_WRITE|VM_EXEC);
        vma_set_page_prot(vma);
	vpma->calling_pid = INT_MIN;
	up_write(&vpma->pm_sem);

	/* Hand the teardown to the per-vpma kthread */
	if(IS_ENABLED(CONFIG_PMO_NONBLOCKING)) 
		nonblocking_disable_vpma_access(vpma);
	else /* Directly call disable_vpma_access */
		disable_vpma_access(vpma);

	pmo_stats_stop_detach_time(&mm->pmo_stats);
	trace_printk("[Detach_end: %lld]\n", mm->pmo_stats.detachtime);

	return 0;
}


size_t do_get_size(struct mm_struct *mm, char *path)
{
	struct vpma_area_struct *vpma;
	struct pmo_entry *pmo;
	mmap_write_lock(mm);
	vpma = find_vma(mm, (long unsigned int)path)->vpma;
	mmap_write_unlock(mm);

	if(unlikely(!vpma))
		return -ENOENT;

	pmo = vpma->pmo_ptr;

	if(unlikely(!pmo)){
		printk(KERN_ERR "WARNING: pmo not found\n");
		return 0;
	}
	return pmo->size_in_pages*PAGE_SIZE;
}



/**
 * get_pmo_from_name() - get the pmo metadata information from its name.
 * @arg1: Name of the PMO
 *
 * Returns metadata associated with the PMO, or NULL, if none exists.
 * Inserts the metadata into the cached radix tree.
 *
 * Return: a pointer to the PMO metadata entry. 
 */
struct pmo_entry *get_pmo_from_name(char * name)
{
          struct pmo_entry * pmo = (struct pmo_entry *) pmo_memremap(name);

          if(strcmp(name, pmo->name) == 0) {
                  radix_tree_insert(&pmo_radix_tree, djb2_hash(name), pmo);
                  return pmo;
          }
          return NULL;
}
EXPORT_SYMBOL(get_pmo_from_name);

struct pmo_entry *pmo_memremap(char *name)
{
	unsigned long int entry_id = djb2_hash(name) % MAX_NODES;
	return PMO_DAX_IS_ENABLED() ? pmo_dax_memremap(entry_id) :
		pmo_block_memremap(entry_id);
}



/*
 * Does [offset, offset + span) -- an offset from metadata_start -- lie inside
 * the PMO device?  metadata_end is the device's last byte (inclusive).
 *
 * This must hold for every PMO: under DAX the region is memremap()ed, and
 * memremap() of an address past the end of the dax device that happens to be
 * System RAM silently returns the direct-map alias of live kernel memory.
 * The PMO then scribbles over whatever the kernel keeps there.
 */
static bool pmo_location_fits(__u64 offset, __u64 span)
{
	if (span == 0 || offset + span < offset)
		return false;
	/* pm_primary is a 32-bit page index */
	if ((offset + span) / PAGE_SIZE >= PMO_NO_LOCATION)
		return false;
	return metadata_start + offset + span - 1 <= metadata_end;
}

/*
 * Can a re-create of an existing PMO keep the space it already owns?  Only if
 * that space is big enough and was handed out by the allocator's current run
 * (i.e., below next_free_pmo), so it cannot overlap any other live PMO.
 * Caller holds pmo_system_mutex.
 */
static bool pmo_attached_elsewhere(struct pmo_entry *pmo)
{
	int pid = atomic_read(&pmo->pid);
	bool alive;

	/* pid is left over from an earlier boot, or it is our own attach
	 * whose (nonblocking) detach has not cleared it yet */
	if (!pid || atomic_read(&pmo->boot_id) != get_boot_id() ||
			pid == task_pid_vnr(current))
		return false;

	rcu_read_lock();
	alive = pid_task(find_vpid(pid), PIDTYPE_PID) != NULL;
	rcu_read_unlock();
	return alive;
}

static bool pmo_location_reusable(struct pmo_entry *pmo, __u64 size)
{
	__u64 offset = (__u64)pmo->pm_primary * PAGE_SIZE,
	      span = 2 * (__u64)pmo->size_in_pages * PAGE_SIZE;

	/* Another process still maps the old space: give the new PMO its own */
	if (pmo_attached_elsewhere(pmo))
		return false;

	return pmo->pm_primary != PMO_NO_LOCATION &&
		(__u64)pmo->size_in_pages * PAGE_SIZE >= PAGE_ALIGN(size) &&
		offset + span <= header->this.next_free_pmo &&
		pmo_location_fits(offset, span);
}

/*
 * Pick the location of a PMO being created, as a page index from
 * metadata_start.  Re-creating a PMO under its own name reuses its space:
 * PMOs cannot be deleted, so benchmarks that re-create the same PMO every
 * iteration used to leak 2 * size per create and, after ~15.9k creates of a
 * 4 MiB PMO, run off the end of dax0.0 into DRAM.
 *
 * Returns PMO_NO_LOCATION if the device is full.
 */
__u64 get_pmo_location(struct pmo_entry *pmo, char *name, __u64 size)
{
	__u64 location;

	mutex_lock(&pmo_system_mutex);
	if (strncmp(pmo->name, name, sizeof(pmo->name)) == 0 &&
			pmo_location_reusable(pmo, size))
		location = pmo->pm_primary;
	else
		location = PMO_NO_LOCATION;
	mutex_unlock(&pmo_system_mutex);

	if (location != PMO_NO_LOCATION)
		return location;
	return get_available_pmo_location(size);
}

__u64 get_available_pmo_location(__u64 size)
{
          __u64 available_pmo;

          /*****************************
           * Start of critical section *
           *****************************/
          mutex_lock(&pmo_system_mutex);

          /* get an available open PMO */
          available_pmo = header->this.next_free_pmo;

	  /* Primary and shadow both have to fit; do not advance past the end */
	  if (!pmo_location_fits(available_pmo, 2 * (__u64)PAGE_ALIGN(size))) {
		  mutex_unlock(&pmo_system_mutex);
		  printk(KERN_ERR "PMO: out of space: need %llu bytes at offset "
				  "0x%llx, device ends at 0x%llx\n",
				  2 * (__u64)PAGE_ALIGN(size), available_pmo,
				  metadata_end - metadata_start + 1);
		  return PMO_NO_LOCATION;
	  }

          /* The next free PMO should be double the size of the PMO and the size of the 
	   * to provide room for the shadow PMO
	   * If we're using ALLOC, also want to provide additional room for that */
          header->this.next_free_pmo = get_next_free_pmo(available_pmo, size);
  
          /* Flush the cacheline here to ensure persistence */
	  if (PMO_DAX_IS_ENABLED())
          	pmo_sync(&header->this.next_free_pmo, sizeof(__u64));
	  else
	  	pmo_update_header();

	  pmo_barrier();
          mutex_unlock(&pmo_system_mutex);
  
          /***************************
           * End of critical section *
           ***************************/
  
	  /* Bounds were checked above, before next_free_pmo was advanced */
	  return available_pmo / PAGE_SIZE;
}



void pmo_encrypt_shadow(struct vpma_area_struct *vpma, struct pmo_pages *head)
{
	struct pmo_pages *cursor, *temp;
	unsigned long int address, offset, page_count = 0;
	struct vm_area_struct *vma = vpma->vma;
	list_for_each_entry_safe(cursor, temp, &head->list, list) {
		address = cursor->faulted_address&PAGE_MASK;
		change_protection(vma, address, address + PAGE_SIZE,
				vma->vm_page_prot, CP_FLAGS);
		offset = address - vma->vm_start;

		/* Can just copy the primary over */
		memcpy_flushcache(vpma->shadow + offset,
				vpma->primary + offset, PAGE_SIZE);
		list_del(&cursor->list);
		kfree(cursor);
		page_count++;
	}
	pmo_barrier();
	return;
}

void pmo_destroy_shadow_page(struct vpma_area_struct *vpma, size_t pagenum, char detach)
{
	struct vm_area_struct *vma = vpma->vma;

	if(PMO_PAGE_IS_DESTROYED(vpma, pagenum))  {
		return;
	}

	/* Update the IV even if it's just sitting in DRAM */
	if(PMO_IV_DETACH_IS_ENABLED()) {
		pmo_obtain_shadow_hash(vpma, pagenum);
		pmo_assign_primary_hash(vpma, pagenum);
	}



	 /* We kept the page around even into detach, which we don't want */
	if(detach) 
		pmo_inc_exposed_pages(vpma);
	else {
		dump_stack();
		PMO_SET_PAGE_DESTROYED(vpma, pagenum);
	}

	if (PMO_DRAM_IS_ENABLED())
		pmo_invalidate_page(vpma, pagenum, false);
	else {
		memset(vpma->shadow + pagenum * PAGE_SIZE, 0, PAGE_SIZE);
		pmo_sync(vpma->shadow + pagenum * PAGE_SIZE, PAGE_SIZE);
	}

	if (PMO_BLOCK_IS_ENABLED()) {
		loff_t loff_shadow = vpma->phys_shadow + pagenum * PAGE_SIZE;
		kernel_write(PMO_FILE_PTR, vpma->shadow + pagenum * PAGE_SIZE,
				PAGE_SIZE, &loff_shadow);
	}

        zap_vma_ptes(vma, vma->vm_start + pagenum * PAGE_SIZE, PAGE_SIZE);

	return;
}

void _pmo_populate_prediction_statistics (struct vpma_area_struct *vpma)
{
	int pagenum;
	struct mm_struct *mm = vpma->current_mm;
	for (pagenum = 0; pagenum < vpma->pmo_ptr->size_in_pages; pagenum++) {
		if (PMO_TEST_IS_PREDICTED(vpma, pagenum) && 
				PMO_TEST_IS_FAULTED(vpma, pagenum))
			atomic64_inc(&mm->pmo_stats.accurate_predictions);

		else if (PMO_TEST_IS_PREDICTED(vpma, pagenum))
			atomic64_inc(&mm->pmo_stats.mispredict_no_faults);

		else if (PMO_TEST_IS_FAULTED(vpma, pagenum))
			atomic64_inc(&mm->pmo_stats.mispredict_faults);
	}
	return;

}

void pmo_destroy_shadow(struct vpma_area_struct *vpma,
		struct pmo_pages *head, char detach)
{
	struct pmo_pages *cursor, *temp;
	struct vm_area_struct *vma = vpma->vma;
	unsigned long int address, offset, page_count = 0;
	size_t pagenum;

	if (PMO_DRAM_IS_ENABLED())
		_pmo_populate_prediction_statistics(vpma);

	list_for_each_entry_safe(cursor, temp, &head->list, list) {
		address = cursor->faulted_address&PAGE_MASK;
		/* Change the protection from R/W to none... */

		change_protection(vma, address, address + PAGE_SIZE,
				vma->vm_page_prot, CP_FLAGS);
		offset = address - vma->vm_start;
		pagenum = offset/PAGE_SIZE;

		if(IS_ENABLED(CONFIG_PMO_NO_PREDICTION) || detach) {
			pmo_destroy_shadow_page(vpma, pagenum, true);
			list_del(&cursor->list);
			kfree(cursor);

		}
		else {
			if(pmo_page_should_destroy(vpma, pagenum)) 
				pmo_destroy_shadow_page(vpma, pagenum, 0);
			/* Or if it's already destroyed... */
			else if(PMO_PAGE_IS_DESTROYED(vpma, pagenum)) 
				pmo_towards_or_set_inert(vpma, pagenum);
		}

		page_count++;
	}
	pmo_barrier();
	return;
}
