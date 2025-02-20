/*************************************************************************** 
 * Copyright (C) 2021-2022 Derrick Greenspan and the University of Central *
 * Florida (UCF).                                                          *  
 ***************************************************************************
 * Virtual Persistent Memory Area (VPMA) implementation.		   *
 ***************************************************************************/

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <crypto/skcipher.h>
#include "pagewalk.h"
#include "nopagewalk.h"
#include "pmo.h"

/* Look for the associated VPMA, if one exists */
struct vpma_area_struct *vpma_search(struct rb_root *root, char *name)
{
          struct vpma_area_struct *data;
	  int result;
          struct rb_node *node = root->rb_node;

          while(node) {
		  data = container_of(node, struct vpma_area_struct, node);
		  result = strcmp(name, data->name);

		  if(result < 0)
			  node = node->rb_left;
		  else if(result > 0)
			  node = node->rb_right;
		  else
			  return data;
          }
          return NULL;
}

/*  Insert into the red-black tree, a new VPMA  */
int vpma_insert(struct rb_root *root, struct vpma_area_struct *data)
{
	int result;
        struct vpma_area_struct *this;
        struct rb_node **new = &(root->rb_node), *parent = NULL;

        while(*new) {
		this = container_of(*new, struct vpma_area_struct, node);
		result = strcmp(data->name, this->name);

		parent = *new;
		if(result < 0)
			new = &((*new)->rb_left);
                else if(result > 0)
                        new = &((*new)->rb_right);
                else
                	return 0;
          }

          /* Add a new node and then rebalance the tree */
          rb_link_node(&data->node, parent, new);
          rb_insert_color(&data->node, root);

          return 1;
}

void zap_vpmas(struct rb_root *root)
{
	struct rb_node *node = root->rb_node;
	struct vpma_area_struct *data;
	int i;
	if (IS_ENABLED(CONFIG_PMO_TRACK_EXPOSED_PAGES))
		printk("Statistical information for %s follows\n", current->comm);
	while(!RB_EMPTY_ROOT(root)) {
		data = container_of(node,struct vpma_area_struct, node);

		mmap_read_lock(data->current_mm);
		down_write(&data->pm_sem);
		pmo_handle_abend(data, data->vma->vm_start); 
		dump_coverage_statistics(data);

		if (PMO_PRED_IS_ENABLED()) {
			pmo_invalidate_working(data, true);
			kvfree (data->working_data);
		}

		/* We would have called this earlier, but since the shadow
		 * contains an encrypted copy of the page, it hardly seems necessary */
		for (i = 0; i < data->pmo_ptr->size_in_pages; i++) {
			if (PMO_DRAM_IS_ENABLED()) {
				memset(data->shadow + i * PAGE_SIZE, 0, PAGE_SIZE);
				pmo_sync(data->shadow + i * PAGE_SIZE, PAGE_SIZE);
			}
		}

		rb_erase(&data->node, root);
		pmo_crypto_zap_skcipher(data);
		kvfree(data->faulted_pages_ll);
		kvfree(data->prediction);
		kvfree(data->lock_page);
		kvfree(data->destroyed);
		up_write(&data->pm_sem);
		mmap_read_unlock(data->current_mm);
		vpma_clear(data);
		node = rb_first(root);
	}
	return;
}
/* Initialize a vpma 
 ******************************************************************************
 * Important to note: we do not support subsets of a PMO in the library, but  *
 * the code is available in case we would like to focus on that in the future.*
 ******************************************************************************/
struct vpma_area_struct * create_vpma_for_pmo(__u64 address, __u64 size, 
		char *name, char *subset_name, char prot_type, char *key)
{
	struct vpma_area_struct *vpma;
	struct mm_struct *mm = current->mm;
	struct pmo_entry *pmo;
	char local_key[64];
	int i;
	memset(local_key, 0, 64);
	strncpy(local_key, key, 64);

//	mmap_write_lock(mm);
	vpma = kmem_cache_alloc(pmo_area_cachep, GFP_KERNEL);
	if(!vpma) {
		printk("Could not allocate PMA!\n");
		vpma = ERR_PTR(-ENOMEM);
		goto out_unlock;
	}

	/* Initialize the pmo semaphore */
	init_rwsem(&vpma->pm_sem);
	down_write(&vpma->pm_sem);

	pmo = radix_tree_lookup(&pmo_radix_tree, djb2_hash(name));

	if(!pmo)
		pmo = get_pmo_from_name(name);

	if(!pmo) {
		printk(KERN_WARNING "PMO %s does not exist!\n", name);
		vpma = ERR_PTR(-ENOENT);
		goto out_unlock;
	}
	
	vpma_init(vpma);
	pmo_set_key(vpma, key);

	vpma->pmo_ptr = pmo;
	vpma->vma = create_vma_for_pmo(size, pmo->pm_primary * PAGE_SIZE,
			prot_type);
        vpma->vma->vpma = vpma;

	strcpy(vpma->name, subset_name);

	vpma->calling_pid = current->tgid;
	vpma->prediction = kvcalloc(sizeof(atomic_t), size/PAGE_SIZE, GFP_KERNEL);
	vpma->destroyed = kvcalloc(sizeof(atomic_t), size/PAGE_SIZE, GFP_KERNEL);

	vpma->lock_page = kvcalloc(sizeof(struct mutex), size/PAGE_SIZE, GFP_KERNEL);;
	for (i = 0; i < size/PAGE_SIZE; i++)
		mutex_init(&vpma->lock_page[i]);
	atomic_set(&vpma->fault_order, 0);

        /* Kernel mapping of persistent memory.
	 * Always mapped, regardless if read or write. */
	vpma->phys_primary = address;

	/* TODO: Here, we can either use kern_read() or kern_write(), or we can
	 * use a kernel level mmap call (if there is such a thing). Either way,
	 * we can't really use memremap() if we're not using DAX */
        vpma->primary = pmo_map(vpma->phys_primary, PAGE_ALIGN(size));

	vpma->type = prot_type;

	/* Initialize crypto specific things */
	vpma_init_crypto(vpma, local_key);
	pmo_set_iv(vpma, pmo->iv);
	pmo_initialize_detach_thread(vpma);
	pmo_initialize_decryptahead_thread(vpma);


	if (PMO_MARKOV_IS_ENABLED()) {
		pmo_initialize_markov_chain(vpma, size/PAGE_SIZE);
		printk("Initialized markov\n");
	}
	else if (PMO_STRIDE_IS_ENABLED()) {
		pmo_initialize_stride_chain(vpma, size/PAGE_SIZE);
		printk("Initialized stride\n");
	}

        vpma_insert(&(mm->pmo_rb), vpma);

out_unlock:
	up_write(&vpma->pm_sem);
	//mmap_write_unlock(mm);
	return vpma;
}

struct vm_area_struct *create_vma_for_pmo(__u64 size, __u64 pmo_address,
	       	char prot_type)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int ret;

	mm = current->mm;

	vma = vm_area_alloc(mm);

	if(unlikely(vma == NULL))
		return ERR_PTR(-ENOMEM);

	vma->vm_start = get_unmapped_pmo_area(pmo_address);
	BUG_ON(IS_ERR_VALUE(vma->vm_start));

	vma->vm_end = vma->vm_start + PAGE_ALIGN(size);
	/* FIXME -- not sure if this will work; if not, we'll have to change
	 * the permissions of all the pages at detach time */
	vma->vm_flags = (VM_MAYSHARE | VM_SHARED | VM_NOHUGEPAGE)&~(VM_READ|VM_WRITE|VM_EXEC);

        vma->vm_pgoff = vma->vm_start >> PAGE_SHIFT;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

	vma->vm_file = NULL;
        vma->vm_ops = NULL;
        vma->vm_private_data = NULL;
        /* Link the VMA in with insert_vm_struct */
	ret = insert_vm_struct(mm, vma);

	if(ret)
	{
		printk(KERN_ERR "NO MEM AVAILABLE FOR INSERT!\n");
		vm_area_free(vma);
		return ERR_PTR(ret);
	}

        /* New VMA must get soft dirty flag to prevent SIGSEGV */
        vma_set_page_prot(vma);
        change_protection(vma, vma->vm_start, vma->vm_end, vma->vm_page_prot,
			CP_FLAGS);

	return vma;
}


void pmo_invalidate_page (struct vpma_area_struct *vpma,
		unsigned long int pagenum, bool is_exiting)
{
	/*
	WARN_ON(!is_exiting && PMO_PRED_IS_ENABLED() && 
			!vpma->working_data[pagenum].phys_addr);
			*/
	if (PMO_NOPRED_IS_ENABLED() || !vpma->working_data[pagenum].phys_addr)
		return; /* Nothing to do */

	memset (vpma->working_data[pagenum].vaddr, 0, PAGE_SIZE);

	if (PMO_PRED_IS_ENABLED()) {
		PMO_CLEAR_IS_FAULTED(vpma, pagenum);
		PMO_CLEAR_IS_PREDICTED(vpma, pagenum);
		PMO_CLEAR_IS_HANDLED(vpma, pagenum);
		PMO_CLEAR_PAGE_TIMELY(vpma, pagenum);
		PMO_CLEAR_WAITING_HANDLED(vpma, pagenum);
	}

	if (is_exiting && PMO_DRAM_IS_ENABLED()) 
		free_page ((unsigned long int)vpma->working_data[pagenum].vaddr);

	/*
	if (PMO_DRAM_AS_BUFFER_IS_ENABLED())
		PMO_CLEAR_PAGE_IN_BUFFER(vpma, pagenum);

	if (PMO_PRED_IS_ENABLED()) {
		vpma->working_data[pagenum].vaddr = 0;
		vpma->working_data[pagenum].phys_addr = 0;
	}
		*/
	return;
}

void pmo_invalidate_working (struct vpma_area_struct *vpma, bool is_exiting)
{

	int i;
	for (i = 0; i < vpma->pmo_ptr->size_in_pages; i++)
		pmo_invalidate_page (vpma, i, is_exiting);
	return;
}
