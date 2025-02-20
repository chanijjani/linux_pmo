/*************************************************************************** 
 * Copyright (C) 2024 Derrick Greenspan and the University of Central      *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA.               *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY   *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or       *
 * FITNESS FOR A PARTICULAR PURPOSE.                                       *
 ***************************************************************************
 * Block handling (i.e., NVMe devices) for PMOs				   *
 ***************************************************************************/

#include "pmo.h"
struct file *PMO_FILE_PTR;
struct device *PMO_DEV_PTR;
void block_pmo_handle_init(void) 
{
	PMO_FILE_PTR = filp_open(NVME_NAME, O_RDWR, 0);
	metadata_start = 0;
	/* Let's hardcode this for now as 32GiB */
	metadata_end = 34359738368; 
	return;
}

void *pmo_block_get_header(__u64 pmo_start)
{
	/* what do? *
	size_t size_of_metadata_region = sizeof(union pmo_header) + 
		sizeof(__u64) + sizeof(struct pmo_entry) * MAX_NODES;
		*/

	void *header_buff = kvcalloc(4096, 1, GFP_KERNEL);
	loff_t pos = (loff_t) pmo_start;
	kernel_read(PMO_FILE_PTR, header_buff, 4096, &pos);
	return header_buff;
}
void block_pmo_handle_exit(void)
{
	return;
}

void * pmo_block_map(unsigned long int ptr, size_t size)
{
	loff_t pos = (loff_t) ptr;
	void *ret_ptr = kvcalloc(size, 1, GFP_KERNEL);
	kernel_read(PMO_FILE_PTR, ret_ptr, size, &pos);
	return ret_ptr;
}


void pmo_block_unmap(void *ptr)
{
	pmo_block_update_header();
	kvfree(ptr);
	return;
}

void _pmo_block_write_header(void * pmo_header)
{
	loff_t pos = (loff_t) metadata_start;
	kernel_write(PMO_FILE_PTR, pmo_header, 4096, &pos);
	return;
}

void pmo_block_update_metadata(struct vpma_area_struct *vpma)
{
	loff_t pos = (loff_t) djb2_hash(vpma->pmo_ptr->name);
	kernel_write(PMO_FILE_PTR, vpma->pmo_ptr, sizeof (struct pmo_entry), &pos);
	return;
}

void pmo_block_update_header(void)
{
	/* Update the header with new information */
	_pmo_block_write_header(header);
	vfs_fsync(PMO_FILE_PTR, 0);
	printk("Updated PMO block header\n");
	return;
}

struct pmo_entry * pmo_block_memremap(__u64 entry_id)
{

	loff_t start = metadata_start + sizeof(union pmo_header) + sizeof(__u64),
	       pos = start + sizeof(struct pmo_entry)*entry_id;

	struct pmo_entry *data = kvcalloc(sizeof(struct pmo_entry), 1, GFP_KERNEL);
	kernel_read(PMO_FILE_PTR, data, sizeof (struct pmo_entry), &pos);
	return data;	
}

