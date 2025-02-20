/***************************************************************************
 * Copyright (C) 2024 Derrick Greenspan and the University of Central	   *
 * Florida (UCF).							   *
 ***************************************************************************
 * Initialization handling						   *
 ***************************************************************************/
#include "pmo.h"
#include "../drivers/dax/dax-private.h"

void __pmo_handle_init(void)
{
	if (PMO_DAX_IS_ENABLED())
		dax_pmo_handle_init();
	else
		block_pmo_handle_init();
	return;
}


/* Get the PMO Header region. */
union pmo_header *_pmo_header_get(__u64 pmo_start, __u64 pmo_end)
{
          /* Get header region */
          union pmo_header * header = PMO_DAX_IS_ENABLED() ?
		  pmo_dax_get_header(pmo_start):
		  pmo_block_get_header(pmo_start);
  
          if(!header)
                  goto err_no_mapping;
          else if(strncmp((char *) header, "PMO\0", 4) != 0)
                  goto no_header;
          else
                  return header;
  
          no_header:
	  	printk(KERN_WARNING "No PMO header exists!\n");
		return ERR_PTR(-ENOENT);
  
          err_no_mapping:
                  printk(KERN_ERR "Could not map 0x%llx!\n", pmo_start);
                  return ERR_PTR(-EFAULT);
}

void pmo_handle_init(bool init_proc) 
{
	pmo_area_cachep = KMEM_CACHE(vpma_area_struct, SLAB_PANIC|SLAB_ACCOUNT);

	if (init_proc)
		pmo_proc_init();

	printk("pmo_area_cachep is %llX\n",
			(long long unsigned int) pmo_area_cachep);

	
	/* If using DAX, this will be get_dev_dax_resource(DAX_NAME)->start/end
	 * Otherwise this will just be 0 and the end of the block device */ 
	__pmo_handle_init();

	header = _pmo_header_get(metadata_start, metadata_end);

	init_sha256_region(metadata_start, metadata_end);

	mutex_init(&pmo_system_mutex);
	atomic_inc(&header->this.boot_id);
	pmo_update_header();

	memset(ZEROED_PAGE, 0x00, PAGE_SIZE);
	pmo_initialize_checksum();
	pmo_print_config();

	return;
}


