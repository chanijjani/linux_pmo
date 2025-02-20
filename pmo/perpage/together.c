#include "../pmo.h"


void _pmo_encrypt_together_cb(struct crypto_async_request *req, int err)
{
	struct pmo_async_struct *async_struct = req->data;
	struct vpma_area_struct *vpma = async_struct->vpma;
	size_t offset = async_struct->pagenum;

	pmo_sync(vpma->primary + offset, PAGE_SIZE);
	atomic_dec(&vpma->crypto.faulted_pages);
	if(PMO_IV_PSYNC_IS_ENABLED()) {
		pmo_assign_primary_hash(vpma, offset/PAGE_SIZE);
	}

	kvfree(async_struct);

	return;
}

void _pmo_encrypt_primary(struct vpma_area_struct *vpma,
		struct pmo_pages *cursor, struct skcipher_request *req,
		char *local_iv)
{
	struct vm_area_struct *vma = vpma->vma;
	unsigned long int address = cursor->faulted_address&PAGE_MASK,
		      	offset = address - vma->vm_start;

	struct pmo_async_struct *async_struct;
	void *primary = vpma->primary + offset, 
	     *shadow = vpma->shadow + offset;

	change_protection(vma, address, address + PAGE_SIZE,
			vma->vm_page_prot, CP_FLAGS);

       	async_struct = create_async_struct(vpma, cursor->pagenum, 0);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                       _pmo_encrypt_together_cb, async_struct);

	if(PMO_IV_PSYNC_IS_ENABLED()) 
		pmo_obtain_shadow_hash(vpma, cursor->pagenum/PAGE_SIZE);


        sg_init_one(&cursor->sg_primary, primary, PAGE_SIZE);
	sg_init_one(&cursor->sg_shadow, shadow, PAGE_SIZE);


	/* ENCRYPT PAGES */
       	skcipher_request_set_crypt(req, &cursor->sg_shadow,
			&cursor->sg_primary, PAGE_SIZE, local_iv);
	crypto_skcipher_encrypt(req);



	return;

}

void _pmo_destroy_shadow(struct vpma_area_struct *vpma,
		struct pmo_pages *cursor)
{
	struct vm_area_struct *vma = vpma->vma;
	unsigned long int address = cursor->faulted_address&PAGE_MASK,
		      offset = address - vma->vm_start;
	/*
	void *shadow = vpma->shadow + offset;
	memset(shadow, 0, PAGE_SIZE);
	pmo_sync(shadow, PAGE_SIZE);
	*/
	zap_vma_ptes(vma, vma->vm_start + offset, PAGE_SIZE);

	return;
}

void pmo_encrypt_primary_destroy_shadow(struct vpma_area_struct *vpma, struct pmo_pages *head)
{
	struct pmo_pages *cursor, *temp;
	struct crypto_skcipher *tfm = pmo_get_tfm(vpma);
	struct skcipher_request *req = skcipher_request_alloc(tfm, GFP_KERNEL);
	struct vm_area_struct *vma = vpma->vma;
	size_t pagenum;
	char local_iv[16];
	memcpy(local_iv, pmo_get_iv(vpma), 16);

	list_for_each_entry_safe(cursor, temp, &head->list, list) {
		pagenum = ((cursor->faulted_address&PAGE_MASK) - vma->vm_start)/PAGE_SIZE;
		if(PMO_IV_DETACH_IS_ENABLED()) {
			pmo_obtain_shadow_hash(vpma, pagenum);
			pmo_assign_primary_hash(vpma, pagenum);
		}
		_pmo_encrypt_primary(vpma, cursor, req, local_iv);
		zap_vma_ptes(vma, vma->vm_start + pagenum*PAGE_SIZE, PAGE_SIZE);
	}

	list_for_each_entry_safe(cursor, temp, &head->list, list) {
		pagenum = ((cursor->faulted_address&PAGE_MASK) - vma->vm_start)/PAGE_SIZE;
		if (PMO_BLOCK_IS_ENABLED()) {
			unsigned long int offset = pagenum * PAGE_SIZE;
			loff_t primary_pos = (loff_t)(vpma->phys_primary + offset);
			kernel_write(PMO_FILE_PTR, vpma->primary + offset, PAGE_SIZE, &primary_pos);
		}
		list_del(&cursor->list);
		kfree(cursor);
	}

	skcipher_request_free(req);
	pmo_barrier();
	return;
}


void pmo_handle_memcpy_sync_together(struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_shadow)
{
	void *primary = vpma->primary + pagenum * PAGE_SIZE,
	     *shadow = vpma->shadow + pagenum * PAGE_SIZE;
	memcpy_flushcache(primary, shadow, PAGE_SIZE);

	if (PMO_BLOCK_IS_ENABLED()) {
		loff_t phys_primary = vpma->phys_primary + pagenum * PAGE_SIZE;
		kernel_write(PMO_FILE_PTR, primary, PAGE_SIZE, &phys_primary);
	}
	return;
}


void pmo_handle_page_both(struct vpma_area_struct *vpma, size_t offset)
{
        void *primary = vpma->primary + offset,
             *shadow = vpma->shadow + offset;
        struct crypto_skcipher *tfm = vpma->crypto.tfm;
        struct skcipher_request *req = skcipher_request_alloc(tfm, GFP_KERNEL);
        struct scatterlist sg_primary, sg_shadow;
        char local_iv[16];
        DECLARE_COMPLETION(wait);

        memcpy(local_iv, vpma->crypto.pmo_iv, 16);

        skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                        pmo_decrypt_cb, &wait);

	if (PMO_BLOCK_IS_ENABLED()) {
		loff_t primary_pos = (loff_t)(vpma->phys_primary + offset);
		kernel_read(PMO_FILE_PTR, primary, PAGE_SIZE, &primary_pos);
	}
        sg_init_one(&sg_primary, primary, PAGE_SIZE);
        sg_init_one(&sg_shadow, shadow, PAGE_SIZE);

        skcipher_request_set_crypt(req, &sg_primary, &sg_shadow, PAGE_SIZE,
                        local_iv);
        crypto_skcipher_decrypt(req);
        wait_for_completion(&wait);

        pmo_sync(shadow, PAGE_SIZE);

        /* Copy changes back to primary */
        memcpy_flushcache(primary, shadow, PAGE_SIZE);

	if (PMO_BLOCK_IS_ENABLED()) {
		loff_t primary_pos = (loff_t)(vpma->phys_primary + offset);
		kernel_write(PMO_FILE_PTR, primary, PAGE_SIZE, &primary_pos);
	}
        skcipher_request_free(req);
	if (PMO_IV_IS_ENABLED())
	        handle_pmo_hash_identical(vpma, shadow, offset/PAGE_SIZE);
        pmo_barrier();

        return;
}
