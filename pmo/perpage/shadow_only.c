/*************************************************************************** 
 * Copyright (C) 2021-2023 Derrick Greenspan and the University of Central *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * Crypto handling							   *
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
#include "../../mm/internal.h"
#include "../pmo.h"
#include "../crypto.h"



void _pmo_encrypt_cb(struct crypto_async_request *req, int err)
{
	struct pmo_async_struct *async_struct = req->data;
	struct vpma_area_struct *vpma = async_struct->vpma;
	size_t pagenum = async_struct->pagenum; 
	void *primary = vpma->primary + pagenum * PAGE_SIZE,
	     *shadow = vpma->shadow + pagenum * PAGE_SIZE;

	

	pmo_sync(primary, PAGE_SIZE);
	



	/* Atomically decrement a variable indicating how many pages have been
	 * synchronized, and wake up the completion to inform flushcache of 
	 * that fact. */
	pmo_dec_encrypted_pages(vpma);
	wake_up(&vpma->crypto.encrypt_wq);

	/* FIXME: should pmo_barrier() be called here? */
	if(PMO_IV_PSYNC_IS_ENABLED()) {
		if (PMO_ASYNC_CHECKSUM_IS_ENABLED())
			pmo_async_obtain_primary_hash(vpma, pagenum);
		else
			pmo_assign_primary_hash(vpma, pagenum);

	}
	/* Finally free the async struct */
	kvfree(async_struct);
	return;
}

void pmo_handle_memcpy_sync_shadow_only(struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_shadow)
{
	struct pmo_async_struct *async_struct;

	async_struct = create_async_struct(vpma, pagenum, 0); 
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
			_pmo_encrypt_cb, async_struct);

	/* ENCRYPT PAGES */
	skcipher_request_set_crypt(req, sg_shadow, sg_primary, PAGE_SIZE,
			local_iv);
	crypto_skcipher_encrypt(req);

	return;
}

void _pmo_handle_page_shadow_blk (struct vpma_area_struct *vpma, size_t offset)
{

	void *shadow = vpma->shadow + offset; 
	loff_t shadow_pos = (loff_t) (vpma->phys_shadow + offset);

	kernel_write(PMO_FILE_PTR, shadow, PAGE_SIZE, &shadow_pos);
//	vfs_fsync_range(PMO_FILE_PTR, shadow, shadow + PAGE_SIZE, false);

	return;
}
void pmo_handle_page_shadow(struct vpma_area_struct *vpma, size_t offset)
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

	/* Perform verification now */
	if (PMO_PPs_IS_ENABLED() && PMO_IV_DETACH_IS_ENABLED())
		handle_pmo_hash_identical(vpma, primary, offset/PAGE_SIZE,
				PMO_ASYNC_CHECKSUM_IS_ENABLED());

        wait_for_completion(&wait);


        pmo_barrier();

        skcipher_request_free(req);

	if (PMO_IV_IS_ENABLED() && !(PMO_PPs_IS_ENABLED() && PMO_IV_DETACH_IS_ENABLED()))
        	handle_pmo_hash_identical(vpma, shadow, offset/PAGE_SIZE,
				PMO_ASYNC_CHECKSUM_IS_ENABLED());

        return;

}

struct _pmo_pmem_crypto_struct 
{
	struct vpma_area_struct *vpma;
	unsigned long int pagenum;
};

struct _pmo_pmem_crypto_struct *_create_pmem_crypto_struct(
		struct vpma_area_struct *vpma, unsigned long long int pagenum)
{
	struct _pmo_pmem_crypto_struct *struct_to_ret = 
		kvmalloc (sizeof(struct _pmo_pmem_crypto_struct), GFP_KERNEL);

	struct_to_ret->vpma = vpma;
	struct_to_ret->pagenum =pagenum;
	return struct_to_ret;
}

void _pmo_decrypt_pmem_cb (struct crypto_async_request *req, int err)
{
	struct _pmo_pmem_crypto_struct *crypto_struct = req->data;
	struct vpma_area_struct *vpma = crypto_struct->vpma;
	unsigned long int pagenum = crypto_struct->pagenum;

	pmo_sync(vpma->shadow + pagenum * PAGE_SIZE, PAGE_SIZE);
	pmo_barrier();

	/* TODO: Set flag to indicate decryption finished */

	pmo_insert_faulted_pages(vpma, pagenum * PAGE_SIZE);

	PMO_PAGE_UNLOCK(vpma, pagenum);

	kvfree(crypto_struct);

	return;
}

void _pmo_handle_page_pmem_prediction(struct skcipher_request *req,
		struct vpma_area_struct *vpma, char *local_iv,
                struct scatterlist *sg_primary,struct scatterlist *sg_shadow,
	       	unsigned long int pagenum)
{
	struct _pmo_pmem_crypto_struct *_pmem_crypto_struct = 
		_create_pmem_crypto_struct(vpma, pagenum);

	/* Decrypt from the primary into the shadow */
	skcipher_request_set_callback (req, CRYPTO_TFM_REQ_MAY_BACKLOG,
			_pmo_decrypt_pmem_cb, (void *) _pmem_crypto_struct);
	
	/* Tell the skcipher request to decrypt */
	skcipher_request_set_crypt (req, sg_primary, sg_shadow, PAGE_SIZE,
			local_iv);

	/* Perform the decryption */
	crypto_skcipher_decrypt (req);
	return;
}

void pmo_init_pmem_working_data (struct vpma_area_struct *vpma, unsigned long pagenum)
{
	vpma->working_data[pagenum].phys_addr = vpma->phys_shadow +  pagenum * PAGE_SIZE;
	vpma->working_data[pagenum].vaddr = vpma->shadow + pagenum * PAGE_SIZE;

	sg_init_one(&vpma->working_data[pagenum].sg_shadow,
			vpma->working_data[pagenum].vaddr, PAGE_SIZE);

	return;
}

