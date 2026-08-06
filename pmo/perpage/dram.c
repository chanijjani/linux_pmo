#include "../pmo.h"

struct _pmo_dram_crypto_struct 
{
	struct vpma_area_struct *vpma;
	struct pmo_pages *sentinel;
	unsigned long int pagenum;
};

struct _pmo_dram_crypto_struct *_create_dram_crypto_struct(
		struct vpma_area_struct *vpma, struct pmo_pages *sentinel,
		unsigned long int pagenum)
{
	struct _pmo_dram_crypto_struct *struct_to_ret = 
		kvmalloc (sizeof(struct _pmo_dram_crypto_struct), GFP_KERNEL);

	struct_to_ret->vpma = vpma;
	struct_to_ret->sentinel = sentinel;
	struct_to_ret->pagenum = pagenum;

	return struct_to_ret;
}

void _pmo_dram_pred_handler(struct vpma_area_struct *vpma, unsigned long int pagenum)
{
	pmo_insert_faulted_pages(vpma, pagenum * PAGE_SIZE);
	PMO_SET_PAGE_TIMELY(vpma, pagenum);
	PMO_PAGE_UNLOCK(vpma, pagenum);
	return;
}

void _pmo_decrypt_dram_cb (struct crypto_async_request *req, int err)
{
	struct _pmo_dram_crypto_struct *crypto_struct = req->data;
	struct vpma_area_struct *vpma = crypto_struct->vpma;
	unsigned long int pagenum = crypto_struct->pagenum;

	_pmo_dram_pred_handler(vpma, pagenum);
	kvfree(crypto_struct);

	return;
}

void pmo_handle_page_prediction_noenc(struct vpma_area_struct *vpma, unsigned long int pagenum)
{
	void *working = vpma->working_data[pagenum].vaddr,
	     *primary = vpma->primary + pagenum * PAGE_SIZE;

	
	/* Copy from the primary into the working set */
	memcpy(working, primary, PAGE_SIZE);

	/* Perform integrity verification ahead of time */
	if (PMO_IV_IS_ENABLED())
		handle_pmo_hash_identical (vpma, primary, pagenum, false);

	/* Unlock page */
	PMO_PAGE_UNLOCK(vpma, pagenum);
	return;
}


void _pmo_handle_page_dram_crypto_prediction(struct skcipher_request *req,
		struct vpma_area_struct *vpma, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_working,
		unsigned long int pagenum)
{
	void *working = vpma->working_data[pagenum].vaddr,
	     *primary = vpma->primary + pagenum*PAGE_SIZE;


	struct _pmo_dram_crypto_struct *_dram_crypto_struct = 
		_create_dram_crypto_struct(vpma, NULL, pagenum);

	/* Decrypt from the primary into the working set */
	skcipher_request_set_callback (req, CRYPTO_TFM_REQ_MAY_BACKLOG,
			_pmo_decrypt_dram_cb, (void *) _dram_crypto_struct);

	/* Decrypt pages */
	skcipher_request_set_crypt (req, sg_primary, sg_working, PAGE_SIZE,
			local_iv);

	crypto_skcipher_decrypt (req);
	/* Perform integrity verification ahead of time */
	if (PMO_IV_IS_ENABLED())
		handle_pmo_hash_identical (vpma, primary, pagenum,
				PMO_ASYNC_CHECKSUM_IS_ENABLED());

	return;
}



void _pmo_handle_page_dram_crypto_dram(struct vpma_area_struct *vpma, size_t offset)
{
	/* Decrypt from the primary into the working set */
	void *enc_working = vpma->working_data[offset/PAGE_SIZE].enc_addr,
	     *working = vpma->working_data[offset/PAGE_SIZE].vaddr;	

	struct crypto_skcipher *tfm = vpma->crypto.tfm;
	struct skcipher_request *req = skcipher_request_alloc(tfm, GFP_KERNEL);
	struct scatterlist sg_enc_working, sg_working;

	char local_iv[16];
	DECLARE_COMPLETION(wait);

	memcpy (local_iv, vpma->crypto.pmo_iv, 16);
	skcipher_request_set_callback (req, CRYPTO_TFM_REQ_MAY_BACKLOG,
			pmo_decrypt_cb, &wait);

	sg_init_one (&sg_enc_working, enc_working, PAGE_SIZE);
	sg_init_one (&sg_working, working, PAGE_SIZE);

	skcipher_request_set_crypt (req, &sg_enc_working, &sg_working, PAGE_SIZE,
			local_iv);

	crypto_skcipher_decrypt (req);
	wait_for_completion (&wait);

	skcipher_request_free (req);
	if (PMO_IV_IS_ENABLED())
		handle_pmo_hash_identical (vpma, working, offset/PAGE_SIZE,
				PMO_ASYNC_CHECKSUM_IS_ENABLED());

	return;
}




void _pmo_handle_page_dram_crypto(struct vpma_area_struct *vpma, unsigned long int offset)
{
	/* Decrypt from the primary into the working set */
	void *working = vpma->working_data[offset/PAGE_SIZE].vaddr,
	     *primary = vpma->primary + offset;

	struct crypto_skcipher *tfm = vpma->crypto.tfm;
	struct skcipher_request *req = skcipher_request_alloc(tfm, GFP_KERNEL);
	struct scatterlist sg_primary, sg_working;

	char local_iv[16];
	DECLARE_COMPLETION(wait);

	memcpy (local_iv, vpma->crypto.pmo_iv, 16);
	skcipher_request_set_callback (req, CRYPTO_TFM_REQ_MAY_BACKLOG,
			pmo_decrypt_cb, &wait);

	sg_init_one (&sg_primary, vpma->primary + offset, PAGE_SIZE);
	sg_init_one (&sg_working, working, PAGE_SIZE);

	skcipher_request_set_crypt (req, &sg_primary, &sg_working, PAGE_SIZE,
			local_iv);

	crypto_skcipher_decrypt (req);
	//wait_for_completion (&wait);

	skcipher_request_free (req);
	if (PMO_IV_IS_ENABLED())
		handle_pmo_hash_identical (vpma, primary, offset/PAGE_SIZE,
				PMO_ASYNC_CHECKSUM_IS_ENABLED());

	return;
}

void _pmo_handle_page_in_buffer(struct vpma_area_struct *vpma, unsigned long int offset)
{
	memcpy_flushcache(vpma->shadow + offset,
			vpma->working_data[offset/PAGE_SIZE].buff_addr,
			PAGE_SIZE);
	
	PMO_CLEAR_PAGE_IN_BUFFER(vpma, offset/PAGE_SIZE);
	memset(vpma->working_data[offset/PAGE_SIZE].buff_addr, 0, PAGE_SIZE);
	pmo_barrier();

	return;
}

void pmo_handle_page_dram(struct vpma_area_struct *vpma, unsigned long int offset)
{


	/* Check if we already have this page in DRAM */
	if (PMO_DRAM_AS_BUFFER_IS_ENABLED()) {	
	     	PMO_PAGE_IN_BUFFER(vpma, offset/PAGE_SIZE) ?
			_pmo_handle_page_in_buffer(vpma, offset):
			pmo_handle_page_shadow(vpma, offset); 

		return;
	}

	/* Encrypt into DRAM */
	if (PMO_ENCRYPT_IN_DRAM_IS_ENABLED()) {
		/* TODO: just pass in the cursor  */
		memcpy (vpma->working_data[offset/PAGE_SIZE].enc_addr,
				vpma->primary + offset, PAGE_SIZE);
		_pmo_handle_page_dram_crypto_dram(vpma, offset);
		return;
	}

	else if (PMO_NOENC_IS_ENABLED()) {
		memcpy(vpma->working_data[offset/PAGE_SIZE].vaddr,
				vpma->primary + offset, PAGE_SIZE);

		return;
	}
	else 
		_pmo_handle_page_dram_crypto(vpma, offset);
	return;
}

void _pmo_dram_encrypt_cb(struct crypto_async_request *req, int err)
{
        struct pmo_async_struct *async_struct = req->data;
        struct vpma_area_struct *vpma = async_struct->vpma;
        size_t pagenum = async_struct->pagenum;
        //, starttime = ktime_get_ns(), endtime;
        void *primary = vpma->primary + pagenum * PAGE_SIZE;

        pmo_sync(primary, PAGE_SIZE);

        /* FIXME: should pmo_barrier() be called here? */
        if(PMO_IV_PSYNC_IS_ENABLED()) {
		if (PMO_ASYNC_CHECKSUM_IS_ENABLED())
			pmo_async_obtain_primary_hash(vpma, pagenum);
		else
                	pmo_assign_primary_hash(vpma, pagenum);
	}

        /* Atomically decrement a variable indicating how many pages have been
         * synchronized, and wake up the completion to inform flushcache of
         * that fact. */
        pmo_dec_encrypted_pages(vpma);
        wake_up(&vpma->crypto.encrypt_wq);

        /* Finally free the async struct */
        kvfree(async_struct);
        return;
}


void pmo_handle_memcpy_sync_dram (struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_working)
{

        struct pmo_async_struct *async_struct;

        async_struct = create_async_struct(vpma, pagenum, 0); 
        skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                        _pmo_dram_encrypt_cb, async_struct);

        /* ENCRYPT PAGES */
        skcipher_request_set_crypt(req, sg_working, sg_primary, PAGE_SIZE,
                        local_iv);
        crypto_skcipher_encrypt(req);

	return;
}


/* If we're emulating a CXL system, we need to allocate from the far CXL node */
inline unsigned long pmo_numa_alloc_page_far(gfp_t gfp_mask)
{
	struct page *numa_page;
	int node = numa_mem_id() ? 0 : 1;

      	numa_page = __alloc_pages_node(node, __GFP_THISNODE | gfp_mask, 0);

	BUG_ON(!numa_page);
	return (unsigned long) page_address(numa_page);
}


void pmo_init_dram_working_data (struct vpma_area_struct *vpma, unsigned long pagenum)
{
	/*
	 * If the phys_addr hasn't been set yet, then that implies that
	 * working_data hasn't been alloced yet.
	 */
	vpma->working_data[pagenum].vaddr = 
		(PMO_GET_CXL_MODE() == PMO_LOCAL) ?
			(void *)__get_free_page(GFP_ATOMIC) : 
			(void *)pmo_numa_alloc_page_far(GFP_ATOMIC);
	BUG_ON(!vpma->working_data[pagenum].vaddr);

	vpma->working_data[pagenum].phys_addr = 
		virt_to_phys(vpma->working_data[pagenum].vaddr);

	sg_init_one(&vpma->working_data[pagenum].sg_working,
			vpma->working_data[pagenum].vaddr, PAGE_SIZE);

	return;
}

void pmo_handle_dirty_dram (struct vpma_area_struct *vpma, unsigned long offset)
{
	/* Copy from the working set to the shadow */
	void *shadow = vpma->shadow + offset,
	     *working = vpma->working_data[offset/PAGE_SIZE].vaddr;

	struct crypto_skcipher *tfm = vpma->crypto.tfm;
	struct skcipher_request *req = skcipher_request_alloc(tfm, GFP_KERNEL);
	struct scatterlist sg_shadow, sg_working;

	char local_iv[16];
	DECLARE_COMPLETION(wait);

	memcpy (local_iv, vpma->crypto.pmo_iv, 16);
	skcipher_request_set_callback (req, CRYPTO_TFM_REQ_MAY_BACKLOG,
			pmo_decrypt_cb, &wait);

	sg_init_one (&sg_shadow, shadow, PAGE_SIZE);
	sg_init_one (&sg_working, working, PAGE_SIZE);

	skcipher_request_set_crypt (req, &sg_working, &sg_shadow, PAGE_SIZE,
			local_iv);

	crypto_skcipher_encrypt (req);
	wait_for_completion (&wait);

	skcipher_request_free (req);

	handle_pmo_hash_identical (vpma, working, offset/PAGE_SIZE,
			PMO_ASYNC_CHECKSUM_IS_ENABLED());
	/* FIXME: do this in a chain instead of waiting for each to complete */
	return;
}

