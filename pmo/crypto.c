/*************************************************************************** 
 * Copyright (C) 2023 Derrick Greenspan and the University of Central	   *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA.               *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY   *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or       *
 * FITNESS FOR A PARTICULAR PURPOSE.                                       *
 ***************************************************************************
 * PMO encryption functions.						   *
 ***************************************************************************/

#include "pmo.h"
#include "crypto.h"


inline void pmo_decrypt_cb(struct crypto_async_request *req, int err)
{

	complete (req->data);
	return;
}

void vpma_init_crypto(struct vpma_area_struct *vpma, char *key)
{
        atomic_set(&vpma->crypto.encrypted_pages, 0);
        atomic_set(&vpma->crypto.faulted_pages, 0);
        init_waitqueue_head(&vpma->crypto.encrypt_wq);
        vpma->crypto.tfm = crypto_alloc_skcipher("xts(aes)",
                        CRYPTO_ALG_TYPE_SKCIPHER, CRYPTO_ALG_ASYNC);
        crypto_skcipher_setkey(vpma->crypto.tfm, key, 64);
        return;
}



struct pmo_async_struct *create_async_struct(
                struct vpma_area_struct * vpma, size_t pagenum,
                char should_destroy) 
{
        struct pmo_async_struct *ret_struct =
                kvcalloc(sizeof(struct pmo_async_struct), 1, GFP_KERNEL);

        ret_struct->vpma = vpma;
        ret_struct->pagenum = pagenum;
        ret_struct->should_destroy = should_destroy;
        return ret_struct;
}
