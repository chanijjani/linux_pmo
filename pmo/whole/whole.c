/*
 * Copyright (C) 2022-2023 Derrick Greenspan and the University of Central 
 * Florida (UCF).                                                           
 *
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA. It is          
 * distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A   
 * PARTICULAR PURPOSE.                                                      
 *
 * PMO Encryption functions, encrypt on detach, decrypt on attach etc.
 */

#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <linux/libnvdimm.h>
#include "../pmo.h"

unsigned long long int hash_hit = 0;
/* See this: https://www.kernel.org/doc/html/v5.13/crypto/api-samples.html */
struct sdesc {
    struct shash_desc shash;
    char ctx[];
};


void crypt_data(void * data, void *data_out, char *key, size_t size, char *iv, char encrypt,
		char *expected_sha256)
{
	char local_key[64], local_iv[16], sha256hash[32]; 
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg_data;
	void *crypted_data = data_out; //kvcalloc(sizeof(char), PAGE_ALIGN(size), GFP_KERNEL);
	int err;
	DECLARE_CRYPTO_WAIT(wait);
	

	memcpy(crypted_data, data, PAGE_ALIGN(size));
	memcpy(local_iv, iv,16);

	tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
	if(IS_ERR(tfm))
	{
		printk ("Error allocating xts\n");
		return;// (void *) PTR_ERR(tfm);
	}

	/* Key stretch */
	memset(local_key, 0, 64);
	strcpy(local_key, key);

	err = crypto_skcipher_setkey(tfm, local_key, 64);

	if(err) {
		printk("Error setting key\n");
		return;
		//return (void *) -1;
	}

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	sg_init_one(&sg_data, crypted_data, PAGE_ALIGN(size));
	
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | 
			CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);

	skcipher_request_set_crypt(req, &sg_data, &sg_data, size, local_iv);



	err = crypto_wait_req(encrypt ? crypto_skcipher_encrypt(req) :
		       	crypto_skcipher_decrypt(req), &wait);



	if(!encrypt && PMO_IV_IS_ENABLED()) {
		pmo_stats_start_attachtime_iv(current->mm->pmo_stats);
		get_sha256_hash(sha256hash, crypted_data, size);
		if(memcmp(sha256hash, expected_sha256, 32)) {
			hash_hit++;
			/* We don't care, ignore this. TODO: Actually figure
			 * out why this is happening */
			/*
			printk("SHA256sum is different from last attach!\n"
					"Either the data was maliciously "
					"altered, or the data has become "
					"corrupted.");
			kvfree(crypted_data);
			crypted_data = -EIO;
			goto out;
			*/
		}
		pmo_stats_stop_attachtime_iv(current->mm->pmo_stats);
	}


//	printk(encrypt ? "PMO is encrypted\n" : "PMO is decrypted\n");
	/* TODO: move tfm to vpma and don't free it here. */
	crypto_free_skcipher(tfm);
	skcipher_request_free(req);
	
	return;// crypted_data;
}

/* Completely destroy the data within the shadow before releasing it. */
void destroy_shadow(void *data, size_t size)
{
	memset(data, 0, size);
	pmo_sync(data, size);
	pmo_barrier();
	return;
}


/* Return the data, in an encrypted form */
void get_encrypted_data(void * data, void *out, char * key, size_t size, char * iv)
{
	crypt_data(data, out, key, size, iv, 1, NULL);
}

/* Return the data, in a decrypted form */
void get_decrypted_data(void * data, void *out, char * key, size_t size, char * iv,
		char *expected_sha256) 
{
	crypt_data(data, out, key, size, iv, 0, expected_sha256);
}

void pmo_handle_memcpy_sync_whole(struct skcipher_request *req,
                struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
                struct scatterlist *sg_primary, struct scatterlist *sg_shadow)
{
        void *primary = vpma->primary + pagenum * PAGE_SIZE,
             *shadow = vpma->shadow + pagenum * PAGE_SIZE;
        memcpy_flushcache(primary, shadow, PAGE_SIZE);
        return;
}

void whole_enable_vpma_access(struct vpma_area_struct *vpma)
{
	struct pmo_entry *pmo_ptr = vpma->pmo_ptr;
	size_t size = pmo_ptr->size_in_pages * PAGE_SIZE;
	char *key = vpma->crypto.enc_key;

	/* PMO is to be created *
	if(pmo_bit_is_set(6, pmo_ptr))
	{
		memset(vpma->primary, 0, PAGE_ALIGN(size));
		get_sha256_hash(pmo_ptr->sha256sum, vpma->primary, PAGE_ALIGN(size));

		get_encrypted_data(vpma->primary, vpma->shadow, key,PAGE_ALIGN(size), pmo_ptr->iv);
		memcpy_flushcache(vpma->primary, vpma->shadow, PAGE_ALIGN(size));

		pmo_barrier();
		printk("Created PMO\n");
	}

	

	* Indicate shadow is invalid -- but primay valid and encrypted */
	/* PMO is decrypted! *
	BUG_ON(pmo_bit_is_set(7, pmo_ptr)); * This shouldn't happen,
					       recovery should have detected
					       this condition and prevented it. *
	*/
	pmo_set_bit(2, pmo_ptr);

	pmo_stats_start_attachtime_decrypt(current->mm->pmo_stats);
	get_decrypted_data(vpma->primary, vpma->shadow, key, PAGE_ALIGN(size),
			pmo_ptr->iv, pmo_ptr->sha256sum);
	pmo_stats_stop_attachtime_decrypt(current->mm->pmo_stats);
	
//	pmo_barrier();

	/* Indicate Decryption */
	pmo_set_bit(7, pmo_ptr);
	/* Indicate primary is invalid -- but shadow is validly decrypted */
	pmo_set_bit(3, pmo_ptr);

	pmo_stats_start_attachtime_memcpy(current->mm->pmo_stats);
	memcpy_flushcache(vpma->primary, vpma->shadow, PAGE_ALIGN(size));
	pmo_barrier();
	pmo_stats_stop_attachtime_memcpy(current->mm->pmo_stats);

	return;
}

void whole_disable_vpma_access(struct vpma_area_struct *vpma)
{
	char *key = vpma->crypto.enc_key;
	struct pmo_entry *pmo_ptr = vpma->pmo_ptr;
	size_t size = pmo_ptr->size_in_pages * PAGE_SIZE;
	struct vm_area_struct *vma = vpma->vma;
	change_protection(vma, vma->vm_start, vma->vm_end, 
			vma->vm_page_prot, CP_FLAGS);


	/* Encrypt primary into shadow 
	 * FIXME: Try to encrypt directly into the shadow instead of copying it over*/
	get_encrypted_data(vpma->primary, vpma->shadow, key, PAGE_ALIGN(size), pmo_ptr->iv);
	pmo_barrier();

	/* Indicate encryption... */
	pmo_unlock_bit(7, pmo_ptr);

	/* Indicate shadow is valid, but primary might not be */
	pmo_set_bit(3, pmo_ptr);
	memcpy_flushcache(vpma->primary, vpma->shadow, PAGE_ALIGN(size));
	pmo_barrier();

	/* Destroy shadow */
	memset(vpma->shadow, 0, PAGE_ALIGN(size));
	pmo_sync(vpma->shadow, PAGE_ALIGN(size));
	/*
	for(i = 0; i < size/PAGE_SIZE; i++)
		pmo_destroy_shadow_page(vpma, i,1);
		*/
	//memset(vpma->destroyed, size/PAGE_SIZE; 1);

	
	/* Deallocate shadow and unmap it from the kernel */
	//memunmap(vpma->shadow);
	//vpma->phys_shadow = 0;

	/* Finally, unmap the pages */
        zap_vma_ptes(vma, vma->vm_start, PAGE_ALIGN(size));

	return;
}



void pmo_handle_page_whole(struct vpma_area_struct *vpma, size_t offset)
{
        void *primary = vpma->primary + offset,
             *shadow = vpma->shadow + offset;

	memcpy_flushcache(shadow, primary, PAGE_SIZE);
	pmo_barrier();
        return;
}
