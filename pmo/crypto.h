/*****************************************************************************
 * Copyright (C) 2021 - 2023 Derrick Greenspan and the University of Central *
 * Florida (UCF)                                                             *
 *****************************************************************************
 * PMO Cryptography header functions and structs                             *
 *****************************************************************************/

#ifndef __PMO_CRYPTO_H__
#define __PMO_CRYPTO_H__

struct pmo_encryption_struct {
        struct crypto_skcipher *tfm; /* The tfm for this VPMA */
        wait_queue_head_t encrypt_wq;
        atomic_t encrypted_pages;
        char enc_key[64], pmo_iv[16];
	atomic_t faulted_pages;
	struct pmo_pages *decrypt_queue_ll;
	struct task_struct *decryptahead_thread_ptr;
	
};
#endif
