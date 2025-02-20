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


void get_sha256_hash(void *ret, void *data, size_t size)
{
          __maybe_unused struct crypto_shash *alg;
          __maybe_unused char digest[32];
	  if(!(PMO_WHOLE_IS_ENABLED() && PMO_IV_IS_ENABLED()))
		return;

          alg = crypto_alloc_shash("sha256", 0, 0);
          if(IS_ERR(alg))
                  printk("Could not allocate algorithm");

          calc_hash(alg, data, size, digest);
          memcpy_flushcache(ret, digest, 32);
          kvfree(alg);
          return;
}
