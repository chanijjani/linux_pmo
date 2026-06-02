/*
 * Copyright (C) 2022-2026 Derrick Greenspan, Chanhee Lee and the University
 * of Central Florida (UCF).                                                           
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
          char digest[32];
	  if(!(PMO_WHOLE_IS_ENABLED() && PMO_IV_IS_ENABLED()))
		return;

          if (unlikely(IS_ERR_OR_NULL(pmo_shash_tfm))) {
                  printk(KERN_ERR "pmo_shash_tfm not initialized\n");
                  return;
          }

          calc_hash(pmo_shash_tfm, data, size, digest);
          memcpy_flushcache(ret, digest, 32);
          return;
}
