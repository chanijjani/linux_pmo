/*****************************************************************************
 * Copyright (C) 2020 - 2023 Derrick Greenspan and the University of Central *
 * Florida (UCF)							     *
 *****************************************************************************
 * Hashing for placing PMOs metadata in unique locations.		     *
 *****************************************************************************/

#include <crypto/hash.h>
#include "pmo.h"


/***********
 * HASHING *
 ***********/

/* See this: https://www.kernel.org/doc/html/v5.13/crypto/api-samples.html */
struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}


