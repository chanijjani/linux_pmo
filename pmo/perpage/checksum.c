/*****************************************************************************
 * Copyright (C) 2020 - 2023 Derrick Greenspan and the University of Central *
 * Florida (UCF)							     *
 *****************************************************************************
 * PMO Checksum calculation						     *
 *****************************************************************************/

#include <crypto/hash.h>
#include "../pmo.h"
#include "../checksum.h"


char *PMO_EMPTY_CHECKSUM;
struct pmo_sha256 *sha256_region;

void pmo_obtain_shadow_hash(struct vpma_area_struct *vpma, size_t pagenum)
{
        size_t shadow_sha_offset;

	BUG_ON(!PMO_IV_IS_ENABLED());
        shadow_sha_offset = pmo_address_to_sha_offset(vpma->phys_shadow) + pagenum;

	/* It will be encrypted if detach and pps are true */
        pmo_get_page_hash(OFFSET_TO_SHA(shadow_sha_offset), 
			((PMO_IV_DETACH_IS_ENABLED() && PMO_PPs_IS_ENABLED()) ? 
			vpma->primary : vpma->shadow) + pagenum * PAGE_SIZE);

        pmo_barrier();
        return;
}

void pmo_assign_primary_hash(struct vpma_area_struct *vpma, size_t pagenum)
{
        size_t shadow_sha_offset = pmo_address_to_sha_offset(vpma->phys_shadow) + pagenum,
               primary_sha_offset = pmo_address_to_sha_offset(vpma->phys_primary) + pagenum;
	BUG_ON(!PMO_IV_IS_ENABLED());
        memcpy_flushcache(OFFSET_TO_SHA(primary_sha_offset),
                        OFFSET_TO_SHA(shadow_sha_offset), 32);
        //pmo_sync(OFFSET_TO_SHA(primary_sha_offset), 32);
        pmo_barrier();
        return;
}

void pmo_get_page_hash(void *ret, void *data)
{
        struct crypto_shash *alg = crypto_alloc_shash("sha256", 0, 0);
        char *digest = kvcalloc(sizeof(char), 32, GFP_KERNEL);
        if(IS_ERR(alg))
                printk("Could not allocate algorithm");

        calc_hash(alg, data, PAGE_SIZE, digest);
        memcpy_flushcache(ret, digest, 32);
        kvfree(alg);
        kvfree(digest);
        return;
}

char *PMO_EMPTY_CHECKSUM;
struct pmo_sha256 *sha256_region;

void pmo_initialize_checksum(void)
{
        PMO_EMPTY_CHECKSUM = kcalloc(sizeof(char), 32, GFP_KERNEL);
        memset(PMO_EMPTY_CHECKSUM, 0xFF, 32);
        return;
}

/* Check if the hash matches expected hash at fault time,
 * always returns 1 if checksums are disabled */
void handle_pmo_hash_identical(struct vpma_area_struct *vpma,
                void *_data, size_t page_offset, bool async)
{
        char sha256hash[32], buffer[33];
	volatile char mismatch = 0;
        size_t  primary_sha_offset =
                pmo_address_to_sha_offset(vpma->phys_primary) + page_offset,
                shadow_sha_offset =
                        pmo_address_to_sha_offset(vpma->phys_shadow) +
                        page_offset;
        struct mm_struct *mm = current->mm;

	/* Why was this called? */
	WARN_ON(!PMO_IV_IS_ENABLED());

	/* This makes no sense if this is an asynchronous call, because current
	 * is literally just the kernel thread */
	if (!async) 
        	pmo_stats_start_page_iv(&mm->pmo_stats);

        pmo_get_page_hash(sha256hash, _data);
        if (!PMO_CHECKSUMS_MATCH(sha256hash, primary_sha_offset) &&
                        !PMO_CHECKSUMS_MATCH(PMO_EMPTY_CHECKSUM, primary_sha_offset)) {
		mismatch = 1;
                printk(KERN_INFO "PMO hashes with offset %ld are not identical!",
                                page_offset);

		memcpy(buffer, sha256hash, 32);
		buffer[32] = 0;

		printk(KERN_INFO "Expected SHA was %s", buffer);

		memcpy(buffer, OFFSET_TO_SHA(shadow_sha_offset), 32);
		printk(KERN_INFO "But the ctual SHA was %s", buffer);
		printk(KERN_INFO "The PMO was probably not properly detached.\n");
		dump_stack();
        }

        if(memcmp(PMO_EMPTY_CHECKSUM, sha256hash, 32) == 0)
                memcpy_flushcache(vpma->shadow + page_offset * PAGE_SIZE,
                                ZEROED_PAGE, PAGE_SIZE);
        else
                memcpy_flushcache(OFFSET_TO_SHA(shadow_sha_offset), sha256hash,
                                32);

	if (!async) {
 	       pmo_stats_stop_page_iv(&mm->pmo_stats);
	       if (atomic64_read(&mm->pmo_stats.page_iv) > 0)
		       trace_printk("[[Page-IV_start:%lld,Page-IV_end:%lld]]",
				       mm->pmo_stats.page_iv_start,
				       atomic64_read(&mm->pmo_stats.page_iv));
	}

	if (async)
		kthread_park(vpma->working_data[page_offset].verify_thread);

        return;
}

void vpma_set_sha_ranges(struct vpma_area_struct *vpma)
{
        vpma->pmo_range.sha256_range_primary.start =
                pmo_address_to_sha_offset(vpma->phys_primary);
        vpma->pmo_range.sha256_range_primary.end =
                pmo_address_to_sha_offset(vpma->phys_primary) + vpma->attached_size/PAGE_SIZE;

        vpma->pmo_range.sha256_range_shadow.start =
                pmo_address_to_sha_offset(vpma->phys_shadow);
        vpma->pmo_range.sha256_range_shadow.end =
                pmo_address_to_sha_offset(vpma->phys_shadow) + vpma->attached_size/PAGE_SIZE;

        return;
}


void init_sha256_region(size_t start, size_t end)
{
        loff_t sha256_region_location = 
		(loff_t) (header->this.sha256_region_location + start);
        size_t sha256_region_size = header->this.pmo_region_location -
                       header->this.sha256_region_location;

	if (PMO_DAX_IS_ENABLED()) {
		BUG_ON(!PAGE_ALIGNED(sha256_region_location));
        	BUG_ON(sha256_region_location > end || sha256_region_location < start);
	}

        /* remap the address */
	if (PMO_DAX_IS_ENABLED())
		sha256_region = 
		 IS_ENABLED(CONFIG_X86) ?
		  ioremap_uc(sha256_region_location, sha256_region_size) :
		  ioremap(sha256_region_location + start, sha256_region_size);
	else 
		kernel_read(PMO_FILE_PTR, sha256_region, sha256_region_size,
				&sha256_region_location);


        sha256size = sha256_region_size;
        return;
}

