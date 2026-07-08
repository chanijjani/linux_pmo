/*****************************************************************************
 * Copyright (C) 2020 - 2026 Derrick Greenspan, Chanhee Lee, and the         *
 * University of Central Florida (UCF)					     *
 *****************************************************************************
 * PMO Checksum calculation						     *
 *****************************************************************************/

#include <crypto/hash.h>
#include <linux/ktime.h>
#include "../pmo.h"
#include "../checksum.h"


char *PMO_EMPTY_CHECKSUM;
struct pmo_sha256 *sha256_region;

/* Pre-allocated SHA-256 transform handle, shared across all verification
 * calls. crypto_shash (the algorithm handle) is safe to share across
 * threads; per-call state lives in the shash_desc allocated by calc_hash(). */
struct crypto_shash *pmo_shash_tfm;

/* Sensitivity-analysis knobs (exported via /proc/pmo/verify_cost_ns and
 * /proc/pmo/hash_algo).  pmo_verify_cost_ns adds a synthetic per-page
 * busy-wait so the verification cost can be swept as an independent
 * variable in the inline-vs-async-offload crossover study; pmo_hash_algo_name
 * records the active crypto_shash algorithm.  Both default to plain SHA-256
 * so behaviour is unchanged unless the knobs are written. */
int pmo_verify_cost_ns = 0;
char pmo_hash_algo_name[32] = "sha256";

/* Busy-wait for pmo_verify_cost_ns nanoseconds to emulate a more (or less)
 * expensive verification primitive.  Uses the monotonic clock so it is robust
 * for arbitrary durations; a no-op when the knob is 0 (the default). */
static inline void pmo_verify_inject_cost(void)
{
	u64 deadline;

	if (likely(pmo_verify_cost_ns <= 0))
		return;

	deadline = ktime_get_ns() + (u64)pmo_verify_cost_ns;
	while (ktime_get_ns() < deadline)
		cpu_relax();
}

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
        pmo_barrier();
        return;
}

/* Compute the active verification hash of a 4 KB PMO page and write the digest
 * to ret.  Uses the module-level pre-allocated transform to avoid per-call
 * crypto_alloc_shash overhead (which dominated measured verification cost).
 *
 * The per-page metadata slot is a fixed 32 bytes and every store/compare site
 * (memcpy_flushcache/memcmp) operates on all 32.  Algorithms whose digest is
 * shorter than 32 B (crc32c/md5/sha1/sha224) only fill the leading bytes, so we
 * zero the buffer first: the trailing pad is then a deterministic 0 on both the
 * store and the verify path, and the 32-byte comparison reflects true digest
 * equality instead of comparing uninitialized stack. */
void pmo_get_page_hash(void *ret, void *data)
{
        char digest[32] = { 0 };

        if (unlikely(IS_ERR_OR_NULL(pmo_shash_tfm))) {
                printk(KERN_ERR "pmo_shash_tfm not initialized\n");
                return;
        }

        calc_hash(pmo_shash_tfm, data, PAGE_SIZE, digest);
        pmo_verify_inject_cost();
        memcpy_flushcache(ret, digest, 32);
        return;
}

/* Swap the active verification algorithm at runtime.  Allocates the new
 * crypto_shash first and rejects any algorithm whose digest exceeds the
 * 32-byte per-page metadata slot (so e.g. crc32c/md5/sha1/sha224/sha256 are
 * accepted but sha512 is not), then frees the old handle.  Intended to be set
 * while the system is idle between sweep points. Returns 0 on success. */
int pmo_set_hash_algo(const char *name)
{
        struct crypto_shash *new_tfm, *old_tfm;
        char clean[32];
        size_t i;

        /* Copy and strip a trailing newline / whitespace from the procfs write. */
        strscpy(clean, name, sizeof(clean));
        for (i = 0; i < sizeof(clean) && clean[i]; i++) {
                if (clean[i] == '\n' || clean[i] == '\r' || clean[i] == ' ') {
                        clean[i] = 0;
                        break;
                }
        }
        if (clean[0] == 0)
                return -EINVAL;

        new_tfm = crypto_alloc_shash(clean, 0, 0);
        if (IS_ERR(new_tfm)) {
                printk(KERN_ERR "PMO: could not allocate '%s' tfm: %ld\n",
                       clean, PTR_ERR(new_tfm));
                return PTR_ERR(new_tfm);
        }

        if (crypto_shash_digestsize(new_tfm) > 32) {
                printk(KERN_ERR "PMO: algo '%s' digest %u > 32 B, rejected\n",
                       clean, crypto_shash_digestsize(new_tfm));
                crypto_free_shash(new_tfm);
                return -EINVAL;
        }

        old_tfm = pmo_shash_tfm;
        pmo_shash_tfm = new_tfm;
        if (old_tfm && !IS_ERR(old_tfm))
                crypto_free_shash(old_tfm);

        strscpy(pmo_hash_algo_name, clean, sizeof(pmo_hash_algo_name));
        printk(KERN_INFO "PMO: verification algorithm set to '%s' (digest %u B)\n",
               pmo_hash_algo_name, crypto_shash_digestsize(pmo_shash_tfm));
        return 0;
}

void pmo_initialize_checksum(void)
{
        PMO_EMPTY_CHECKSUM = kcalloc(sizeof(char), 32, GFP_KERNEL);
        memset(PMO_EMPTY_CHECKSUM, 0xFF, 32);

        pmo_shash_tfm = crypto_alloc_shash(pmo_hash_algo_name, 0, 0);
        if (IS_ERR(pmo_shash_tfm)) {
                printk(KERN_ERR "PMO: could not allocate '%s' tfm: %ld\n",
                       pmo_hash_algo_name, PTR_ERR(pmo_shash_tfm));
                pmo_shash_tfm = NULL;
        }
        return;
}

void pmo_cleanup_checksum(void)
{
        if (pmo_shash_tfm) {
                crypto_free_shash(pmo_shash_tfm);
                pmo_shash_tfm = NULL;
        }
        kfree(PMO_EMPTY_CHECKSUM);
        PMO_EMPTY_CHECKSUM = NULL;
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
	if (!PMO_ASYNC_CHECKSUM_IS_ENABLED()) 
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

	if (!PMO_ASYNC_CHECKSUM_IS_ENABLED()) {
                if (PMO_OLD_EAGER_FAULT_TOLERANCE()) {
                        memcpy_flushcache(OFFSET_TO_SHA(shadow_sha_offset), sha256hash,
                                32);
                        pmo_barrier();
                }
                pmo_stats_stop_page_iv(&mm->pmo_stats);
                if (atomic64_read(&mm->pmo_stats.page_iv) > 0)
                        trace_printk("[[Page-IV_start:%lld,Page-IV_end:%lld]]\n",
                                        mm->pmo_stats.page_iv_start,
                                        atomic64_read(&mm->pmo_stats.page_iv));
	}

	if (PMO_GET_ASYNC_WOKRER_NUM() == 1) {
                trace_printk("[OLD] Park the verification thread\n");
		kthread_park(vpma->working_data[page_offset].verify_thread);
        }

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

