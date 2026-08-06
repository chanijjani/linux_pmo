/*************************************************************************** 
 * Copyright (C) 2021-2023 Derrick Greenspan and the University of Central *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * PMO Header								   *
 ***************************************************************************/

#ifndef __PMO_HEADER__
#define __PMO_HEADER__
#include <linux/mm_types.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/range.h>
#include <linux/proc_fs.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/rmap.h>
#include <linux/gfp.h>
#include <linux/radix-tree.h>
#include <linux/list.h>
#include <linux/kfifo.h>
#include <linux/libnvdimm.h>
#include <linux/scatterlist.h>
#include <linux/tracepoint.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include "pagewalk.h"
#include "nopagewalk.h"
#include "checksum.h"
#include "crypto.h"
#include "alloc.h"


/**************
 * STRUCTURES *
 **************/

#define MAX_NODES 16777215
#define DAX_NAME "dax0.0"
#define NVME_NAME "/dev/nvme0n1"
#define DISABLE_LOCKING 1

/* Macros */
#define IS_WRITE(x) test_and_set_bit(1, x)
#define IS_READ_OR_EXECUTE(x) !test_and_clear_bit(1, x)

#define IS_OCCUPIED(x) test_and_set_bit(0, x)
#define IS_UNOCCUPIED(x) test_and_clear_bit(0, x)

#define CP_FLAGS 0
#define DB_PERSIST 1
#define DB_CLEAR 2

#ifdef CONFIG_PMO_NO_PAGEWALK
#define PMO_ASSIGN_PAGE_INFO(vmf) \
	printk("Assigning page info for %llX\n", vmf->pte);\
	if(vmf->vma->vpma && vmf->pmo_page_info) { \
		vmf->pmo_page_info->pte = vmf->pte; \
		vmf->pmo_page_info->ptl = vmf->ptl; \
		printk("Did assign...\nWith pte %llX, ptl %llX\n",\
				vmf->pmo_page_info->pte, vmf->pmo_page_info->ptl); \
		complete(&vmf->pmo_page_info->pte_nonzero);\
	}\
	lse if(vmf->vma->vpma) \
	{\
		printk("Nothing to assign for %llX...VPMA: %llX, pageinfo: %llx\n", vmf->pte, vmf->vma->vpma, vmf->pmo_page_info);\
	}
#else
#define PMO_ASSIGN_PAGE_INFO(vmf)
#endif

#define pmo_unlock_bit(x, y) \
	clear_bit_unlock(x, (long unsigned int *) &y->state)

#define pmo_set_bit(x, y) \
	set_bit(x, (long unsigned int *)&y->state)

#define pmo_test_and_set(x, y) \
	test_and_set_bit(x, (long unsigned int*)&y->state)

#define pmo_test_and_lock(x, y) \
	test_and_set_bit_lock(x, (long unsigned int*)&y->state)

#define pmo_bit_is_set(x, y) \
	test_bit(x, (long unsigned int* )&y->state)

/* Formerly dax_start, dax_end */
extern __u64 metadata_start, metadata_end;
extern struct file *PMO_FILE_PTR;
extern struct device *PMO_DEV_PTR;

extern struct radix_tree_root pmo_radix_tree;
extern struct kmem_cache *pmo_area_cachep;
extern struct mutex pmo_system_mutex;

extern char *PMO_EMPTY_CHECKSUM;
extern union pmo_header *header;

extern char ZEROED_PAGE[PAGE_SIZE];

/* PROC */
void pmo_proc_init(void);
extern struct proc_dir_entry *pmo_proc_entry, *pmo_dram_entry,
       *pmo_pred_entry, *pmo_depth_entry, *pmo_debug_entry,
       *pmo_access_entry, *pmo_emulate_cxl_entry, *pmo_async_checksum_entry;

/* END PROC */

/* It doesn't make sense to have two separate structures that basically track
 * the same thing yet has different components. Merging them together makes the
 * no pagewalk simpler, as an added bonus */
struct pmo_pages
{
	struct list_head list;
	struct scatterlist sg_primary, sg_shadow, sg_working;
	unsigned long int faulted_address; /* The full faulting address of
					      the page */
	unsigned long int pagenum; /* Page number offset of the page from the
				      start of the PMO */

	/* TODO: Move this to a union */
	unsigned long pfn;
	pte_t *pte;
	spinlock_t *ptl;
	struct completion pte_nonzero;

	wait_queue_head_t wq;
	atomic_t pagecount;
};


#define PMO_CLEAR_WRITE 0x0
#define PMO_CLEAR_READWRITE 0x1

#define PMO_SHOULD_CLEAR_WRITE(x) (x->flags & PMO_CLEAR_WRITE)
#define PMO_SHOULD_CLEAR_READWRITE(x) (x->flags & PMO_CLEAR_READWRITE)
struct vpma_area_struct {
        char type;
        struct rb_node node;

	struct pmo_pages *faulted_pages_ll;

#ifdef CONFIG_PMO_NO_PAGEWALK
	/* This linked list is always a subset of faulted_pages_ll. 
	 * When we are *not* pagewalking, we build this linked list instead */
	struct pmo_pages *dirty_pages_ll;
#endif

        struct vm_area_struct *vma; /* The associated vma */
        struct pmo_entry *pmo_ptr; /* A pointer to the PMO metadata entry  */
        struct rw_semaphore pm_sem; /* semaphore allowing multiple threads to 
                                     * access the same vpma for reading, but
				     * only one for writing. Replaces 
				     * mmap_lock hold in most cases for 
				     * modifying the permissions */


        int calling_pid; /* Stores the calling PID -- detach will look at this 
			    to determine if it has permission to detach --
                            If the calling thread's PID does not match this,
			    then a detach will be rejected. This also is used 
			    in replacement to is_attached -- if the calling 
			    PID is less than 0, then it is in the detached 
			    state. No need to duplicate work.*/

        __u64 hash, attached_size, attached_offset;

	/* Pointers to the kernel memory of the PMO's primary and shadow */
       void *primary, *shadow;

	struct working_page {
		void *enc_addr;
		
		union {
			void *vaddr,
			     *buff_addr;
		};

		union {
			struct scatterlist sg_working,
					   sg_shadow;
		};
		struct scatterlist sg_primary;

		/* Flags are: 0 - IS FAULTED, 1 IS PREDICTED, 2 IS HANDLED */
		unsigned long phys_addr;
	        volatile long unsigned int flag;
		
		bool page_in_buffer;
	
		struct task_struct *verify_thread,
				   *shadowhash_thread,
				   *primaryhash_thread;
	} *working_data;

	/* I heard you like structs, so I nested a struct within a union within a
	 * struct inside another struct. */
	struct pmo_markov_table 
	{
		unsigned long int thread_id, page_count;
		atomic_t most_recent, last_page_accessed,
			 initialized;

		/* a linked list node of nested structs/unions */
		struct markov_node
		{
			spinlock_t lock;
			atomic_t initialized, weight;
			struct list_head list;
			/* The markov data */
			union markov_data {
				/* An individual address, for address transitions */
				struct pmo_page_addresses {
					size_t x, y;
				} address;

				/* Strides, for strides */
				struct pmo_stride_data {
					size_t value;
					bool is_negative;
				} stride;
			} data;
		}*markov_positive_weights, *markov_negative_weights;
		struct markov_node *markov_weights_middle;
	} markov_table;

	bool has_predict_entries, is_pmo;
	struct mm_struct *current_mm; /* A pointer to the current mm */

        __u64 phys_primary, phys_shadow;

        struct mutex psync_mutex; /* This mutex ensures that only one thread 
				     will synchronize; other threads will wait. */
        struct mutex page_mutex;

	/* Struct of sha256 range when using integrity verification */
	struct pmo_range_struct pmo_range;


	/* Struct of additional fields for encryption */
	struct pmo_encryption_struct crypto;

#ifdef CONFIG_PMO_TRACK_EXPOSED_PAGES
	atomic_t total_predictions, mispredict, exposed_pages;
#endif

#ifdef CONFIG_PMO_NONBLOCKING
	struct task_struct *disable_thread;
#endif


#ifdef CONFIG_PMO_NONBLOCKING_CHECKSUM_SYNC
	struct task_struct *checksum_sync_thread;
#endif

	struct mutex *lock_page;
	atomic_t *destroyed, *prediction, fault_order;
	/* PMO name */
        char name[50], flags;
};

#ifdef CONFIG_PMO_NONBLOCKING
#define pmo_kill_disable_thread(vpma) \
	kthread_stop(vpma->disable_thread)
//	put_task_struct(vpma->disable_thread)
#else
#define pmo_kill_disable_thread(vpma) 
#endif

/* Each PFN is either occupied or unoccupied; if occupied, it cannot be
 * used for a shadow or a primary PMO.*/
struct pmo_entry {

	/* Use test_and_set_bit on state. Macros should be provided. 
	 *
	 * 1 0 - read/execute (treated the same)
	 * 1 1 - write
	 * 0 ** - unoccupied
	 *
	 * if LSB (bit 0) == 0 -- unoccupied
	 * if LSB (bit 0) == 1 -- occupied
	 *
	 * if 2nd (bit 1) == 0 -- read
	 * if 2nd (bit 1) == 1 -- write
	 *
	 * if 3rd (bit 2) == 0 -- data in primary is valid
	 * if 3rd (bit 2) == 1 -- in the process of memcpying to shadow
	 *
	 * if 4th (bit 3) == 0 -- data in shadow is valid
	 * if 4th (bit 3) == 1 -- in the process of memcpying to primary
	 *
	 * if 5th (bit 4) == 0 -- unsecure
	 * if 5th (bit 4) == 1 -- secure
	 *
	 * if 6th (bit 5) == 0 -- state is as indicated by 5th bit
	 * if 6th (bit 5) == 1 -- state is unknown (ignore 5th bit)
	 *
	 * if 7th (bit 6) == 0 -- PMO is old
	 * if 7th (bit 6) == 1 -- PMO is new
	 *
	 * if 8th (bit 7) == 0 -- PMO is encrypted
	 * if 8th (bit 7) == 1 -- PMO is decrypted
	 */

	/* Packing these things is annoying */
	unsigned char state; /* 1 byte */

	char sha256sum[32]; /* Only for whole case */
	char name[27]; 

	/* Physical address of PMO from start of PMEM -- should be PFN */
        __u32 size_in_pages, /* 4 bytes */
	      pm_primary, /* 40 bytes */
	      pm_shadow; /* 44 bytes -
			    Location of the PMO shadow, is 0 after detach*/

	atomic_t pid, 
		 boot_id;

	/* 16 bytes (?) */

	
	char iv[16];
	/* 16 bytes */

	/* additional fields if using PMO alloc */
};

struct pmo_async_struct {
	struct vpma_area_struct *vpma;
	size_t pagenum;
	/* Did we invalidate this PTE? If so, we need to destroy it.
	 * This is always true if using paranoid mode, and always false
	 * if not using paranoid or predictive encryption */
	char should_destroy; 
};

#ifdef CONFIG_PMO_DEBUG_REPORTING
#define pmo_debug_print_pagecount(num_pages) \
	printk(KERN_INFO "Number of pages at this psync were %lld\n", num_pages)
#else
#define pmo_debug_print_pagecount(num_pages) 
#endif
void pmo_debug_print_faulting_page(unsigned long int phys, unsigned long int virt);


#ifdef CONFIG_PMO_STATS_REPORTING
void pmo_dump_stats(struct pmo_stats_struct stats);

/*** PSYNC TIME ***/

/* Start psync time stuff */
#define pmo_stats_start_psynctime_other(x) \
	(x)->psynctime_other_start = ktime_get_ns()

#define pmo_stats_start_psynctime_iv(x) \
	(x)->psynctime_iv_start = ktime_get_ns()

#define pmo_stats_start_page_iv(x) \
	(x)->page_iv_start = ktime_get_ns()

#define pmo_stats_start_psynctime_encrypt(x) \
	(x)->psynctime_encrypt_start = ktime_get_ns()

#define pmo_stats_start_page_encrypt(x) \
	(x)->page_encrypt_start = ktime_get_ns()

/*
#define pmo_stats_start_psync_time_memcpy(x) \
	x.psynctime_memcpy_start = ktime_get_ns()
	*/


/* Stop psync time stuff */
#define pmo_stats_stop_psynctime_other(x) \
	(x)->psynctime_other += ktime_get_ns() - (x)->psynctime_other_start

#define pmo_stats_stop_psynctime_iv(x) \
	atomic64_add((ktime_get_ns() - (x)->psynctime_iv_start), &(x)->psynctime_iv);

#define pmo_stats_stop_page_iv(x) \
	atomic64_add((ktime_get_ns() - (x)->page_iv_start), &(x)->page_iv);

#define pmo_stats_stop_psynctime_encrypt(x) \
	(x)->psynctime_encrypt += ktime_get_ns() - (x)->psynctime_encrypt_start

#define pmo_stats_stop_page_encrypt(x) \
	(x)->page_encrypt += ktime_get_ns() - (x)->page_encrypt_start

/*
 * #define pmo_stats_stop_psync_time_memcpy(x) \
 * 	x.psynctime_memcpy += ktime_get_ns() - x.psyncttime_memcpy_start
 */

/*** END PSYNC TIME ***/

/*** ATTACH TIME ***/

/* Start attach time stuff */
#define pmo_stats_start_attachtime_other(x) \
	(x)->attachtime_other_start = ktime_get_ns()

#define pmo_stats_start_attachtime_wait(x) \
	(x)->attachtime_wait_start = ktime_get_ns()

#define pmo_stats_start_attachtime_iv(x) \
	(x)->attachtime_iv_start = ktime_get_ns()

#define pmo_stats_start_attachtime_decrypt(x) \
	(x)->attachtime_decrypt_start = ktime_get_ns()

#define pmo_stats_start_attachtime_memcpy(x) \
	(x)->attachtime_memcpy_start = ktime_get_ns()

/* Stop attach time stuff */

#define pmo_stats_stop_attachtime_other(x) { \
	(x)->attachtime_other += ktime_get_ns() - (x)->attachtime_other_start; \
	(x)->attachtime_other_start = 0; }

#define pmo_stats_stop_attachtime_wait(x) { \
	(x)->attachtime_wait += ktime_get_ns() - (x)->attachtime_wait_start; \
	(x)->attachtime_wait_start = 0; }

#define pmo_stats_stop_attachtime_iv(x) { \
	(x)->attachtime_iv += ktime_get_ns() - (x)->attachtime_iv_start; \
	(x)->attachtime_iv_start = 0; }

#define pmo_stats_stop_attachtime_decrypt(x) { \
	(x)->attachtime_decrypt += ktime_get_ns() - (x)->attachtime_decrypt_start; \
	(x)->attachtime_decrypt_start = 0; }

#define pmo_stats_stop_attachtime_memcpy(x) { \
	(x)->attachtime_memcpy += ktime_get_ns() - (x)->attachtime_memcpy_start; \
	(x)->attachtime_memcpy_start = 0; }
/*** END ATTACH TIME ***/



/*** CREATE TIME ***/
#define pmo_stats_start_create_time(x) \
	(x)->createtime_start = ktime_get_ns()

#define pmo_stats_stop_create_time(x) \
	(x)->createtime += ktime_get_ns() - (x)->createtime_start

#define pmo_creation_time_handling_start(x) \
	(x)->creationtimehandling_start = ktime_get_ns()

#define pmo_creation_time_handling_stop(x) \
	(x)->creationtimehandling += ktime_get_ns() - (x)->creationtimehandling_start

/*** END CREATE TIME ***/


#define pmo_stats_start_detach_time(x) \
	(x)->detachtime_start = ktime_get_ns()

#define pmo_stats_stop_detach_time(x) \
	(x)->detachtime += ktime_get_ns() - (x)->detachtime_start

#define pmo_stats_start_fault_time(x, tick) \
	*tick = ktime_get_ns()

#define pmo_stats_stop_fault_time(x, tick, tock) \
	*tock = ktime_get_ns(); \
	atomic64_add(*tock - *tick, &(x)->faulttime)

#define pmo_init_timing_info(x) \
	(x)->psynctime_other_start = 0; \
	(x)->psynctime_iv_start = 0; \
	(x)->page_iv_start = 0; \
	(x)->psynctime_encrypt_start = 0; \
	(x)->page_encrypt_start = 0; \
	(x)->attachtime_wait_start = 0; \
	(x)->attachtime_other_start = 0; \
	(x)->attachtime_iv_start = 0; \
	(x)->attachtime_memcpy_start = 0; \
	(x)->detachtime_start = 0; \
	(x)->attachtime_wait = 0; (x)->attachtime_other = 0; (x)->attachtime_iv = 0; \
	atomic_set(0, &(x)->psynctime_iv); \
	atomic_set(0, &(x)->page_iv); \

	/*pages_touched = 0; x.total_pages = 0; x.attach_waits = 0; x.waiting_time = 0*/

#else
#define pmo_dump_stats(stats)
#define pmo_stats_start_psync_time(x)
#define pmo_stats_stop_psync_time(x)
#define pmo_stats_start_attach_time(x)
#define pmo_stats_stop_attach_time(x)
#define pmo_stats_start_detach_time(x)
#define pmo_stats_stop_detach_time(x)
#define pmo_stats_start_create_time(x)
#define pmo_stats_stop_create_time(x)
#define pmo_stats_start_fault_time(x, tick)
#define pmo_stats_stop_fault_time(x, tick, tock)
#define pmo_init_timing_info(x)
#endif

/**************
 * ENCRYPTION *
 **************/
void pmo_destroy_shadow(struct vpma_area_struct *vpma,
		struct pmo_pages *conductor, char detach);
void pmo_encrypt_shadow(struct vpma_area_struct *vpma,
		struct pmo_pages *conductor);

void pmo_encrypt_primary_destroy_shadow (struct vpma_area_struct *vpma,
		struct pmo_pages *conductor);


void pmo_change_shadow_permissions(struct vm_area_struct *vma, void *data,
		struct pmo_pages *conductor);


#if defined(CONFIG_PMO_HANDLE_ABEND) && defined(CONFIG_PMO_USE_ENCRYPTION)
void pmo_handle_abend(struct vpma_area_struct *vpma, size_t starting_vma_address);
void pmo_encrypt_attached(struct rb_root *root);
#else
	#define pmo_handle_abend(vpma, starting_vma_address)
	#define pmo_encrypt_attached(root)
#endif

void pmo_handle_page(struct vpma_area_struct *vpma, unsigned long int pagenum);


void pmo_handle_page_prediction_noenc(struct vpma_area_struct *vpma, unsigned long int pagenum);
void pmo_handle_page_prediction_enc(struct skcipher_request *req, struct vpma_area_struct *vpma, char *local_iv,
                struct scatterlist *sg_primary, struct scatterlist *sg_other, unsigned long int pagenum);

void _pmo_handle_page_dram_crypto_prediction(struct skcipher_request *req, struct vpma_area_struct *vpma, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_working, unsigned long int pagenum);

void _pmo_handle_page_pmem_prediction(struct skcipher_request *req, struct vpma_area_struct *vpma, char *local_iv,
                struct scatterlist *sg_primary, struct scatterlist *sg_shadow, unsigned long int pagenum);


void _pmo_perform_prediction(struct vpma_area_struct *vpma, unsigned long int pagenum, unsigned int num_predicts);


/* Page handling -- DAX */
void pmo_handle_page_dram(struct vpma_area_struct *vpma, size_t offset);
void pmo_handle_page_noenc(struct vpma_area_struct *vpma, size_t offset);
void pmo_handle_page_shadow(struct vpma_area_struct *vpma, size_t offset);
void pmo_handle_page_both(struct vpma_area_struct *vpma, size_t offset);
void pmo_handle_page_whole(struct vpma_area_struct *vpma, size_t offset);

void pmo_destroy_shadow_page(struct vpma_area_struct *vpma, size_t offset, char detach);
inline void pmo_decrypt_cb(struct crypto_async_request *req, int err);

void whole_enable_vpma_access(struct vpma_area_struct *vpma);
void whole_disable_vpma_access(struct vpma_area_struct *vpma);

void pmo_print_config(void);

/*********************
 * END OF ENCRYPTION *
 *********************/

#define pmo_crypto_zap_skcipher(vpma) \
	crypto_free_skcipher(vpma->crypto.tfm)

#define pmo_get_iv(vpma) \
	vpma->crypto.pmo_iv


#define pmo_crypto_wakeup(vpma) \
       	wake_up(&vpma->crypto.encrypt_wq)


void pmo_psync_wait(struct vpma_area_struct *vpma);
void pmo_fault_wait(struct pmo_pages *sentinel);

/*******************************
 * BEGIN PREDICTIVE ENCRYPTION *
 *******************************/
#ifndef CONFIG_PMO_USE_PREDICTION
#define pmo_handle_prediction_pte(vma, addr, pte)
#define PREDICT_INIT_STATE 0

#else

#define PREDICT_INIT_STATE CONFIG_PMO_PREDICT_INIT_STATE
/* Handle a PTE when using prediction */
void pmo_handle_prediction_pte(struct vm_area_struct *vma,
		unsigned long int addr, pte_t *pte);
#endif

/*****************************
 * END PREDICTIVE ENCRYPTION *
 *****************************/

/******************
 * BEGIN COVERAGE *
 ******************/

void pmo_set_predict_init_state(struct vpma_area_struct *vpma, size_t size_in_pages);
//#ifndef CONFIG_PMO_NO_PREDICTION
#define PMO_SET_PAGE_DESTROYED(vpma, offset) \
	atomic_set(&vpma->destroyed[offset], 1)

#define PMO_CLEAR_PAGE_DESTROYED(vpma, offset) \
	atomic_set(&vpma->destroyed[offset], 0)

#define PMO_PAGE_IS_DESTROYED(vpma, pagenum) \
	atomic_read(&vpma->destroyed[pagenum])

#define PMO_PAGE_LOCK(vpma, pagenum) \
	mutex_lock (&vpma->lock_page[pagenum])

#define PMO_PAGE_UNLOCK(vpma, pagenum) \
	mutex_unlock (&vpma->lock_page[pagenum])

/*
#else
#define PMO_SET_PAGE_DESTROYED(vpma, offset)
#define PMO_CLEAR_PAGE_DESTROYED(vpma, offset)
#define PMO_PAGE_IS_DESTROYED(vpma, pagenum) false
#endif
*/

#if defined(CONFIG_PMO_TRACK_EXPOSED_PAGES)
void pmo_inc_mispredict(struct vpma_area_struct *vpma);
void pmo_inc_exposed_pages(struct vpma_area_struct *vpma);
void pmo_inc_total_predictions(struct vpma_area_struct *vpma);

void dump_coverage_statistics(struct vpma_area_struct *vpma);
void pmo_init_tracking(struct vpma_area_struct *vpma);
void pmo_inc_exposed_pages(struct vpma_area_struct *vpma);
void pmo_add_total_pages(struct vpma_area_struct *vpma);
#else

#define pmo_inc_mispredict(vpma)
#define pmo_inc_exposed_pages(vpma)
#define pmo_inc_total_predictions(vpma)
#define dump_coverage_statistics(vpma)
#define pmo_init_tracking(vpma)
#define pmo_inc_exposed_pages(vpma)
#define pmo_add_total_pages(vpma)

#endif

/**************** 
 * END COVERAGE *
 ****************/

void vpma_init_crypto(struct vpma_area_struct *vpma, char *key);
struct pmo_async_struct *create_async_struct(
		struct vpma_area_struct * vpma, size_t pagenum,
		char should_destroy);

#define pmo_get_tfm(vpma) vpma->crypto.tfm
#define pmo_set_iv(vpma, iv) \
	memcpy(vpma->crypto.pmo_iv, iv, 16)

#define pmo_invalidate_pte(addr, pte) \
	ptep_get_and_clear(current->mm, (unsigned long int) addr, pte)
	/* See /fs/proc/task_mmu.c for more information about this.
	 * This is slightly simplified because if we've ever gotten here,
	 * we *know* that this is coming from a present page that is a PMO, so
	 * we can skip these checks. 
	 * Since we will invalidate the entire TLB at the end, there's no need
	 * to do it now */


/* Destroy the shadow at the end of every psync, if we're paranoid or if
 * should_destroy is true */
void pmo_destroy_shadow_paranoid(struct pmo_async_struct *async_struct);


enum encryption_type {NOENC, PPs, PPb, WHOLE};
enum IVType {NONE, PSYNC, DETACH};
enum pred_type {NONE_PRED, STREAM, MARKOV, STRIDE};
enum access_type {DAX, BLOCK};
enum cxl_type {PMO_LOCAL, PMO_FAR};
extern enum access_type pmo_access_mode;
struct pmo_settings {
	enum encryption_type enc_mode;
	enum IVType iv_type;
	enum pred_type pred;
	enum cxl_type pmo_cxl_emulation_mode;
	
	bool dram,
	     dram_predictahead,
	     enc_in_dram,
	     dram_as_buffer,
	     debug,
	     paranoid,
	     async_checksum,
	     bypass_shadow;

	char depth;
};

#define PMO_ENABLE_DEBUG_MODE() \
	header->this.settings.debug = true

#define PMO_DISABLE_DEBUG_MODE() \
	header->this.settings.debug = false

#define PMO_DEBUG_MODE_IS_ENABLED() \
	header->this.settings.debug

#define PMO_BYPASS_SHADOW_IS_ENABLED() \
	header->this.settings.bypass_shadow

#define PMO_ASYNC_CHECKSUM_IS_ENABLED() \
	header->this.settings.async_checksum

#define PMO_ENABLE_ASYNC_CHECKSUM() \
	header->this.settings.async_checksum = true

#define PMO_DISABLE_ASYNC_CHECKSUM() \
	header->this.settings.async_checksum = false

#define PMO_DISABLE_ENCRYPT_IN_DRAM() \
	header->this.settings.enc_in_dram = false

#define PMO_DISABLE_PREDICTION() \
	header->this.settings.pred = NONE_PRED

#define PMO_ENABLE_STREAM() \
	header->this.settings.pred = STREAM

#define PMO_ENABLE_MARKOV() \
	header->this.settings.pred = MARKOV

#define PMO_ENABLE_STRIDE() \
	header->this.settings.pred = STRIDE

#define PMO_SET_ACCESS_TYPE_DAX() \
	pmo_access_mode = DAX

#define PMO_DAX_IS_ENABLED() \
	(pmo_access_mode == DAX)

#define PMO_SET_CXL_TYPE_LOCAL() \
	(header->this.settings.pmo_cxl_emulation_mode = PMO_LOCAL)

#define PMO_SET_CXL_TYPE_FAR() \
	(header->this.settings.pmo_cxl_emulation_mode = PMO_FAR)

#define PMO_GET_CXL_MODE() \
	(header->this.settings.pmo_cxl_emulation_mode)

#define PMO_SET_ACCESS_TYPE_BLOCK() \
	pmo_access_mode = BLOCK

#define PMO_BLOCK_IS_ENABLED() \
	(pmo_access_mode == BLOCK)

#define PMO_STREAM_IS_ENABLED() \
	(header->this.settings.pred == STREAM)

#define PMO_MARKOV_IS_ENABLED() \
	(header->this.settings.pred == MARKOV)

#define PMO_STRIDE_IS_ENABLED() \
	(header->this.settings.pred == STRIDE)

#define PMO_NOPRED_IS_ENABLED() \
	(header->this.settings.pred == NONE_PRED)

#define PMO_PRED_IS_ENABLED() \
	(header->this.settings.pred != NONE_PRED)

#define PMO_SHOULD_VERIFY_SHADOW_AND_PRIMARY() \
	(header->this.settings.paranoid)

#define PMO_ENABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY() \
	header->this.settings.paranoid = true

#define PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY() \
	header->this.settings.paranoid = false

#define PMO_ENABLE_ENCRYPT_IN_DRAM() \
	header->this.settings.enc_in_dram = true

#define PMO_ENCRYPT_IN_DRAM_IS_ENABLED() \
	header->this.settings.enc_in_dram

#define PMO_ENABLE_DRAM() \
	header->this.settings.dram = true

#define PMO_ENABLE_DRAM_AS_BUFFER() \
	header->this.settings.dram_as_buffer = true

#define PMO_DISABLE_DRAM_AS_BUFFER() \
	header->this.settings.dram_as_buffer = false

#define PMO_DRAM_AS_BUFFER_IS_ENABLED() \
	header->this.settings.dram_as_buffer

#define PMO_ENABLE_DRAM_PREDICTAHEAD() \
	header->this.settings.dram_predictahead = true;

#define PMO_DISABLE_DRAM() \
	header->this.settings.dram = false; 

#define PMO_DISABLE_DRAM_PREDICTAHEAD() \
	header->this.settings.dram_predictahead = false;

#define PMO_DRAM_IS_ENABLED() \
	header->this.settings.dram

#define PMO_DRAM_PREDICTAHEAD_IS_ENABLED() \
	header->this.settings.dram_predictahead

#define PMO_GET_PREDICTION_DEPTH() \
	header->this.settings.depth

#define PMO_SET_PREDICTION_DEPTH(x) \
	header->this.settings.depth = x

#define PMO_SET_NOENC() \
	header->this.settings.enc_mode = NOENC

#define PMO_SET_PPs() \
	header->this.settings.enc_mode = PPs

#define PMO_SET_PPb() \
	header->this.settings.enc_mode = PPb

#define PMO_SET_WHOLE() \
	header->this.settings.enc_mode = WHOLE;

#define PMO_SET_IV_NOENC() \
	header->this.settings.iv_type = NOENC

#define PMO_SET_IV_PSYNC() \
	header->this.settings.iv_type = PSYNC

#define PMO_SET_IV_DETACH() \
	header->this.settings.iv_type = DETACH



#define PMO_NOENC_IS_ENABLED() \
	(header->this.settings.enc_mode == NOENC)

#define PMO_PPs_IS_ENABLED() \
	(header->this.settings.enc_mode == PPs)

#define PMO_PPb_IS_ENABLED() \
	(header->this.settings.enc_mode == PPb)

#define PMO_WHOLE_IS_ENABLED() \
	(header->this.settings.enc_mode == WHOLE)



#define PMO_IV_IS_ENABLED() \
	(header->this.settings.iv_type >= PSYNC)

#define PMO_IV_PSYNC_IS_ENABLED() \
	(header->this.settings.iv_type == PSYNC)

#define PMO_IV_DETACH_IS_ENABLED() \
	(header->this.settings.iv_type == DETACH)
void pmo_get_mode(char *mode);



struct pmo_header_s {
	char header[4];
	char name[16];
	struct range pmo_range;

	__u64 nodelist_location; /* The location of the nodelist offset
				    from the starting address */

	__u64 sha256_region_location;
	__u64 pmo_region_location;
	__u64 next_free_pmo;

	char dram_offloading; /* Instead of a shadow PMO on NVMM,
				 enables DRAM offloading -- the shadow PMO
				 instead lives in the DRAM and psync()
				 memcpys the changes back to the NVMM */
	atomic_t boot_id;
	struct pmo_settings settings;
};

union pmo_header {
	struct pmo_header_s this;
	char padding[0x1000];
};

/**********************
 *  END OF STRUCTURES *
 **********************/

/***************************************************************************/

/*********
 * STATE *
 *********/

#define UNKNOWN 6
#define SECURE 5
#define INSECURE 4

#define pmo_state_unknown(y) \
	test_bit(6, (long unsigned int*)&y->state)

#define pmo_state_secure(y) \
	!pmo_state_unknown(y) && \
	test_bit(5, (long unsigned int*)&y->state)

#define pmo_state_insecure(y) \
	!pmo_state_unknown(y) && \
	!test_bit(5, (long unsigned int*)&y->state)

int set_state(int state,struct pmo_entry *entry);

/*****************
 *  END OF STATE *
 *****************/

/***************************************************************************/

/********
 * HASH *
 ********/


/* Note: djb2_hash was originally created by Dan Bernstein in the 1990s, but
 * not copyright notice has been supplied. It is unlikely to be under any  
 * restrictive licensing since it has been released to the community, 
 * nevertheless, this algorithm was provided by him.
 * Found at: http://www.cse.yorku.ca/~oz/hash.html */

static inline __u64 djb2_hash(unsigned char *str)
{
	int c;
	__u64 hash = 5381;
	while( (c = *str++))
		hash = ((hash << 5) + hash) + c; /*  hash * 33 + c */
	return hash;
}

/***************
 * END OF HASH *
 ***************/

/***************************************************************************/

/**********
 * ACCESS *
 **********/

/* Right now, this just finds the location of the shadow */
#define find_hole(x, y) (x + PAGE_ALIGN(y))
#define get_unmapped_pmo_area(x) (x ^= 1UL << 46) 



void verify_attach(struct pmo_entry *pmo, char prot_type,
		size_t size, size_t page_offset, char *key);
void block_verify_attach(struct pmo_entry *pmo, char prot_type,
		size_t size, size_t page_offset, char *key);



void *do_attach(struct pmo_entry *pmo, char prot_type, size_t size,
		size_t page_offset, char *key, unsigned char flags);
int do_detach(struct mm_struct *mm, char *path);
size_t do_get_size(struct mm_struct *mm, char *path);
int get_boot_id(void);
int is_alive_pid(int pid);
struct resource *get_dax_dev_resource(char *dev_name);
void dax_pmo_handle_init(void);
void block_pmo_handle_init(void);
extern int block_psync(struct device *dev/*,TODO: maybe add linked list pointer?*/);
void pmo_handle_init(bool init_proc);

__u64 get_available_pmo_location(__u64 size);
int enable_vpma_access(struct vpma_area_struct *vpma, __u64 size,
		__u64 offset, char prot_type, char * key);
int disable_vpma_access(struct vpma_area_struct *vpma);
#ifdef CONFIG_PMO_NONBLOCKING
void nonblocking_disable_vpma_access(struct vpma_area_struct *vpma);
void nonblocking_verify_fault(struct vpma_area_struct *vpma,
		unsigned long pagenum);
void pmo_initialize_detach_thread(struct vpma_area_struct *vpma);
void pmo_initialize_async_thread(struct vpma_area_struct *vpma);
void pmo_async_obtain_shadow_hash(struct vpma_area_struct *vpma, size_t pagenum);
void pmo_async_obtain_primary_hash(struct vpma_area_struct *vpma, size_t pagenum);
void pmo_initialize_decryptahead_thread(struct vpma_area_struct *vpma);
void pmo_run_decryptahead_thread(struct vpma_area_struct *vpma);
#else
#define nonblocking_disable_vpma_access(idx)
#define pmo_initialize_detach_thread(vpma)
#endif

struct pmo_entry *get_pmo_from_name(char * name);

#ifdef CONFIG_X86
	/* Map the PMO metadata entry into the kernel as uncacheable, so we can
	 * modify the metadata atomically. ioremap_uc() informs the kernel
	 * to map this address "as strongly uncached". */
#define pmo_architecture_specific_memremap(address) \
	ioremap_uc(address, sizeof(struct pmo_entry))

#else
	/* ioremap_uc is x86 specific. Therefore, non-x86 architectures are
	 * unsupported for now, but we'll still handle this by falling back to
	 * architecture agnostic ioremap. */
#define pmo_architecture_specific_memremap(address) \
	printk(KERN_WARNING "Non-x86 architectures are unsupported\n")
#endif

struct pmo_entry * pmo_memremap(char *name);
void *pmo_block_map(unsigned long int ptr, size_t size);
void pmo_block_unmap(void *ptr);
void *pmo_dax_map(unsigned long int ptr, size_t size);
void pmo_dax_unmap(void *ptr);
void *pmo_dax_get_header(__u64 pmo_start);
struct pmo_entry * pmo_dax_memremap(__u64 entry_id);
struct pmo_entry * pmo_block_memremap(__u64 entry_id);
void *pmo_block_get_header(__u64 pmo_start);

void pmo_block_update_header(void);
void pmo_update_header(void);
void pmo_update_metadata(struct vpma_area_struct *vpma);
void pmo_block_update_metadata(struct vpma_area_struct *vpma);

void *pmo_map(unsigned long int ptr, size_t size);
void pmo_unmap(void * ptr);

void pmo_barrier(void);
void pmo_sync (void * address, size_t size);

void pmo_handle_block_page(struct vpma_area_struct *vpma, size_t offset);

struct vpma_area_struct *vpma_search(struct rb_root *root, char *name);
void zap_vpmas(struct rb_root *root);

/*****************
 * END OF ACCESS *
 *****************/

/***************************************************************************/

/************
 * CREATION * 
 ************/
void do_create(char *name, __u64 size, char *key);
struct vpma_area_struct * create_vpma_for_pmo(__u64 address,__u64 size,
		char *name, char *subset_name, char prot_type, char *key);
struct vm_area_struct *create_vma_for_pmo(__u64 size, __u64 pmo_address,
                char prot_type);

/*******************
 * END OF CREATION *
 *******************/

/***************************************************************************/

/************
 * PAGEWALK *
 ************/

void debug_dirty_ll(struct pmo_pages *dirty_ll);
void pmo_handle_dirty_dram (struct vpma_area_struct *vpma, unsigned long offset);

void pmo_init_pred_working_data (struct vpma_area_struct *vpma, unsigned long pagenum);
void pmo_init_pmem_working_data (struct vpma_area_struct *vpma, unsigned long pagenum);
void pmo_init_dram_working_data(struct vpma_area_struct *vpma, unsigned long int pagenum);
void pmo_invalidate_working (struct vpma_area_struct *vpma, bool is_exiting);
void pmo_invalidate_page (struct vpma_area_struct *vpma, unsigned long int pagenum, bool is_exiting);

#define PMO_CLEAR_IS_FAULTED(vpma, pagenum) \
	clear_bit(0, &vpma->working_data[pagenum].flag)

#define PMO_CLEAR_IS_PREDICTED(vpma, pagenum) \
	clear_bit(1, &vpma->working_data[pagenum].flag)

#define PMO_CLEAR_IS_HANDLED(vpma, pagenum) \
	clear_bit(2, &vpma->working_data[pagenum].flag)

#define PMO_CLEAR_NO_PREDICT(vpma, pagenum) \
	clear_bit(3, &vpma->working_data[pagenum].flag)

#define PMO_CLEAR_PAGE_TIMELY(vpma, pagenum) \
	clear_bit(4, &vpma->working_data[pagenum].flag)

#define PMO_CLEAR_WAITING_HANDLED(vpma, pagenum) \
	clear_bit(5, &vpma->working_data[pagenum].flag)


#define PMO_SET_IS_FAULTED(vpma, pagenum) \
	set_bit(0, &vpma->working_data[pagenum].flag)

#define PMO_SET_IS_PREDICTED(vpma, pagenum) \
	set_bit(1, &vpma->working_data[pagenum].flag)

#define PMO_SET_IS_HANDLED(vpma, pagenum) \
	set_bit(2, &vpma->working_data[pagenum].flag)

#define PMO_SET_NO_PREDICT(vpma, pagenum) \
	set_bit(3, &vpma->working_data[pagenum].flag)

#define PMO_SET_PAGE_TIMELY(vpma, pagenum) \
	set_bit(4, &vpma->working_data[pagenum].flag)



#define PMO_TEST_IS_FAULTED(vpma, pagenum) \
	test_bit(0, &vpma->working_data[pagenum].flag)

#define PMO_TEST_IS_PREDICTED(vpma, pagenum) \
	test_bit(1, &vpma->working_data[pagenum].flag)

#define PMO_TEST_IS_HANDLED(vpma, pagenum) \
	test_bit(2, &vpma->working_data[pagenum].flag)

#define PMO_TEST_NO_PREDICT(vpma, pagenum) \
	test_bit(3, &vpma->working_data[pagenum].flag)

#define PMO_TEST_PAGE_IS_TIMELY(vpma, pagenum) \
	test_bit(4, &vpma->working_data[pagenum].flag)



#define PMO_TEST_AND_SET_WAITING_HANDLED(vpma, pagenum) \
	test_and_set_bit(5, &vpma->working_data[pagenum].flag)

#define PMO_TEST_AND_SET_IS_HANDLED(vpma, pagenum) \
	test_and_set_bit(2, &vpma->working_data[pagenum].flag)

#define PMO_TEST_AND_SET_IS_FAULTED(vpma, pagenum) \
	test_and_set_bit(0, &vpma->working_data[pagenum].flag)


#define pmo_do_sg_init(sg, page) \
	sg_init_one(&sg, page, PAGE_SIZE);

struct pmo_pages *create_dirty_ll(unsigned long int offset, void *primary,
		void *shadow, void *working);
struct pmo_pages *create_pages_ll(unsigned long int address, unsigned long int offset);
inline struct pmo_pages * vpma_insert_into_dirtypages(struct vpma_area_struct *vpma,
		unsigned long pfn, size_t offset, pte_t *pte, spinlock_t *ptl);
inline struct pmo_pages * vpma_insert_into_faulted_pages(struct vpma_area_struct *vpma,
		unsigned long pfn, size_t offset, pte_t *pte, spinlock_t *ptl);

#define create_dirty_sentinel() \
	create_dirty_ll(-1, (void *)-1, (void *)-1, (void *)-1)



void pte_range_dirtybits(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long address, unsigned long end, int flag,
		struct pmo_pages ** dirty_ll);

void pmd_range_dirtybits(struct vm_area_struct *vma, pud_t *pud,
		unsigned long address, unsigned long end, int flag,
		struct pmo_pages ** dirty_ll);

void pud_range_dirtybits(struct vm_area_struct *vma, p4d_t *p4d,
		unsigned long address, unsigned long end, int flag,
		struct pmo_pages ** dirty_ll);

void p4d_range_dirtybits(struct vm_area_struct *vma, pgd_t *pgd,
		unsigned long address, unsigned long end, int flag,
		struct pmo_pages ** dirty_ll);

void pmo_sync_pages(struct vpma_area_struct *vpma, size_t starting_vma_address,  bool update_checksum);

#ifdef CONFIG_PMO_PAGEWALK

void pmo_pagewalk_unset_dirtybits(struct vpma_area_struct *vpma,
	       unsigned long address);

#endif

#ifdef CONFIG_PMO_STATS_REPORTING
#define inc_pages_touched(vpma) \
	current->mm->pmo_stats.pages_touched++;
#define inc_total_pages(vpma, pagenum) \
	current->mm->pmo_stats.total_pages += pagenum
#define attach_waits() \
	current->mm->pmo_stats.attach_waits++
#define waiting_time(start, end) \
	current->mm->pmo_stats.waiting_time += (end - start)
#else
#define inc_pages_touched(vpma)
#define inc_total_pages(vpma, pagenum)
#define attach_waits() 
#define waiting_time(start, end) 
#endif

#define pmo_set_key(vpma, key)\
	memcpy(vpma->crypto.enc_key, key, 63);\
	vpma->crypto.enc_key[62] = 0

#define pmo_inc_faulted_pages(vpma) \
	atomic_inc(&vpma->crypto.faulted_pages)

#define pmo_dec_faulted_pages(vpma) \
	atomic_inc(&vpma->crypto.faulted_pages)


#define pmo_dec_encrypted_pages(vpma)\
	if(!PMO_WHOLE_IS_ENABLED()) \
		atomic_dec(&vpma->crypto.encrypted_pages)

#define pmo_inc_encrypted_pages(vpma)\
	if(!PMO_WHOLE_IS_ENABLED()) \
		atomic_inc(&vpma->crypto.encrypted_pages)


inline void pmo_clear_dirty(pte_t *pte);
inline void pmo_clear_access(pte_t *pte);
inline void pmo_clear_write(pte_t *pte);
inline void pmo_clear_read(pte_t *pte);


/*******************************
 * BEGIN MEMCPY SYNC FUNCTIONS *
 *******************************/

void pmo_handle_memcpy_sync(struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_shadow,
		struct scatterlist *sg_working);

void pmo_handle_memcpy_sync_shadow_only(struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_shadow);


void pmo_handle_memcpy_sync_dram (struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_working);

void pmo_hanlde_memcpy_sync_dram_alternate(struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist sg_working_backup,
		struct scatterlist *sg_working);

void pmo_handle_memcpy_sync_together(struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_shadow);

void pmo_handle_memcpy_sync_whole(struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_shadow);

void pmo_handle_memcpy_sync_noenc(struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_shadow);

/*****************************
 * END MEMCPY SYNC FUNCTIONS *
 *****************************/


/* Maybe not double ptr? */
bool pmo_page_should_destroy(struct vpma_area_struct *vpma, size_t offset);
void pmo_predecrypt_all_pages(struct vpma_area_struct *vpma, size_t size_in_pages);
void fix_pmo_page_entry(struct vm_area_struct *vma, unsigned long address,
		struct pmo_pages *entry);
int _pmo_follow_pfn(struct vm_area_struct *vma, unsigned long address, 
		unsigned long *pfn, pte_t **ptep, spinlock_t **ptlp);

struct pmo_pages * pmo_handle_pagefault(struct vm_area_struct *vma,
		unsigned long address);

/*******************
 * END OF PAGEWALK *
 *******************/

/***************************************************************************/

/****************
 * GAP HANDLING *
 ****************/

/************************************************************************** 
 * This struct describes a PMO gap. Each gap has a size and a position.	  *
 * When a pmo is created, or when it is attached as a write, the kernel	  *
 * searches through the red-black tree of PMO gaps, and returns the first *
 * gap which is large enough to fit the PMO. This also removes that gap   *
 * from the red-black tree. Conversely, when a pmo attached as a write is *
 * detached, or when a PMO is destroyed (not implemented yet), the space  * 
 * is freed, and a gap is added into the tree.				  *
 * 									  *
 * If the kernel fails to find a suitable gap in the tree, it will return *
 * the first address past the end of the last allocated PMO		  *
 **************************************************************************/ 
struct pmo_gaps
{
        struct rb_node node;
        __u64 gap_size;
        struct gap_stack *head;
	char sentinel; /* Is this the sentinel?
			  (the empty space until the end of the pmem?)
			  Then we move the address*/
};

struct gap_stack
{
	__u64 address;
	struct gap_stack *next;
};

/********************
 * END GAP HANDLING *
 ********************/

/***************************************************************************/


/************
 * RECOVERY *
 ************/

/* Recovery defines */
#define SUCCESS 0  /* 0x0  0000 */
#define READING 1  /* 0x1  1000 */
#define WRITING 3  /* 0x3  1100 */
#define PERSIST	7  /* 0x7  1110 */
#define COPYING 15 /* 0xF  1111 */
#define COMPLET	31 /* 0xFF 11111 */

int recover(struct pmo_entry *pmo, char access_type, char *key);

/*******************
 * END OF RECOVERY *
 *******************/

/* PAGEWALK OR TRAVERSE */
#ifdef CONFIG_PMO_PAGEWALK 
#else
#define pmo_traverse_or_pagewalk_persist(vpma, address, dirty_ll) \
	pmo_traverse(vpma, address, DB_PERSIST | DB_CLEAR, dirty_ll)

#define pmo_traverse_or_pagewalk_unset_dirtybits(vpma) \
	pmo_traverse(vpma, vpma->vma->vm_start, DB_CLEAR, NULL)
#endif




/*************************************
 * CONFIG_PMO_INTEGRITY_VERIFICATION *
 *************************************/

/* Although this only makes sense in the context of using integrity checking,
 * we might as well keep it here as other parts of our code uses it. */
#define pmo_address_to_sha_offset(address) \
	(address - header->this.pmo_region_location)/PAGE_SIZE


int calc_hash(struct crypto_shash *alg, const unsigned char *data,
		unsigned int datalen, unsigned char *digest);

extern size_t sha256size;
extern char _pmo_sha_sentinel[32];


#define assign_sha256_to_pmo_entry(pmo_ptr, sha256hash) \
	if(PMO_IV_IS_ENABLED() && PMO_WHOLE_IS_ENABLED()) \
		memcpy_flushcache(pmo_ptr->sha256sum, sha256hash, 32)

extern struct pmo_sha256 *sha256_region;
#define PMO_CHECKSUMS_MATCH(sha256hash, offset) \
	memcmp(sha256hash, OFFSET_TO_SHA(offset), 32) == 0

struct pmo_sha256 {
	char sum[32]; /* The sha */
};

#define OFFSET_TO_SHA(pagenum) \
	sha256_region[pagenum].sum

#define PMO_PAGE_SHA_IS_UNSET(pagenum) \
	memcmp(OFFSET_TO_SHA(pagenum), _pmo_sha_sentinel, 32) == 0

void init_sha256_region(size_t start, size_t end);
void pmo_initialize_checksum(void);
void pmo_init_empty_hash(void);
void pmo_get_page_hash(void *ret, void *data);
void pmo_handle_hash_psync(void *addr);
struct sdesc *init_sdesc(struct crypto_shash *alg);
void vpma_initialize_primary_checksum(struct vpma_area_struct *vpma);
void vpma_initialize_shadow_checksum(struct vpma_area_struct *vpma);

void get_sha256_hash(void *ret, void *data, size_t size);

/* At persist time, obtain the PMO hash, and assign to shadow hash */
void pmo_obtain_shadow_hash(struct vpma_area_struct *vpma, size_t page_offset);

void handle_pmo_hash_identical(struct vpma_area_struct *vpma,
		void *decrypted_data, size_t page_offset, bool is_async);
void pmo_assign_primary_hash(struct vpma_area_struct *vpma,
		size_t page_offset);
void vpma_set_sha_ranges(struct vpma_area_struct *vpma);

/*************************************
 * CONFIG_PMO_INTEGRITY_VERIFICATION *
 *************************************/

/**************
 * PMO ACCESS *
 **************/

#define get_next_free_pmo(available_pmo, size) \
	available_pmo + PAGE_ALIGN(size)*2

#define get_phys_shadow_from_size(phys_primary, size) \
	find_hole(phys_primary, size)

/******************
 * END PMO ACCESS *
 ******************/

bool pmo_page_should_destroy(struct vpma_area_struct *vpma, size_t offset);

void pmo_towards_access(struct vpma_area_struct *vpma, size_t offset);

void pmo_towards_or_set_inert(struct vpma_area_struct *vpma, size_t offset);

void pmo_insert_faulted_pages(struct vpma_area_struct *vpma,
		unsigned long int offset);

long long int pmo_decide_best_markov_path(struct vpma_area_struct *vpma, signed long long int m);
void pmo_initialize_markov_chain(struct vpma_area_struct *vpma, size_t num_pages);
void pmo_initialize_stride_chain(struct vpma_area_struct *vpma, size_t num_pages);
void pmo_increment_markov_entry(struct vpma_area_struct *vpma, size_t entry);
void pmo_increment_stride_entry(struct vpma_area_struct *vpma, signed long long int entry);
long long int pmo_decide_best_stride(struct vpma_area_struct *vpma, long long int m);

#define PMO_SET_PAGE_IN_BUFFER(vpma, pagenum) \
	vpma->working_data[pagenum].page_in_buffer = true

#define PMO_CLEAR_PAGE_IN_BUFFER(vpma, pagenum) \
	vpma->working_data[pagenum].page_in_buffer = false

#define PMO_PAGE_IN_BUFFER(vpma, pagenum) \
	vpma->working_data[pagenum].page_in_buffer
#endif


