#include "../pmo.h"
#include <linux/circ_buf.h>
#include <linux/bitmap.h>

#define RING_MAX_SIZE 8192

/*
 * FPMO+ stage 2 (shadow -> primary) runs on one long-lived pmem_worker.
 *
 * psync() persists the dirty pages and their checksums to the shadow (stage
 * 1), persists the COPYING state (pmo->state bits 2 and 3), queues one request
 * per page here and, when the copy needs nothing but the vpma and the page
 * number (pmem_proxy_can_defer()), returns without waiting: stage 2 overlaps
 * the next transaction.  COPYING ends (pmem_proxy_release()) only when the
 * psync has finished queuing and every queued page is in primary and fenced,
 * whichever of the two happens last, so a crash before that is recovered by
 * redoing shadow -> primary (recover(), COPYING).
 *
 * Anything that reads primary or rewrites the shadow waits first:
 *   - the next psync, before stage 1 overwrites the shadow (redo source);
 *   - detach and process exit, before the vpma goes away;
 *   - a page fault on a page whose stage 2 is still pending.
 * See pmem_proxy_drain_vpma() and pmem_proxy_page_wait().
 */
struct page_save_req {
    struct skcipher_request *sk_req;
    struct vpma_area_struct *vpma;
    size_t pagenum;
    char *local_iv;
    struct scatterlist *sg_primary;
    struct scatterlist *sg_shadow;
    struct scatterlist *sg_working;
};

struct proxy_ring_buffer {
    struct page_save_req buffer[RING_MAX_SIZE];
    atomic_t head;
    atomic_t tail;
    spinlock_t lock;
};

static struct proxy_ring_buffer pmem_proxy_rb;
static struct task_struct *pmem_worker;
static DEFINE_MUTEX(pmem_worker_lock);
static DECLARE_WAIT_QUEUE_HEAD(pmem_proxy_work_wq);  /* worker waits for work */
static DECLARE_WAIT_QUEUE_HEAD(pmem_proxy_done_wq);  /* drains wait for pages */

static int pmem_worker_thread(void *data);
int pmem_proxy_rb_occupancy(void);

/*
 * Usable proxy-buffer capacity, for the capacity sweep (R3 Q4).
 * /proc/pmo/proxy_capacity_pct sets it as a percentage of each psync's
 * dirty-page count N_d; 0 (the default) means the whole ring.  A push beyond
 * the limit returns -ENOSPC exactly like a full ring, so the overflow path
 * (stop queuing, commit the rest of this psync's pages synchronously) is
 * what gets exercised.
 */
static int pmem_proxy_capacity_pct;
static int pmem_proxy_limit = RING_MAX_SIZE - 1;

void pmem_proxy_set_capacity_pct(int pct)
{
    pmem_proxy_capacity_pct = pct;
}

int pmem_proxy_get_capacity_pct(void)
{
    return pmem_proxy_capacity_pct;
}

/* Called once per psync, before its pages are pushed. */
void pmem_proxy_set_limit(int n_dirty)
{
    int limit = RING_MAX_SIZE - 1;

    if (pmem_proxy_capacity_pct > 0)
        limit = clamp(DIV_ROUND_UP(n_dirty * pmem_proxy_capacity_pct, 100),
            1, RING_MAX_SIZE - 1);
    pmem_proxy_limit = limit;
}

/* Start the worker once; it stays up for later psyncs. */
void pmem_proxy_init(void)
{
    mutex_lock(&pmem_worker_lock);
    if (!pmem_worker) {
        memset(&pmem_proxy_rb, 0, sizeof(pmem_proxy_rb));
        atomic_set(&pmem_proxy_rb.head, 0);
        atomic_set(&pmem_proxy_rb.tail, 0);
        spin_lock_init(&pmem_proxy_rb.lock);

        pmem_worker = kthread_run(pmem_worker_thread,
            &pmem_proxy_rb, "pmem_worker");
        if (IS_ERR(pmem_worker)) {
            printk(KERN_WARNING "PMO: no pmem_worker (%ld); renamed pages "
                "are committed synchronously\n", PTR_ERR(pmem_worker));
            pmem_worker = NULL;
        }
    }
    mutex_unlock(&pmem_worker_lock);
}

/* Stage 2 may be left running after psync returns only if the copy uses
 * nothing that psync frees: the vpma and the page number.  That is the
 * plain shadow -> primary memcpy_flushcache of PPb and NOENC on DAX.  The
 * DRAM, PPs and WHOLE handlers use psync's scatterlists, stack IV or crypto
 * request, and the paranoid mode compares primary right after the copy. */
bool pmem_proxy_can_defer(void)
{
    return pmem_proxy_pages_independent() &&
        !PMO_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
}

/* Each page's stage 2 is a self-contained shadow -> primary copy, so psync
 * may commit other pages itself while the worker still copies queued ones.
 * Not so for PPs (shared crypto request and IV) or the DRAM/WHOLE handlers. */
bool pmem_proxy_pages_independent(void)
{
    return pmem_worker && PMO_DAX_IS_ENABLED() && !PMO_DRAM_IS_ENABLED() &&
        (PMO_PPb_IS_ENABLED() || PMO_NOENC_IS_ENABLED());
}

/* Persist pmo->state, the crash-recovery state, after a bit change. */
static void pmem_proxy_persist_state(struct pmo_entry *pmo)
{
    pmo_sync(&pmo->state, sizeof(pmo->state));
    pmo_barrier();
}

static int ring_buffer_push(struct proxy_ring_buffer *rb,
    struct page_save_req *req)
{
    unsigned long flags;
    int next_head;

    spin_lock_irqsave(&rb->lock, flags);
    next_head = (atomic_read(&rb->head) + 1) % RING_MAX_SIZE;
    if (next_head == atomic_read(&rb->tail) ||
        CIRC_CNT(atomic_read(&rb->head), atomic_read(&rb->tail),
            RING_MAX_SIZE) >= pmem_proxy_limit) {
        spin_unlock_irqrestore(&rb->lock, flags);
        return -ENOSPC;
    }
    rb->buffer[atomic_read(&rb->head)] = *req;
    atomic_set(&rb->head, next_head);
    spin_unlock_irqrestore(&rb->lock, flags);

    return 0;
}

static int ring_buffer_pop(struct proxy_ring_buffer *rb,
    struct page_save_req *req)
{
    unsigned long flags;

    spin_lock_irqsave(&rb->lock, flags);
    if (atomic_read(&rb->tail) == atomic_read(&rb->head)) {
        spin_unlock_irqrestore(&rb->lock, flags);
        return -ENOENT;
    }
    *req = rb->buffer[atomic_read(&rb->tail)];
    atomic_set(&rb->tail, (atomic_read(&rb->tail) + 1) % RING_MAX_SIZE);
    spin_unlock_irqrestore(&rb->lock, flags);

    return 0;
}

/* End the COPYING state if this vpma's commit is complete: the psync has
 * finished queuing and no page is pending.  Caller holds stage2_lock, which
 * makes this run exactly once per commit, before the next psync can take
 * bit 2 again. */
static void pmem_proxy_release(struct vpma_area_struct *vpma)
{
    struct pmo_entry *pmo = vpma->pmo_ptr;

    if (vpma->stage2_committing || atomic_read(&vpma->stage2_pending) ||
        !pmo_bit_is_set(3, pmo))
        return;
    /* primary == shadow == this commit. */
    pmo_unlock_bit(3, pmo);
    pmo_unlock_bit(2, pmo);
    pmem_proxy_persist_state(pmo);
}

/* psync has set and persisted COPYING (bits 2 and 3) and starts queuing. */
void pmem_proxy_begin_commit(struct vpma_area_struct *vpma)
{
    spin_lock(&vpma->stage2_lock);
    vpma->stage2_committing = true;
    spin_unlock(&vpma->stage2_lock);
}

/* psync is done: end COPYING now if stage 2 is done, else the worker will. */
void pmem_proxy_end_commit(struct vpma_area_struct *vpma)
{
    spin_lock(&vpma->stage2_lock);
    vpma->stage2_committing = false;
    pmem_proxy_release(vpma);
    spin_unlock(&vpma->stage2_lock);
}

/* One page of stage 2 is in primary: publish it. */
static void stage2_page_done(struct page_save_req *req)
{
    struct vpma_area_struct *vpma = req->vpma;

    /* The copy is a flushed (non-temporal) store issued on this CPU: fence
     * before anyone is told the page is in primary, so that a faulting
     * reader on another CPU, or a crash, sees the new data. */
    pmo_barrier();
    if (vpma->stage2_map)
        clear_bit(req->pagenum, vpma->stage2_map);

    spin_lock(&vpma->stage2_lock);
    if (atomic_dec_and_test(&vpma->stage2_pending))
        pmem_proxy_release(vpma);
    spin_unlock(&vpma->stage2_lock);
    wake_up_all(&pmem_proxy_done_wq);
}

static int pmem_worker_thread(void *data)
{
    struct proxy_ring_buffer *rb = (struct proxy_ring_buffer *) data;
    struct page_save_req req;

    for (;;) {
        /* Idle in TASK_IDLE: no busy polling, and not counted by the
         * hung-task detector or the load average. */
        wait_event_idle(pmem_proxy_work_wq,
            pmem_proxy_rb_occupancy() > 0 || kthread_should_stop());

        if (ring_buffer_pop(rb, &req) == 0) {
            pmo_handle_memcpy_sync(req.sk_req, req.vpma,
                req.pagenum, req.local_iv,
                req.sg_primary,
                req.sg_shadow,
                (PMO_DRAM_IS_ENABLED() &&
                !PMO_DRAM_AS_BUFFER_IS_ENABLED())
                    ? req.sg_working
                    : NULL);
            stage2_page_done(&req);
        } else if (kthread_should_stop()) {
            /* Stop only once the ring is empty, so no queued page is lost. */
            break;
        }
    }

    return 0;
}

/* Queue one page for stage 2.  Returns -ENOSPC when the ring (or the
 * configured capacity) is full and -ENODEV without a worker; the caller then
 * commits the page itself. */
int async_persist_page(struct skcipher_request *req,
    struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
    struct scatterlist *sg_primary, struct scatterlist *sg_shadow,
    struct scatterlist *sg_working)
{
    struct page_save_req persist_req = {
        .sk_req = req,
        .vpma = vpma,
        .pagenum = pagenum,
        .local_iv = local_iv,
        .sg_primary = sg_primary,
        .sg_shadow = sg_shadow,
        .sg_working = sg_working,
    };
    struct mm_struct *mm = current->mm;
    int ret, rb_size;

    if (!pmem_worker)
        return -ENODEV;

    /* Account for the page before the worker can see it, so its decrement
     * can never run ahead of this increment. */
    atomic_inc(&vpma->stage2_pending);
    if (vpma->stage2_map)
        set_bit(pagenum, vpma->stage2_map);

    ret = ring_buffer_push(&pmem_proxy_rb, &persist_req);
    if (ret) {
        if (vpma->stage2_map)
            clear_bit(pagenum, vpma->stage2_map);
        atomic_dec(&vpma->stage2_pending);
    } else {
        wake_up(&pmem_proxy_work_wq);
    }

    /* Occupancy after the push, so the recorded peak includes this page. */
    rb_size = pmem_proxy_rb_occupancy();
    if (ret == 0)
        pmo_stats_sum_ring_buffer(&mm->pmo_stats, rb_size);
    trace_printk("[RENAMING] (%d) = ring_buffer_push(%ld) done, size = %d\n",
        ret, (long)pagenum, rb_size);

    return ret;
}

/* Wait until every page this vpma queued is in primary and fenced. */
void pmem_proxy_drain_vpma(struct vpma_area_struct *vpma)
{
    wait_event(pmem_proxy_done_wq, atomic_read(&vpma->stage2_pending) == 0);
}

/* Wait until this one page's stage 2 is done (page-fault path). */
void pmem_proxy_page_wait(struct vpma_area_struct *vpma, size_t pagenum)
{
    if (!vpma->stage2_map || !test_bit(pagenum, vpma->stage2_map))
        return;
    wait_event(pmem_proxy_done_wq, !test_bit(pagenum, vpma->stage2_map));
}

int pmem_proxy_rb_occupancy(void)
{
    int head = atomic_read(&pmem_proxy_rb.head);
    int tail = atomic_read(&pmem_proxy_rb.tail);
    return CIRC_CNT(head, tail, RING_MAX_SIZE);
}

/* Stop the worker after it has emptied the ring.  Not called on the psync
 * path any more: the worker is long-lived. */
void pmem_proxy_exit(void)
{
    mutex_lock(&pmem_worker_lock);
    if (pmem_worker) {
        kthread_stop(pmem_worker);
        pmem_worker = NULL;
    }
    mutex_unlock(&pmem_worker_lock);
}
