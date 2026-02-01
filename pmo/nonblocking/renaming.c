#include "../pmo.h"
#include <linux/circ_buf.h>

#define RING_MAX_SIZE 8192

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

static int pmem_worker_thread(void *data);
int pmem_proxy_rb_occupancy(void);

void pmem_proxy_init(void)
{
    memset(&pmem_proxy_rb, 0, sizeof(pmem_proxy_rb));
    atomic_set(&pmem_proxy_rb.head, 0);
    atomic_set(&pmem_proxy_rb.tail, 0);
    spin_lock_init(&pmem_proxy_rb.lock);

    pmem_worker = kthread_run(pmem_worker_thread,
        &pmem_proxy_rb, "pmem_worker");
}

static int ring_buffer_push(struct proxy_ring_buffer *rb,
    struct page_save_req *req)
{
    unsigned long flags;
    int next_head;

    spin_lock_irqsave(&rb->lock, flags);
    next_head = (atomic_read(&rb->head) + 1) % RING_MAX_SIZE;
    if (next_head == atomic_read(&rb->tail)) {
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

static int pmem_worker_thread(void *data)
{
    struct proxy_ring_buffer *rb = (struct proxy_ring_buffer *) data;
    struct page_save_req req;

    while (!kthread_should_stop()) {
        int rb_size = pmem_proxy_rb_occupancy();
        trace_printk("Current Ring buffer size = %d\n", rb_size);
        if (ring_buffer_pop(rb, &req) == 0) {
            pmo_handle_memcpy_sync(req.sk_req, req.vpma,
                req.pagenum, req.local_iv,
                req.sg_primary,
                req.sg_shadow,
                (PMO_DRAM_IS_ENABLED() &&
                !PMO_DRAM_AS_BUFFER_IS_ENABLED())
                    ? req.sg_working
                    : NULL);
        } else {
            trace_printk("[RENAMING] PARK pmem_worker_thread, Q(%d)\n",
                rb_size);
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(HZ / 10000);  // 0.1 ms, 100 = 10 ms
        }
    }

    return 0;
}

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

    int rb_size = pmem_proxy_rb_occupancy();
    int ret = ring_buffer_push(&pmem_proxy_rb, &persist_req);
    pmo_stats_sum_ring_buffer(&mm->pmo_stats, rb_size);
    trace_printk("[RENAMING] (%d) = ring_buffer_push(%d) done, size = %d\n",
        ret, pagenum, rb_size);

    return ret;
}

int pmem_proxy_rb_occupancy(void)
{
    int head = atomic_read(&pmem_proxy_rb.head);
    int tail = atomic_read(&pmem_proxy_rb.tail);
    return CIRC_CNT(head, tail, RING_MAX_SIZE);
}

void pmem_proxy_exit(void)
{
    if (pmem_worker) {
        kthread_stop(pmem_worker);
        pmem_worker = NULL;
    }

    memset(&pmem_proxy_rb, 0, sizeof(pmem_proxy_rb));
}
