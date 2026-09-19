#include "../pmo.h"

struct fault_ptr_struct 
{
	unsigned long int pagenum;
	struct vpma_area_struct *vpma;
};

struct checksum_work {
	struct work_struct work;
	struct vpma_area_struct *vpma;
	unsigned long int pagenum;
	unsigned int num_pages;
};

static struct workqueue_struct *verify_wq;

void _checksum_work_func(struct work_struct *work) {
	struct checksum_work *cwork = container_of(work,
		struct checksum_work, work);

	struct vpma_area_struct * vpma = cwork->vpma;
	unsigned long int pagenum = cwork->pagenum;
	unsigned int i;

	for (i = 0; i < cwork->num_pages; i++) {
		void *primary = (pagenum + i) * PAGE_SIZE + vpma->primary;
		trace_printk("[NEW] ASYNC Checksum Verification --> TASK, page_num[%d] (batch %d/%d)\n",
			pagenum + i, i + 1, cwork->num_pages);
		handle_pmo_hash_identical(vpma, primary, pagenum + i, true);
	}

	kfree(cwork);
}

int _verify_fault_thread(void *_fault_ptr )
{
	struct fault_ptr_struct *fault_ptr = 
		(struct fault_ptr_struct *)_fault_ptr;
	struct vpma_area_struct * vpma = fault_ptr->vpma;
	unsigned long int pagenum = fault_ptr->pagenum;
	void *primary = pagenum * PAGE_SIZE + vpma->primary;

	while(!kthread_should_stop()) {
		handle_pmo_hash_identical(vpma, primary, pagenum, true);
		if(kthread_should_park())
			kthread_parkme();
	}

	return 0;
}

void nonblocking_verify_fault(struct vpma_area_struct *vpma,
		unsigned long pagenum)
{
	int thread_num = PMO_GET_ASYNC_WOKRER_NUM();
	int batch_size = PMO_GET_CHECKSUM_BATCH_SIZE();

	if (thread_num > 1) {
		unsigned long flags;
		struct checksum_work *cwork = NULL;
		bool enqueue_now = false;

		spin_lock_irqsave(&vpma->verify_batch_lock, flags);

		if (batch_size > 1 && vpma->active_verify_batch) {
			struct checksum_work *active = vpma->active_verify_batch;
			if (pagenum == active->pagenum + active->num_pages &&
				active->num_pages < batch_size) {
				active->num_pages++;
				spin_unlock_irqrestore(&vpma->verify_batch_lock, flags);
				return;
			} else {
				// Current batch is full or non-contiguous, enqueue it
				cwork = active;
				vpma->active_verify_batch = NULL;
				enqueue_now = true;
			}
		}

		if (enqueue_now && cwork) {
			queue_work(verify_wq, &cwork->work);
		}

		// Create a new batch or single item
		cwork = kmalloc(sizeof(*cwork), GFP_ATOMIC); // Use ATOMIC as we are in spinlock
		if (!cwork) {
			spin_unlock_irqrestore(&vpma->verify_batch_lock, flags);
			return;
		}
		cwork->vpma = vpma;
		cwork->pagenum = pagenum;
		cwork->num_pages = 1;
		INIT_WORK(&cwork->work, _checksum_work_func);

		if (batch_size > 1) {
			vpma->active_verify_batch = cwork;
			spin_unlock_irqrestore(&vpma->verify_batch_lock, flags);
		} else {
			spin_unlock_irqrestore(&vpma->verify_batch_lock, flags);
			queue_work(verify_wq, &cwork->work);
		}
	}
	else {
		trace_printk("[OLD] ASYNC Checksum Verification --> Unpark the verify_thread\n");
		kthread_unpark(vpma->working_data[pagenum].verify_thread);
	}

	return;
}

void pmo_flush_verify_batch(struct vpma_area_struct *vpma)
{
	unsigned long flags;
	struct checksum_work *cwork = NULL;

	spin_lock_irqsave(&vpma->verify_batch_lock, flags);
	if (vpma->active_verify_batch) {
		cwork = vpma->active_verify_batch;
		vpma->active_verify_batch = NULL;
	}
	spin_unlock_irqrestore(&vpma->verify_batch_lock, flags);

	if (cwork) {
		queue_work(verify_wq, &cwork->work);
	}
}

void pmo_initialize_verify_thread(struct vpma_area_struct *vpma)
{
	int thread_num = PMO_GET_ASYNC_WOKRER_NUM();
	if (thread_num > 1) {
		trace_printk("[NEW] ASYNC Checksum Execution --> Workers (%d)\n", PMO_GET_ASYNC_WOKRER_NUM());
		int num_workers = PMO_GET_ASYNC_WOKRER_NUM();
		if (num_workers > num_online_cpus())
			num_workers	= num_online_cpus();
		verify_wq = alloc_workqueue("integrity_verify_wq", WQ_UNBOUND | WQ_CPU_INTENSIVE, num_workers);
		if (verify_wq) {
			trace_printk("Verification Queue is created successfully\n");
		} else {
			PMO_DISABLE_ASYNC_CHECKSUM();
			trace_printk("Fail to create the Verification Queue. Disable Async. Verification\n");
		}
	}
	else if (thread_num == 1) {
		char thread_name[32];
		int current_cpu = current->cpu, i;
		trace_printk("[OLD] ASYNC Checksum Execution\n");
		for (i = 0; i < vpma->pmo_ptr->size_in_pages; i++) {
			struct fault_ptr_struct *fault_ptr =
				kvmalloc(sizeof(struct fault_ptr_struct), GFP_KERNEL);
			fault_ptr->vpma = vpma;
			fault_ptr->pagenum = i;
			sprintf(thread_name, "verify_%s_%d", vpma->name, i);
			vpma->working_data[i].verify_thread =
				kthread_create_on_node(_verify_fault_thread,
						fault_ptr, cpu_to_node(current_cpu), thread_name);
				/* TODO: figure out a better way to do this */
				kthread_bind(vpma->working_data[i].verify_thread, i%nr_cpu_ids);
				kthread_park(vpma->working_data[i].verify_thread);
		}
	}
	else {
		PMO_DISABLE_ASYNC_CHECKSUM();
		trace_printk("Abnormal Async. Settings. Disable Async. Verification\n");
	}

	return;
}

void pmo_cleanup_verify_workers(void)
{
    if (verify_wq) {
        destroy_workqueue(verify_wq);
		trace_printk("[NEW] Destroy the verification queue SUCCESSFULLY\n");
	}
	else {
		trace_printk("Abnormal Control flow, NO verification queue to clean up\n");
	}
}
