#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/err.h>
#include "../pmo.h"

/*
 * Per-vpma teardown worker.
 *
 * do_detach() no longer hands this thread a held rw_semaphore: an rwsem must be
 * released by the task that acquired it, so disable_vpma_access() now takes and
 * releases vpma->pm_sem itself.  All this thread does is run that teardown off
 * the detaching task's critical path, which is what makes detach non-blocking.
 *
 * Work is signalled with a counter plus a wait queue rather than with
 * kthread_park()/kthread_unpark().  Park/unpark cannot carry a work item: an
 * unpark that arrived while the previous iteration was still finishing was
 * silently swallowed (the teardown then never ran and pm_sem stayed locked
 * forever), and a park that lost the race let the loop run a second time,
 * producing an up_write() with no matching down_write().
 *
 * disable_pending is incremented by the submitter and decremented here only
 * *after* disable_vpma_access() has returned, so waiting for it to reach zero
 * is a reliable drain -- see pmo_wait_disable_work().
 */
int _disable_vpma_access_thread(void *vpma_ptr)
{
	struct vpma_area_struct *vpma = (struct vpma_area_struct *)vpma_ptr;

	for (;;) {
		/* wait_event_idle(), not wait_event(): an idle worker parks in
		 * TASK_IDLE rather than TASK_UNINTERRUPTIBLE, so khungtaskd
		 * (CONFIG_DETECT_HUNG_TASK, on from #36) does not count a
		 * worker that is merely waiting for its next detach as a hung
		 * task -- with kernel.hung_task_panic=1 that would panic the
		 * box 120 s after the first PMO attach.  It also keeps these
		 * threads out of the load average. */
		wait_event_idle(vpma->disable_wq,
				atomic_read(&vpma->disable_pending) ||
				kthread_should_stop());

		if (!atomic_read(&vpma->disable_pending)) {
			if (kthread_should_stop())
				break;
			continue;
		}

		disable_vpma_access(vpma);

		atomic_dec(&vpma->disable_pending);
		wake_up(&vpma->disable_done_wq);
	}

	return 0;
}

void nonblocking_disable_vpma_access(struct vpma_area_struct *vpma)
{
	/* No worker (creation failed): fall back to tearing down inline. */
	if (!vpma->disable_thread) {
		disable_vpma_access(vpma);
		return;
	}

	atomic_inc(&vpma->disable_pending);
	wake_up(&vpma->disable_wq);
	return;
}

/*
 * Block until any queued teardown has completed.  Must be called before the
 * vpma is freed: the worker dereferences it and takes its pm_sem, so work that
 * outlives the vpma is a use-after-free.
 */
void pmo_wait_disable_work(struct vpma_area_struct *vpma)
{
	if (!vpma->disable_thread)
		return;

	/* Deliberately wait_event() and not wait_event_idle(): this waits on
	 * work that is expected to complete promptly, so if it ever blocks for
	 * hung_task_timeout_secs that is a genuine hang and khungtaskd should
	 * report it. */
	wait_event(vpma->disable_done_wq,
			!atomic_read(&vpma->disable_pending));
	return;
}

void pmo_kill_disable_thread(struct vpma_area_struct *vpma)
{
	struct task_struct *thread = vpma->disable_thread;

	if (!thread)
		return;

	/* Drain first, then stop: kthread_stop() only breaks the loop, it does
	 * not run pending work, and dropping it would leak the PMO lock bits
	 * and the metadata update that disable_vpma_access() performs. */
	pmo_wait_disable_work(vpma);

	/* kthread_stop() returns only once the thread function has returned,
	 * so the worker is guaranteed to be done touching vpma afterwards. */
	vpma->disable_thread = NULL;
	kthread_stop(thread);
	return;
}

void pmo_initialize_detach_thread(struct vpma_area_struct *vpma)
{
	char thread_name[32];
	int current_cpu = current->cpu;

	init_waitqueue_head(&vpma->disable_wq);
	init_waitqueue_head(&vpma->disable_done_wq);
	atomic_set(&vpma->disable_pending, 0);

	/* vpma->name is up to 50 bytes; bound the write (the kthread comm is
	 * truncated to TASK_COMM_LEN anyway). */
	snprintf(thread_name, sizeof(thread_name), "detach_%s", vpma->name);

	vpma->disable_thread = 
		kthread_create_on_node(_disable_vpma_access_thread, vpma, cpu_to_node(current_cpu), thread_name);

	if (IS_ERR_OR_NULL(vpma->disable_thread)) {
		printk(KERN_WARNING "PMO: no detach thread for %s (%ld); "
				"detach will run inline\n",
				vpma->name, PTR_ERR(vpma->disable_thread));
		vpma->disable_thread = NULL;
		return;
	}

	kthread_bind(vpma->disable_thread, (current->cpu + 40)%nr_cpu_ids); /* TODO: figure out a better way to do this */
	wake_up_process(vpma->disable_thread);
	return;
}
