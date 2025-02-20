#include "../pmo.h"

int _decryptahead_thread(void *vpma_ptr)
{
	/*
	char local_iv[16];
	struct skcipher_request * req = NULL;
	struct pmo_pages *cursor, *temp;
	struct vpma_area_struct *vpma = (struct vpma_area_struct *)vpma_ptr;
	struct tasklet_struct tasklet;

	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);


	}
	*/

	/*
	while(!kthread_should_stop()) {
		if (!req)  {
			req = skcipher_request_alloc(vpma->crypto.tfm, GFP_KERNEL);
			memcpy(local_iv, vpma->crypto.pmo_iv, 16);
		}

		list_for_each_entry_safe(cursor, temp, &vpma->crypto.decrypt_queue_ll->list, list) {
			_pmo_handle_page_dram_crypto_prediction(req, vpma, local_iv,
					&cursor->sg_primary, &cursor->sg_working,
					cursor->pagenum);
			list_del(&cursor->list);
			kfree(cursor);
		}

		printk("Just went through the entire list\n");
		
		if(kthread_should_park())
			kthread_parkme();
	}
			*/

	return 0;
}

void pmo_run_decryptahead_thread(struct vpma_area_struct *vpma)
{
	kthread_unpark(vpma->crypto.decryptahead_thread_ptr);
	return;
}

void pmo_initialize_decryptahead_thread(struct vpma_area_struct *vpma)
{
	/*
	char thread_name[32];
	int current_cpu = current->cpu;
	vpma->crypto.decrypt_queue_ll = create_dirty_sentinel();

	sprintf(thread_name, "decryptahead_%s_%d", vpma->name, current_cpu);
	vpma->crypto.decryptahead_thread_ptr = 
		kthread_create_on_node(_decryptahead_thread, vpma,
				cpu_to_node(current_cpu), thread_name);

	kthread_bind(vpma->crypto.decryptahead_thread_ptr,
			(current_cpu + 40)%nr_cpu_ids); 

	adfs
	if (!wake_up_process(vpma->crypto.decryptahead_thread_ptr))
		printk("Decryptahead thread was already running..\n");
	kthread_park(vpma->crypto.decryptahead_thread_ptr);
	*/
	return;
}
