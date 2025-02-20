#include "../pmo.h"

int _disable_vpma_access_thread(void *vpma_ptr)
{
	struct vpma_area_struct *vpma = (struct vpma_area_struct *)vpma_ptr;
	while(!kthread_should_stop()) {
		disable_vpma_access(vpma);
		if(kthread_should_park())
			kthread_parkme();
	}

	return 0;
}

void nonblocking_disable_vpma_access(struct vpma_area_struct *vpma)
{
	kthread_unpark(vpma->disable_thread);
	return;
}

void pmo_initialize_detach_thread(struct vpma_area_struct *vpma)
{
	char thread_name[32];
	int current_cpu = current->cpu;
	sprintf(thread_name, "detach_%s", vpma->name);
	vpma->disable_thread = 
		kthread_create_on_node(_disable_vpma_access_thread, vpma, cpu_to_node(current_cpu), thread_name);
	kthread_bind(vpma->disable_thread, (current->cpu + 40)%nr_cpu_ids); /* TODO: figure out a better way to do this */
	kthread_park(vpma->disable_thread);
	return;
}
