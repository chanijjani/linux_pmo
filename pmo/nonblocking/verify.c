#include "../pmo.h"

struct fault_ptr_struct 
{
	unsigned long int pagenum;
	struct vpma_area_struct *vpma;
};


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
	kthread_unpark(vpma->working_data[pagenum].verify_thread);
	return;
}

void pmo_initialize_verify_thread(struct vpma_area_struct *vpma)
{
	char thread_name[32];
	int current_cpu = current->cpu, i;
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

	return;
}
