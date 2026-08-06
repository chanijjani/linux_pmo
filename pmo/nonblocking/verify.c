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

void pmo_async_obtain_shadow_hash(struct vpma_area_struct *vpma, size_t pagenum)
{
	kthread_unpark(vpma->working_data[pagenum].shadowhash_thread);
	return;
}

void pmo_async_obtain_primary_hash(struct vpma_area_struct *vpma, size_t pagenum)
{
	kthread_unpark(vpma->working_data[pagenum].primaryhash_thread);
	return;
}

void nonblocking_verify_fault(struct vpma_area_struct *vpma,
		unsigned long pagenum)
{
	kthread_unpark(vpma->working_data[pagenum].verify_thread);
	return;
}

int _shadowhash_thread(void *_fault_ptr)
{
	struct fault_ptr_struct *fault_ptr = 
		(struct fault_ptr_struct *)_fault_ptr;
	struct vpma_area_struct * vpma = fault_ptr->vpma;
	unsigned long int pagenum = fault_ptr->pagenum;
	void *primary = pagenum * PAGE_SIZE + vpma->primary;

	while(!kthread_should_stop()) {
		pmo_obtain_shadow_hash(vpma, pagenum * PAGE_SIZE);
		if(kthread_should_park())
			kthread_parkme();
	}

	return 0;
}

int _primaryhash_thread(void *_fault_ptr)
{
	struct fault_ptr_struct *fault_ptr = 
		(struct fault_ptr_struct *)_fault_ptr;
	struct vpma_area_struct * vpma = fault_ptr->vpma;
	unsigned long int pagenum = fault_ptr->pagenum;
	void *primary = pagenum * PAGE_SIZE + vpma->primary;

	while(!kthread_should_stop()) {
		pmo_assign_primary_hash(vpma, pagenum);
		if(kthread_should_park())
			kthread_parkme();
	}

	return 0;
}

void pmo_initialize_verify_thread(struct fault_ptr_struct *fault_ptr,
		int current_cpu)
{
	struct vpma_area_struct *vpma = fault_ptr->vpma;
	unsigned long int pagenum = fault_ptr->pagenum;

	char thread_name[32];

	sprintf(thread_name, "verify_%s_%d", vpma->name, pagenum);
	vpma->working_data[pagenum].verify_thread = 
		kthread_create_on_node(_verify_fault_thread,
		       	fault_ptr, cpu_to_node(current_cpu), thread_name);

	/* TODO: figure out a better way to do this */
	kthread_bind(vpma->working_data[pagenum].verify_thread,
				pagenum%nr_cpu_ids); 
	kthread_park(vpma->working_data[pagenum].verify_thread);
	return;
}

void pmo_initialize_hash_thread(struct fault_ptr_struct *fault_ptr,
		bool is_shadowhash, int current_cpu)
{
	struct vpma_area_struct *vpma = fault_ptr->vpma;
	unsigned long int pagenum = fault_ptr->pagenum;

	char thread_name[32];

	sprintf(thread_name, is_shadowhash? "shadowhash_%s_%d" :
			"primaryhash_%s_%d", vpma->name, pagenum);


	if (is_shadowhash)
		vpma->working_data[pagenum].shadowhash_thread = 
			kthread_create_on_node(_shadowhash_thread,
					fault_ptr, cpu_to_node(current_cpu),
					thread_name);
	else
		vpma->working_data[pagenum].primaryhash_thread =
			kthread_create_on_node(_primaryhash_thread,
					fault_ptr, cpu_to_node(current_cpu),
					thread_name);

	kthread_bind(is_shadowhash ? 
			vpma->working_data[pagenum].shadowhash_thread :
			vpma->working_data[pagenum].primaryhash_thread,
			pagenum%nr_cpu_ids);

	kthread_park(is_shadowhash ? 
			vpma->working_data[pagenum].shadowhash_thread :
			vpma->working_data[pagenum].primaryhash_thread);
	return;
	
}

void pmo_initialize_async_thread(struct vpma_area_struct *vpma)
{
	char thread_name[32];
	int current_cpu = current->cpu, i;
	for (i = 0; i < vpma->pmo_ptr->size_in_pages; i++) {
		struct fault_ptr_struct *fault_ptr =
			kvmalloc(sizeof(struct fault_ptr_struct),
					GFP_KERNEL);
		fault_ptr->vpma = vpma;
		fault_ptr->pagenum = i;
		pmo_initialize_verify_thread(fault_ptr,
				i % nr_cpu_ids);
		pmo_initialize_hash_thread(fault_ptr, true,
				(i + 1) % nr_cpu_ids);
		pmo_initialize_hash_thread(fault_ptr, false,
				(i + 2) % nr_cpu_ids);
	}

	return;
}
