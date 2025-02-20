#include "../pmo.h"
#include "markov.h"
#include "stride.h"

long long int pmo_decide_best_path(struct task_struct *tsk, long long int m)
{
	long long int best_path = LLONG_MIN;
	if(PMO_MARKOV_IS_ENABLED())
		best_path = pmo_decide_best_markov_path(tsk, m);
	else if(PMO_STRIDE_IS_ENABLED())
		best_path = pmo_decide_best_stride(tsk, m);

	return best_path;
}

void pmo_increment_entry(struct task_struct *tsk, long long int pagenum) 
{
	if (PMO_MARKOV_IS_ENABLED())
		pmo_increment_markov_entry(tsk, pagenum);
	else if (PMO_STRIDE_IS_ENABLED())
		pmo_increment_stride_entry(tsk, pagenum);

	return;
}

void pmo_initialize_chain(struct task_struct *tsk, size_t page_size) 
{
	if (PMO_MARKOV_IS_ENABLED())
		pmo_initialize_markov_chain(current, page_size);
	else if (PMO_STRIDE_IS_ENABLED())
		pmo_initialize_stride_chain(tsk, page_size);

	return;
}



void pmo_destroy_entries(struct task_struct *tsk)
{
	if (PMO_MARKOV_IS_ENABLED())
		pmo_destroy_markov_entries(tsk);
	else if (PMO_STRIDE_IS_ENABLED())
		pmo_destroy_stride_entries(tsk);

	return;
}

