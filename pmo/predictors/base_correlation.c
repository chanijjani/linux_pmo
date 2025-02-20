#include "../pmo.h"
#include "correlation.h"


void pmo_init_pair_correlation_table(struct vpma_area_struct * vpma)
{
	size_t num_pages = vpma->pmo_ptr->size_in_pages;
	int i;
	vpma->correlation_table = kvmalloc(sizeof(struct correlation_node *) *
			num_pages, GFP_KERNEL);
	for (i = 0; i < num_pages; i+++)
		vpma->correlation_table[i] = _pmo_init_correlation_node(i, -1, -1);

}
