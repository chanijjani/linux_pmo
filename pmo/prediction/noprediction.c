#include "../pmo.h"

void pmo_set_predict_init_state(struct vpma_area_struct *vpma, size_t pmo_size_in_pages)
{
	int i;
	for(i = 0; i < pmo_size_in_pages; i++) {
		atomic_set(&vpma->prediction[i], PREDICT_INIT_STATE);
		/* No page is destroyed until next attach/detach cycle... */
		PMO_CLEAR_PAGE_DESTROYED(vpma, i);
	}
	return;
}
