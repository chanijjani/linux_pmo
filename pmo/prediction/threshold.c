#include "prediction.h"

/* This is confusing, but it seems to work. TODO, sort this out. */
void pmo_towards_access(struct vpma_area_struct *vpma, size_t offset)
{
	atomic_set(&vpma->prediction[offset], 0);
        return;
}


bool pmo_page_should_destroy(struct vpma_area_struct *vpma, size_t offset)
{
	pmo_inc_total_predictions(vpma);
        return (atomic_read(&vpma->prediction[offset]) >= CONFIG_PMO_THRESHOLD);
}


void pmo_towards_or_set_inert(struct vpma_area_struct *vpma, size_t offset)
{
        atomic_add_unless (&vpma->prediction[offset], 1, CONFIG_PMO_MAX_STATES);
        return;
}
