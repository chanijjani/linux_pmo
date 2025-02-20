#include "prediction.h"


long long int towards_inert_count = 0,
    set_access_count = 0;
void pmo_towards_or_set_inert(struct vpma_area_struct *vpma, size_t offset)
{
//	printk("Towards inert %d value %lld\n", offset, atomic_read(&vpma->prediction[offset]));
	towards_inert_count++;
	atomic_dec_if_positive(&vpma->prediction[offset]);
	//pmo_inc_total_predictions(vpma);

        return;
}

bool pmo_page_should_destroy(struct vpma_area_struct *vpma, size_t offset)
{
	pmo_inc_total_predictions(vpma);
/*	printk("%d: CMP %lld < %lld\n... should destroy? %lld\n",
			offset,
			atomic_read(&vpma->prediction[offset]), CONFIG_PMO_THRESHOLD,
		       	atomic_read(&vpma->prediction[offset]) < CONFIG_PMO_THRESHOLD);
			*/
        return (atomic_read(&vpma->prediction[offset]) <= CONFIG_PMO_THRESHOLD);
}

void pmo_towards_access(struct vpma_area_struct *vpma, size_t offset)
{
	set_access_count++;
        atomic_add_unless (&vpma->prediction[offset], 1, CONFIG_PMO_MAX_STATES);
        return;
}

