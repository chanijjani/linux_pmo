#include "pmo.h"
bool pmo_page_should_destroy(struct vpma_area_struct *vpma, size_t offset)
{
        return 0; 
}

void pmo_towards_access(struct vpma_area_struct *vpma, size_t offset) 
{
        return;
}

void pmo_towards_or_set_inert(struct vpma_area_struct *vpma, size_t offset)
{
        return;
}
