/******************************************************************************
 * Copyright (C) 2023 Derrick Greenspan and the University of Central Florida *
 * (UCF)								      *
 ******************************************************************************
 * PMO Prediction							      *
 ******************************************************************************/

#ifndef __PMO_Prediction__
#define __PMO_Prediction__
#include "../pmo.h"

/* TODO: Move all this to a separate .c file ... */

#define PMO_DESTROYED_PAGE_BIT 0

bool pmo_page_should_destroy(struct vpma_area_struct *vpma, size_t offset);

void pmo_towards_access(struct vpma_area_struct *vpma, size_t offset);
void pmo_towards_or_set_inert(struct vpma_area_struct *vpma, size_t offset);

#endif
