/*****************************************************************************
 * Copyright (C) 2020 - 2023 Derrick Greenspan and the University of Central *
 * Florida (UCF)                                                             *
 *****************************************************************************
 * PMO Checksum calculation headers                                          *
 *****************************************************************************/

#ifndef __PMO_CHECKSUM_H
#define __PMO_CHECKSUM_H
struct pmo_range_struct {
        struct range sha256_range_primary,
                     sha256_range_shadow;
};
#endif
