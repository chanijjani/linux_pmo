#ifndef __PMO_ALLOC_H_
#define __PMO_ALLOC_H_
struct pmo_alloc_struct {
        struct pmo_free_area *free_area;
        char *bitfield;
        __u64 phys_bitfield;
};
#endif
