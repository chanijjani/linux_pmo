/* Don't include this if we're using the new nopagewalk code */
#ifdef CONFIG_PMO_PAGEWALK
#ifndef __PMO_PAGEWALK_H_
#define __PMO_PAGEWALK_H_
#include "pmo.h"

#define reset_dirtypage_pointer(vpma)
struct pmo_pages;
inline void pmo_persist(struct vpma_area_struct *vpma, unsigned long int address,
		struct pmo_pages **dirty_ll);
inline void pmo_unset_dirtybits(struct vpma_area_struct *vpma);
void memcpy_dirtypages(struct pmo_pages **dirty_ll,
		struct vpma_area_struct *vpma);
inline void add_to_dirtypages(struct vpma_area_struct *vpma,
                struct pmo_pages *page_to_add);
inline void vpma_clear(struct vpma_area_struct *vpma);

inline void vpma_init(struct vpma_area_struct *vpma);
#endif
#endif
