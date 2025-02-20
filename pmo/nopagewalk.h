/* Don't include this if we are using the old pagewalk code */
#ifdef CONFIG_PMO_NO_PAGEWALK
#ifndef __PMO_NO_PAGEWALK_H_
#define __PMO_NO_PAGEWALK_H_

struct pmo_pages;
/* Generate a linked list of dirty pages from the faulted pages, instead of
 * performing a dirtypage walk. This is passed into the memcpy_flushcache
 * function. */
inline void pmo_persist(struct vpma_area_struct *vpma, unsigned long int address,
                struct pmo_pages **dirty_ll);
inline void pmo_unset_dirtybits(struct vpma_area_struct *vpma);
void memcpy_flushcache_dirtypages(struct pmo_pages **dirty_ll,
                struct vpma_area_struct *vpma);
inline void add_to_dirtypages(struct vpma_area_struct *vpma,
                struct pmo_pages *page_to_add);

inline void vpma_clear(struct vpma_area_struct *vpma);
inline void vpma_init(struct vpma_area_struct *vpma);

#endif
#endif

