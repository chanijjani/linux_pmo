#ifndef __PMO_STRIDE_H__
#define __PMO_STRIDE_H__
#include <stddef.h>
#include "structs.h"

long long int pmo_decide_best_stride(struct task_struct *tsk, size_t m);
void pmo_increment_stride_entry(struct task_struct *tsk, size_t n);
void pmo_destroy_stride_entries(struct task_struct *tsk);
void pmo_initialize_stride_chain(struct task_struct *tsk, size_t num_pages);
#endif
