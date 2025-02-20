/*************************************************************************** 
 * Copyright (C) 2023-2024 Derrick Greenspan and the University of Central *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * Markov predictor							   *
 ***************************************************************************/

#ifndef __PMO_MARKOV_H__
#define __PMO_MARKOV_H__
#include <stddef.h>
#include "structs.h"

long long int pmo_decide_best_markov_path(struct task_struct *tsk, signed long long int m);
void pmo_increment_markov_entry(struct task_struct *tsk, size_t n);
void pmo_destroy_markov_entries(struct task_struct *tsk);
void pmo_initialize_markov_chain(struct task_struct *tsk, size_t num_pages);


#endif
