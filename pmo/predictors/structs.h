/*************************************************************************** 
 * Copyright (C) 2024 Derrick Greenspan and the University of Central 	   *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * Markov predictor structs (to make sched.h happy)			   *
 ***************************************************************************/

#ifndef __PMO_MARKOV_STRUCTS_H__
#define __PMO_MARKOV_STRUCTS_H__


#define pmo_get_threadnum() \
	(current->pid - current->tgid)


#endif
