#include "pmo.h"

void pmo_destroy_stride_entries(struct vpma_area_struct *vpma)
{
	int i;
	size_t num_pages;
	struct markov_node *cursor, *temp;

	if(!PMO_STRIDE_IS_ENABLED())
		return;

	
       	num_pages = vpma->markov_table.page_count;


	/* Don't allow this to be destroyed again */
	vpma->has_predict_entries = false;

	for(i = 0; i < num_pages; i++) {
		if(list_empty(&vpma->markov_table.markov_negative_weights[i].list))
			continue;

		spin_lock(&vpma->markov_table.markov_negative_weights[i].lock);
		list_for_each_entry_safe(cursor, temp, 
				&vpma->markov_table.markov_negative_weights[i].list,
				list)
		{
			list_del(&cursor->list);
			kvfree(cursor);
		}

		spin_unlock(&vpma->markov_table.markov_negative_weights[i].lock);
	}

	for(i = 0; i < num_pages; i++) {
		if(list_empty(&vpma->markov_table.markov_positive_weights[i].list))
			continue;

		spin_lock(&vpma->markov_table.markov_positive_weights[i].lock);
		list_for_each_entry_safe(cursor, temp, 
				&vpma->markov_table.markov_positive_weights[i].list,
				list)
		{
			list_del(&cursor->list);
			kvfree(cursor);
		}

		spin_unlock(&vpma->markov_table.markov_positive_weights[i].lock);
	}


	return;
}

void __pmo_init_stride_node(struct markov_node *node)
{
	if(!PMO_STRIDE_IS_ENABLED())
		return;

	atomic_set(&node->initialized, 0);
	node->data.stride.is_negative = false;
	atomic_set(&node->weight, -1);
	node->data.stride.value = 0;

	INIT_LIST_HEAD(&node->list);
	spin_lock_init(&node->lock);
	return;
}

void _init_stride_nodes(struct vpma_area_struct *vpma, size_t num_pages)
{
	int i; 
	if(!PMO_STRIDE_IS_ENABLED())
		return;

	/* FIXME: This uses too much memory */
	vpma->markov_table.markov_positive_weights = kvmalloc(sizeof(struct pmo_markov_table) * num_pages, GFP_KERNEL); 
	vpma->markov_table.markov_negative_weights = kvmalloc(sizeof(struct pmo_markov_table) * num_pages, GFP_KERNEL);
	vpma->markov_table.page_count = num_pages;

	for (i = 0; i < num_pages; i++) {
		__pmo_init_stride_node(&vpma->markov_table.markov_positive_weights[i]);
		__pmo_init_stride_node(&vpma->markov_table.markov_negative_weights[i]);
	}

	/* FIXME: vpma should have a linked list of pointers... or maybe an array */

	atomic_set(&vpma->markov_table.most_recent, 0);
	atomic_set(&vpma->markov_table.last_page_accessed, 0);
	return;

}

void pmo_initialize_stride_chain(struct vpma_area_struct *vpma, size_t num_pages)
{
	if(!PMO_STRIDE_IS_ENABLED()) 
		return;
	/*
	if(atomic_read(&vpma->markov_table.initialized))
		return;
	else
		printk("Initialized stride chain\n");
		*/


	/* TODO: This should be called every time a thread is spawned, if the
	 * thread is associated with a PMO. 
	 * What should happen then is that when a thread is spawned, the
	 * function checks if there is an associated VPMA in vpma->mm, if
	 * so, the function spawns here. */

	_init_stride_nodes(vpma, num_pages);
	atomic_set(&vpma->markov_table.initialized, 1);

	return;
}

long long int _pmo_decide_best_stride(struct vpma_area_struct *vpma, size_t old_stride, bool is_negative)
{
	long long int max_weight = INT_MIN, best_path = INT_MIN;
	
	struct markov_node *conductor;
	if(!PMO_STRIDE_IS_ENABLED())
		return INT_MIN;

	/*
	spin_lock(is_negative ? 
			&vpma->markov_table.markov_negative_weights[old_stride].lock :
			&vpma->markov_table.markov_positive_weights[old_stride].lock);
			*/

	list_for_each_entry(conductor, is_negative ?
			&vpma->markov_table.markov_negative_weights[old_stride].list :
			&vpma->markov_table.markov_positive_weights[old_stride].list, list) {
		if(atomic_read(&conductor->weight)
				> max_weight && is_negative == conductor->data.stride.is_negative) {
			best_path = conductor->data.stride.is_negative ? 
				conductor->data.stride.value * -1:
				conductor->data.stride.value;
			max_weight = atomic_read(&conductor->weight);
		}
	}

	/*
	spin_unlock(is_negative ?
			&vpma->markov_table.markov_negative_weights[old_stride].lock:
			&vpma->markov_table.markov_positive_weights[old_stride].lock);
			*/

	return best_path;
}

long long int pmo_decide_best_stride(struct vpma_area_struct *vpma, long long int m)
{

	return (_pmo_decide_best_stride(vpma, abs(m), m < 0));
}



struct markov_node *_pmo_create_markov_stride_entry(long long int stride_value, size_t weight)
{
	struct markov_node *new_node;
	if(!PMO_STRIDE_IS_ENABLED())
		return NULL;

       	new_node = kvmalloc(sizeof(struct markov_node), GFP_KERNEL);

	atomic_set(&new_node->weight, weight);
	new_node->data.stride.value = abs(stride_value);
	new_node->data.stride.is_negative = (stride_value < 0);

	INIT_LIST_HEAD(&new_node->list);
	return new_node;
}

/* See if the entry exists in this linked list */
bool _pmo_find_markov_stride_weight(long long int old_stride, size_t new_stride,
		bool is_negative, bool update_weight, struct vpma_area_struct *vpma)
{
	struct markov_node *cursor;
	if(!PMO_STRIDE_IS_ENABLED())
		return false;

	if(new_stride == INT_MIN)
		return false;

	list_for_each_entry(cursor,old_stride < 0 ?
		       	&vpma->markov_table.markov_negative_weights[abs(old_stride)].list:
			&vpma->markov_table.markov_positive_weights[abs(old_stride)].list,
		       	list) {
		if(update_weight && cursor->data.stride.is_negative == is_negative
				&& cursor->data.stride.value == new_stride) {
			atomic_inc(&cursor->weight);
			atomic_set(&vpma->markov_table.most_recent, 
				is_negative ? new_stride * -1 :
			       	new_stride);
			return true;
		}
	}
	return false;
}

void pmo_increment_stride_entry(struct vpma_area_struct *vpma, signed long long int entry)
{
	struct markov_node *node;
	signed long long int most_recent = atomic_read(&vpma->markov_table.most_recent);

	if(!PMO_STRIDE_IS_ENABLED())
		return;

	if(most_recent != INT_MIN && 
			!_pmo_find_markov_stride_weight(most_recent, abs(entry), entry < 0, true, vpma)) {
		/* Create new node and add to end of linked list */
		node = _pmo_create_markov_stride_entry (entry, 1);
		node->data.stride.is_negative = entry < 0;
		atomic_set(&node->initialized, true);

		spin_lock(most_recent < 0 ?
				&vpma->markov_table.markov_negative_weights[abs(most_recent)].lock:
				&vpma->markov_table.markov_positive_weights[abs(most_recent)].lock);

		list_add_tail(&node->list, most_recent < 0 ?
				&vpma->markov_table.markov_negative_weights[abs(most_recent)].list:
				&vpma->markov_table.markov_positive_weights[abs(most_recent)].list);

		spin_unlock(most_recent < 0 ?
				&vpma->markov_table.markov_negative_weights[abs(most_recent)].lock:
				&vpma->markov_table.markov_positive_weights[abs(most_recent)].lock);
	}

	atomic_set(&vpma->markov_table.most_recent, entry);

	return;
}

