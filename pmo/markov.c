#include "pmo.h"

void pmo_destroy_markov_entries(struct vpma_area_struct *vpma)
{
	int i;
	size_t num_pages;
	struct markov_node *cursor, *temp;

	if(!PMO_MARKOV_IS_ENABLED())
		return;

	
       	num_pages = vpma->markov_table.page_count;


	/* Don't allow this to be destroyed again */
	vpma->is_pmo = false;

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

void __pmo_init_markov_node(struct markov_node *node)
{
	if(!PMO_MARKOV_IS_ENABLED())
		return;

	atomic_set(&node->initialized, 0);
	atomic_set(&node->weight, -1);
	node->data.address.x = -1;
	node->data.address.y = -1;

	INIT_LIST_HEAD(&node->list);
	spin_lock_init(&node->lock);
	return;
}

void _init_markov_nodes(struct vpma_area_struct *vpma, size_t num_pages)
{
	int i; 
	if(!PMO_MARKOV_IS_ENABLED())
		return;

	vpma->markov_table.markov_positive_weights = kvmalloc(sizeof(struct pmo_markov_table) * num_pages, GFP_KERNEL); 
	vpma->markov_table.page_count = num_pages;

	for (i = 0; i < num_pages; i++) 
		__pmo_init_markov_node(&vpma->markov_table.markov_positive_weights[i]);

	/* FIXME: vpma should have a linked list of pointers... or maybe an array */

	atomic_set(&vpma->markov_table.most_recent, 0);
	return;

}
void pmo_initialize_markov_chain(struct vpma_area_struct *vpma, size_t num_pages)
{
	if(!PMO_MARKOV_IS_ENABLED()) 
		return;
	if(atomic_read(&vpma->markov_table.initialized))
		return;


	/* TODO: This should be called every time a thread is spawned, if the
	 * thread is associated with a PMO. 
	 * What should happen then is that when a thread is spawned, the
	 * function checks if there is an associated VPMA in vpma->mm, if
	 * so, the function spawns here. */

	_init_markov_nodes(vpma, num_pages);
	atomic_set(&vpma->markov_table.initialized, 1);
	//spin_unlock(&vpma->markov_table.lock);

	return;
}

long long int pmo_decide_best_markov_path(struct vpma_area_struct *vpma, signed long long int m)
{
	long long int max_weight = -1, best_path = -1, temp_weight;
	
	struct markov_node *conductor;
	if(!PMO_MARKOV_IS_ENABLED())
		return -1;

//	spin_lock(&vpma->markov_table.markov_positive_weights[m].lock);
	if (!atomic_read(&vpma->markov_table.initialized)) {
		printk (KERN_WARNING "markov not initialized yet\n");
		return -1;
	}
	list_for_each_entry(conductor, &vpma->markov_table.markov_positive_weights[m].list, list) {
		if(atomic_read(&conductor->weight) > max_weight) {
			best_path = conductor->data.address.y;
			max_weight = atomic_read(&conductor->weight);
		}
//		printk("Temp weight is %lX, cf max weight %lX\n", temp_weight, max_weight);
	}
//	spin_unlock(&vpma->markov_table.markov_positive_weights[m].lock);
	return best_path;
}



struct markov_node *_pmo_create_markov_node_entry(size_t x, size_t y, size_t weight)
{
	struct markov_node *new_node;
	if(!PMO_MARKOV_IS_ENABLED())
		return NULL;

       	new_node = kvmalloc(sizeof(struct markov_node), GFP_KERNEL);

	atomic_set(&new_node->weight, weight);
	new_node->data.address.x = x;
	new_node->data.address.y = y;

	INIT_LIST_HEAD(&new_node->list);
	spin_lock_init(&new_node->lock);
	return new_node;
}

/* See if the entry exists in this linked list */
bool _pmo_find_markov_entry_weight(size_t x, size_t y, bool update_weight,
		struct vpma_area_struct *vpma)
{
	struct markov_node *cursor;
	if(!PMO_MARKOV_IS_ENABLED())
		return false;
	list_for_each_entry(cursor,
			&vpma->markov_table.markov_positive_weights[x].list, list) {
		if(update_weight && cursor->data.address.y == y) {
			atomic_inc(&cursor->weight);
			atomic_set(&vpma->markov_table.most_recent, y);
			return true;
		}
	}
	return false;
}

void pmo_increment_markov_entry(struct vpma_area_struct *vpma, size_t entry)
{
	struct markov_node *node;
	size_t most_recent = atomic_read(&vpma->markov_table.most_recent);

	if(!PMO_MARKOV_IS_ENABLED())
		return;

	if (most_recent == entry)
		return;

	if(!_pmo_find_markov_entry_weight(most_recent, entry, true, vpma)) {
		/* Create new node and add to end of linked list */
		node = _pmo_create_markov_node_entry (most_recent, entry, 1);
		atomic_set(&node->initialized, 1);
		spin_lock(&vpma->markov_table.markov_positive_weights[most_recent].lock);
		list_add_tail(&node->list, &vpma->markov_table.markov_positive_weights[most_recent].list);
		spin_unlock(&vpma->markov_table.markov_positive_weights[most_recent].lock);
	}

	atomic_set(&vpma->markov_table.most_recent, entry);

	return;
}

