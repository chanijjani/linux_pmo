#include "pmo.h"
#include <linux/mm_types.h>

void pmo_dump_stats(struct pmo_stats_struct stats)
{
	printk("STATISTICAL INFORMATION FOR PROCESS %s FOLLOWS...\n", 
			current->comm);
	printk("Attach stall: %lld, Attach decrypt: %lld, Attach memcpy: %lld, Attach IV: %lld, Other attach: %lld\n",
			stats.attachtime_wait, stats.attachtime_decrypt - stats.attachtime_iv, stats.attachtime_memcpy,
			stats.attachtime_iv, stats.attachtime_other - (stats.attachtime_wait + (stats.attachtime_decrypt - stats.attachtime_iv) \
			       	+ stats.attachtime_memcpy + stats.attachtime_iv));
	printk("Detach: %lld\n", stats.detachtime);
	printk("Psync Total: %lld, Psync IV: %lld, Psync Encrypt: %lld, Psync Other: %lld\n",
		stats.psynctime_other, atomic_read(&stats.psynctime_iv),
		stats.psynctime_encrypt, stats.psynctime_other - stats.psynctime_encrypt - atomic_read(&stats.psynctime_iv));
	printk("Fault time: %lld\n\n", atomic_read(&stats.faulttime));
	printk("Total pages touched: %lld\n", stats.pages_touched);
	printk("Total pages attached: %lld\n", stats.total_pages);
	printk("Total attach waits: %lld\n", stats.attach_waits);
	printk("Total waiting time: %lld\n", stats.waiting_time);
	printk("PMO createtime: %lld\n", stats.createtime);

	printk("Total pages dirtied: %lld\ntotal possible pages that could have been touched: %lld\n",
			stats.pages_dirtied, stats.all_pages);

	printk ("Total accurate predictions: %lld\nTotal predictions that failed to fault: %lld\nTotal faults not associated with a prediction: %lld\nTotal Prediction waits: %lld\n",
			atomic_read(&stats.accurate_predictions),
			atomic_read(&stats.mispredict_no_faults),
			atomic_read(&stats.mispredict_faults),
			atomic_read(&stats.total_waits));

	return;
}
