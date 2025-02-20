/*************************************************************************** 
 * Copyright (C) 2021-2022 Derrick Greenspan and the University of Central *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA.               *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY   *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or       *
 * FITNESS FOR A PARTICULAR PURPOSE.                                       *
 ***************************************************************************
 * PMO Recovery code.							   *
 ***************************************************************************/

#include "pmo.h"

int recover(struct pmo_entry *pmo, char access_type, char *key)
{
	void *primary, *shadow;
	__u64 size = pmo->size_in_pages*PAGE_SIZE, 
	      address = pmo->pm_primary * PAGE_SIZE + metadata_start;
	
	char state = (pmo->state);
	char new = ((state >>  6) & 1); 
	char decrypted = ((state >> 7) & 1);

	printk("Initiating recovery for PMO %s of state %d\n", pmo->name, state);
	if(access_type == 'w' && atomic_read(&pmo->boot_id) == get_boot_id() && 
			is_alive_pid(atomic_read(&pmo->pid))) {
		printk("Refusing to attach a PMO as a write while process %d " 
				"has also attached it\n", atomic_read(&pmo->pid));
		return -1;
	}

        primary = pmo_map(address, PAGE_ALIGN(size));
	
	/* Of course, the shadow needs to be determined better */
        shadow = pmo_map(address+PAGE_ALIGN(size), PAGE_ALIGN(size));

	/* We should check for this and have not called the recovery code. */
	WARN_ON(state == SUCCESS);
	WARN_ON(!primary);
	WARN_ON(!shadow);

	if(new) {
		printk("PMO was never successfully detached after creation. \n");
		/* There might still be garbage data here, so to be sure... */
		memset(primary, 0, PAGE_ALIGN(size));
		memset(shadow, 0, PAGE_ALIGN(size));
		pmo_unlock_bit(7,pmo);
		pmo_unmap(primary);
		pmo_unmap(shadow);
		return 1; /* Nothing to recover */
	}

	/* State should be state masked by 0x80 */
	if(decrypted)
		state = state & ~(0x80);

	/* Not sure how recovery logic works/affected in case of secure	   * 
	 * attach/detach, so skipping recovery if its secure attach/detach */
//	if(!secure_design) {
//		printk("Not secure!\n");
		switch(state) {
			case(READING):
			case(COMPLET):
				printk("Detach was unclean. Current operation %d\n",
					       	state);
				pmo_unmap(primary);
				pmo_unmap(shadow);
				return 1; /* Nothing to recover */
			case(WRITING):
			case(PERSIST):
				if(pmo_bit_is_set(7, pmo)) {
					printk("Restoring corrupted shadow\n");
					memcpy(shadow, primary, size);
					pmo_unlock_bit(7,pmo);
				}
				else {
					printk("Recovering from primary.\n");
					memcpy_flushcache(shadow, primary, size);
				}
				pmo_unmap(primary);
				pmo_unmap(shadow);
				return 1;

			case(COPYING):
				if(pmo_bit_is_set(7, pmo)) {
					printk("Restoring corrupted primary\n");
					memcpy(primary, shadow, size);
					pmo_unlock_bit(7, pmo);
				}
				else {
					printk("Recovering from shadow.\n");
					memcpy_flushcache(primary, shadow, size);
				}
				pmo_unmap(primary);
				pmo_unmap(shadow);
				return 1;

			default:
				printk(KERN_ERR "Current operation %d unsupported\n",
					       	state);
				pmo_unmap(primary);
				pmo_unmap(shadow);
				return 0;
		}
	//}	
	pmo_unmap(primary);
	pmo_unmap(shadow);
	printk("State is clean! Nothing to do");
	return 0;
}
