#include "pmo.h"
#include <linux/mm_types.h>
#include <linux/proc_fs.h>


void pmo_set_mode (char *mode)
{
	/*NOENC, PPs, PPb, WHOLE, PPsIVd, PPbIVd, PPsIVp, PPbIVp, WHOLEIV*/
	int mode_to_set;
	if(kstrtoint(mode, 0, (int *)&mode_to_set) != 0) {
		printk("Could not set unknown mode %s \n", mode);
		return;
	}
	switch(mode_to_set) {
		case(0): /* NOENC */
			printk(KERN_INFO "Setting PMO system to NOENC\n");
			PMO_SET_NOENC();
			PMO_SET_IV_NOENC();
			break;
		case(1): /* PPs */
			printk(KERN_INFO "Setting PMO system to PPs\n");
			PMO_SET_PPs();
			PMO_SET_IV_NOENC();
			break;
		case(2): /* PPb */
			printk(KERN_INFO "Setting PMO system to PPb\n");
			PMO_SET_PPb();
			PMO_SET_IV_NOENC();
			break;
		case(3): /* Whole */
			printk(KERN_INFO "Setting PMO system to WHOLE\n");
			PMO_SET_WHOLE();
			PMO_SET_IV_NOENC();
			break;
		case(4): /*PPsIVp */
			printk(KERN_INFO "Setting PMO system to PPsIVp\n");
			PMO_SET_PPs();
			PMO_SET_IV_PSYNC();
			break;
		case(5): /* PPbIVp */
			printk(KERN_INFO "Setting PMO system to PPbIVp\n");
			PMO_SET_PPb();
			PMO_SET_IV_PSYNC();
			break;
		case(6): /* PPsIVd */
			printk(KERN_INFO "Setting PMO system to PPsIVd\n");
			PMO_SET_PPs();
			PMO_SET_IV_DETACH();
			break;
		case(7): /* PPbIVd */
			printk(KERN_INFO "Setting PMO system to PPbIVd\n");
			PMO_SET_PPb();
			PMO_SET_IV_DETACH();
			break;
		case(8): /* Whole IVd */
			printk(KERN_INFO "Setting PMO system to WHOLE IVd\n");
			PMO_SET_WHOLE();
			PMO_SET_IV_DETACH();
			break;
		case(9): /* Whole IVs */
			printk(KERN_INFO "Setting PMO system to WHOLE IVp\n");
			PMO_SET_WHOLE();
			PMO_SET_IV_PSYNC();
			break;
	}
	printk(KERN_INFO "Updated PMO Configuration....\n");
	pmo_print_config();

	return;

}
void pmo_get_mode (char *mode)
{
	/*NOENC, PPs, PPb, WHOLE, PPsIVd, PPbIVd, PPsIVp, PPbIVp, WHOLEIV*/
	if(PMO_NOENC_IS_ENABLED())
		strcpy(mode, "NOENC\n");	


	if(PMO_PPs_IS_ENABLED() && !PMO_IV_IS_ENABLED())
		strcpy(mode, "PPs\n");
	if(PMO_PPb_IS_ENABLED() && !PMO_IV_IS_ENABLED())
		strcpy(mode, "PPb\n");
	if(PMO_WHOLE_IS_ENABLED() && !PMO_IV_IS_ENABLED())
		strcpy(mode, "WHOLE\n");
	if(PMO_WHOLE_IS_ENABLED() && PMO_IV_IS_ENABLED())
		strcpy(mode, "WHOLEIV\n");


	if(PMO_PPs_IS_ENABLED() && PMO_IV_PSYNC_IS_ENABLED())
		strcpy(mode, "PPsIVp\n");

	if(PMO_PPs_IS_ENABLED() && PMO_IV_DETACH_IS_ENABLED())
		strcpy(mode, "PPsIVd\n");

	if(PMO_PPb_IS_ENABLED() && PMO_IV_PSYNC_IS_ENABLED())
		strcpy(mode, "PPbIVp\n");
	if(PMO_PPb_IS_ENABLED() && PMO_IV_DETACH_IS_ENABLED())
		strcpy(mode, "PPbIVd\n");
	return;
}
static ssize_t pmo_proc_write(struct file *filp, const char *buff,
	       	size_t len, loff_t * off)
{
	char mode[30];
	if(copy_from_user(mode, buff, len) != 0)
		printk("Copy from user failed\n");
	mode[1] = '\0';
	pmo_set_mode(mode);
	return len;
}

static ssize_t pmo_proc_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos) 
{
	char mode[30];
	pmo_get_mode(mode);
	//int strsize = strlen(mode);
	
	if(*ppos > 0 || count < 30)
		return 0;
	if(copy_to_user(ubuf, mode, 20) == 0) {
		*ppos = strlen(mode);
		return (strlen(mode)); /*count;*/
	}
	return -1; /*
	else
		return count;
		*/
}

static struct proc_ops pmo_fops =  {
        .proc_read = pmo_proc_read,
        .proc_write = pmo_proc_write,
};

void pmo_proc_init(void)
{
	pmo_proc_entry = proc_create("pmo", 0660, NULL, &pmo_fops);
	return;
}
