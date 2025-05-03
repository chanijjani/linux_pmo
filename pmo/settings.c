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
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(1): /* PPs */
			printk(KERN_INFO "Setting PMO system to PPs\n");
			PMO_SET_PPs();
			PMO_SET_IV_NOENC();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(2): /* PPb */
			printk(KERN_INFO "Setting PMO system to PPb\n");
			PMO_SET_PPb();
			PMO_SET_IV_NOENC();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(3): /* Whole */
			printk(KERN_INFO "Setting PMO system to WHOLE\n");
			PMO_SET_WHOLE();
			PMO_SET_IV_NOENC();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(4): /*PPsIVp */
			printk(KERN_INFO "Setting PMO system to PPsIVp\n");
			PMO_SET_PPs();
			PMO_SET_IV_PSYNC();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(5): /* PPbIVp */
			printk(KERN_INFO "Setting PMO system to PPbIVp\n");
			PMO_SET_PPb();
			PMO_SET_IV_PSYNC();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(6): /* PPsIVd */
			printk(KERN_INFO "Setting PMO system to PPsIVd\n");
			PMO_SET_PPs();
			PMO_SET_IV_DETACH();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(7): /* PPbIVd */
			printk(KERN_INFO "Setting PMO system to PPbIVd\n");
			PMO_SET_PPb();
			PMO_SET_IV_DETACH();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(8): /* Whole IVd */
			printk(KERN_INFO "Setting PMO system to WHOLE IVd\n");
			PMO_SET_WHOLE();
			PMO_SET_IV_DETACH();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(9): /* Whole IVs */
			printk(KERN_INFO "Setting PMO system to WHOLE IVp\n");
			PMO_SET_WHOLE();
			PMO_SET_IV_PSYNC();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(10): /* NOENC, IV Psync */
			printk(KERN_INFO "Setting PMO system to NOENC_IV_PSYNC\n");
		       	PMO_SET_NOENC();
			PMO_SET_IV_PSYNC();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(11):
			printk(KERN_INFO "Setting PMO system to NOENC_IV_DETACH\n");
		       	PMO_SET_NOENC();
			PMO_SET_IV_DETACH();
			PMO_DISABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		case(12):
			printk(KERN_INFO "Setting PMO system to PPbIVp, paranoid\n");
			PMO_SET_PPb();
			PMO_SET_IV_PSYNC();
			PMO_ENABLE_SHOULD_VERIFY_SHADOW_AND_PRIMARY();
			break;
		default:
			printk(KERN_WARNING "PMO SYSTEM HAS NO VALID CONFIGURATION!\n");
			break;
	}
	printk(KERN_INFO "Updated PMO Configuration....\n");
	pmo_print_config();

	return;

}
void pmo_get_mode (char *mode)
{
	/*NOENC, PPs, PPb, WHOLE, PPsIVd, PPbIVd, PPsIVp, PPbIVp, WHOLEIV*/
	if(PMO_NOENC_IS_ENABLED()) {
		if (!PMO_IV_IS_ENABLED())
			strcpy(mode, "NOENC\n");	
		else {
			if (PMO_IV_PSYNC_IS_ENABLED())
				strcpy(mode, "NOENC + PSYNC\n");	
			else 
				strcpy(mode, "NOENC + DETACH\n");	
		}
	}


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

static ssize_t pmo_debug_write(struct file *filp, const char *buff,
		size_t len, loff_t *off)
{
	char debug_mode[30];
	bool debug_enabled;
	
	if (copy_from_user(debug_mode, buff, len) != 0)
		printk (KERN_WARNING "Copy from user for debug mode failed!\n");

	debug_mode[1] = 0;

	if (debug_mode[0] == '1')
		PMO_ENABLE_DEBUG_MODE();
	else
		PMO_DISABLE_DEBUG_MODE();

	return len;
}

void _reinit_pmo_cachep(void)
{
	if (!pmo_area_cachep)
		return;

	kvfree(pmo_area_cachep);
	pmo_area_cachep = NULL;
	pmo_handle_init(false);

	return;
}

static ssize_t pmo_access_write(struct file *filp, const char *buff,
		size_t len, loff_t *off)
{
	char access_type[30];
	int access_type_num;

	if (copy_from_user(access_type, buff, len) != 0)
		printk (KERN_WARNING "Copy from user for access copy failed!\n");

	access_type[1] = 0;

	if (kstrtoint (access_type, 0, &access_type_num)) {
		printk ("Could not set unknown access type %s\n", access_type);
		return len;
	}

	switch (access_type_num) {
		case (0): 
			PMO_SET_ACCESS_TYPE_DAX();
			_reinit_pmo_cachep();
			printk (KERN_INFO "Set access type to DAX!\n");
			return len;
		case (1): 
			PMO_SET_ACCESS_TYPE_BLOCK();
			_reinit_pmo_cachep();
			printk (KERN_INFO "Set access type to BLOCK!\n");
			return len;
		default:
			printk (KERN_WARNING "Unknown mode %d", access_type_num);
			return len;
	};
	return len;

}

static ssize_t pmo_asnyc_checksum_write(struct file *filp, const char *buff,
		size_t len, loff_t *off)
{
	char async_type[30];
	int async_type_num;
	if(copy_from_user(async_type, buff, len) != 0)
		printk(KERN_WARNING "Copy from user for async checksum write failed!\n");

	async_type[1] = 0;

	if (kstrtoint(async_type, 0, &async_type_num)) {
		printk(KERN_WARNING "Could not set unknown async type %s\n", async_type);
		return len;
	}

	switch(async_type_num) {
		case (0):
			PMO_DISABLE_ASYNC_CHECKSUM();
			printk(KERN_INFO "Disabled async checksum on fault\n");
			return len;
		case (1):
			PMO_ENABLE_ASYNC_CHECKSUM();
			printk(KERN_INFO "Enabled async checksum on fault\n");
			return len;
		default:
			printk(KERN_WARNING "Unknown async type %d\n", async_type_num);
			return len;
	};
	return len;
}

static ssize_t pmo_emulate_cxl_write(struct file *filp, const char *buff,
		size_t len, loff_t *off)
{
	char cxl_type[30];
	int cxl_type_num;

	if (copy_from_user(cxl_type, buff, len) != 0)
		printk (KERN_WARNING "Copy from user for cxl copy failed!\n");

	cxl_type[1] = 0;

	if (kstrtoint (cxl_type, 0, &cxl_type_num)) {
		printk ("Could not set unknown cxl type %s\n", cxl_type);
		return len;
	}

	switch (cxl_type_num) {
		case (0): 
			PMO_SET_CXL_TYPE_LOCAL();
			_reinit_pmo_cachep();
			printk (KERN_INFO "Set cxl type to local (no NUMA for DRAM)!\n");
			return len;
		case (1): 
			PMO_SET_CXL_TYPE_FAR();
			_reinit_pmo_cachep();
			printk (KERN_INFO "Set cxl type to far (NUMA for DRAM)!\n");
			return len;
		default:
			printk (KERN_WARNING "Unknown cxl mode %d\n", cxl_type_num);
			return len;
	};
	return len;
}

static ssize_t pmo_pred_write(struct file *filp, const char *buff,
		size_t len, loff_t *off)
{
	char pred_mode[30];
	int pred_design;	
	
	if (copy_from_user(pred_mode, buff, len) != 0)
		printk (KERN_WARNING "Copy from user for pred mode failed!\n");

	pred_mode[1] = 0;

	if (kstrtoint (pred_mode, 0, &pred_design)) {
		printk ("Could not set unknown mode %s\n", pred_mode);
		return len;
	}

	switch (pred_design) {
		case (0):
			PMO_DISABLE_PREDICTION();
			printk (KERN_INFO "Predictor Disabled\n");
			return len;
		case (1): 
			PMO_ENABLE_STREAM();
			printk (KERN_INFO "STREAM Predictor\n");
			return len;
		case (2):
			PMO_ENABLE_MARKOV();
			printk(KERN_INFO "Markov Predictor\n");
			return len;
		case (3):
			PMO_ENABLE_STRIDE();
			printk (KERN_INFO "Stride Predictor\n");
			return len;
		default:
			printk (KERN_WARNING "Unknown mode %ld\n",
					pred_design);
			return len;
	};
	return len;
}


static ssize_t pmo_dram_write(struct file *filp, const char *buff,
		size_t len, loff_t * off)
{
	char dram_mode[30];
	int dram_enable;
	if (copy_from_user(dram_mode, buff, len) != 0)
		printk (KERN_WARNING "Copy from user failed\n");
	dram_mode[1] = '\0';
	
	if(kstrtoint (dram_mode, 0, &dram_enable)) {
		printk("Could not set unknown mode %s \n", dram_mode);
		return len;
	}

	switch (dram_enable) {
		case (0):
			printk (KERN_INFO "Disabling DRAM\n");
			PMO_DISABLE_DRAM();
			PMO_DISABLE_ENCRYPT_IN_DRAM();
			PMO_DISABLE_DRAM_AS_BUFFER();
			return len;

		case (1):
			printk (KERN_INFO "Enabling DRAM only\n");
			PMO_ENABLE_DRAM();
			PMO_DISABLE_ENCRYPT_IN_DRAM();
			PMO_DISABLE_DRAM_AS_BUFFER();
			return len;

		case (2):
			printk (KERN_INFO "Enabling DRAM ENCRYPT IN DRAM (ignore)\n");
			WARN_ON(!PMO_PPs_IS_ENABLED() && !PMO_PPb_IS_ENABLED());
			PMO_ENABLE_DRAM();
			PMO_ENABLE_ENCRYPT_IN_DRAM();
			PMO_DISABLE_DRAM_AS_BUFFER();
			return len;
		case (3): /* This only makes sense if pred is true */
			if (PMO_NOPRED_IS_ENABLED())
				printk (KERN_WARNING
						"WARNING: Enabling DRAM as buffer only works if pred is enabled\n");
			printk (KERN_INFO "Enabling DRAM and DRAM as Buffer\n");
			WARN_ON(!PMO_PPs_IS_ENABLED() && !PMO_PPb_IS_ENABLED());
			PMO_ENABLE_DRAM();
			PMO_ENABLE_DRAM_AS_BUFFER();
			PMO_DISABLE_ENCRYPT_IN_DRAM();
			return len;
		default:
			printk (KERN_WARNING "Unknown mode %ld\n",
					dram_enable);
			return len;
	}

}

static ssize_t pmo_proc_write(struct file *filp, const char *buff,
	       	size_t len, loff_t * off)
{
	char mode[30] = {0};
	if(copy_from_user(mode, buff, len) != 0)
		printk("Copy from user failed\n");
	pmo_set_mode(mode);
	return len;
}

static ssize_t pmo_depth_write(struct file *filp, const char *buff,
	       	size_t len, loff_t * off)
{
	char depth[30];
	char **end;
	if(copy_from_user(depth, buff, len) != 0)
		printk("Copy from user failed\n");
	PMO_SET_PREDICTION_DEPTH(simple_strtoul(depth, end, 10));
	return len;
}

static ssize_t pmo_access_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	char access_type[30];
	if (*ppos > 0 || count < 30)
		return 0;

	if (pmo_access_mode == DAX)
		strcpy(access_type, "DAX\n");
	else if (pmo_access_mode == BLOCK)
		strcpy(access_type, "BLOCK\n");

	if(copy_to_user(ubuf, access_type, 30) == 0) {
		*ppos = strlen(access_type);
		return (strlen(access_type)); 
	}
	return -1;
}

static ssize_t pmo_async_checksum_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	char async_type[30];
	if (*ppos > 0 || count < 30)
		return 0;

	strcpy(async_type, PMO_ASYNC_CHECKSUM_IS_ENABLED() ?  "TRUE" : "FALSE");

	if (copy_to_user(ubuf, async_type, 30) == 0) {
		*ppos = strlen(async_type);
		return (strlen(async_type));
	}
	return -1;
}

static ssize_t pmo_emulate_cxl_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	char cxl_type[30];
	if (*ppos > 0 || count < 30)
		return 0;

	if (PMO_GET_CXL_MODE() == PMO_LOCAL)
		strcpy(cxl_type, "PMO_LOCAL\n");
	else
		strcpy(cxl_type, "PMO_FAR\n");

	if(copy_to_user(ubuf, cxl_type, 30) == 0) {
		*ppos = strlen(cxl_type);
		return (strlen(cxl_type)); 
	}
	return -1;
}

static ssize_t pmo_proc_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos) 
{
	char mode[30];
	pmo_get_mode(mode);
	
	if(*ppos > 0 || count < 30)
		return 0;
	if(copy_to_user(ubuf, mode, 20) == 0) {
		*ppos = strlen(mode);
		return (strlen(mode)); 
	}
	return -1; 
}

static ssize_t pmo_dram_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	char dram_mode[30];

	strcpy (dram_mode, PMO_DRAM_IS_ENABLED() ?
			"DRAM is enabled\n" : "DRAM is disabled\n");

	if (*ppos > 0 || count < 30)
		return 0;
	if(copy_to_user(ubuf, dram_mode, 20) == 0) {
		*ppos = strlen(dram_mode);
		return (strlen(dram_mode)); /*count;*/
	}
	return -1; 
}

static ssize_t pmo_pred_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	char prediction_mode[256];
	strcpy (prediction_mode, PMO_STREAM_IS_ENABLED() ? 
			"Prediction mode is stream\n":
			"Prediction mode disabled\n");

	if (*ppos > 0 || count < 30)
		return 0;
	if(copy_to_user(ubuf, prediction_mode, 32) == 0) {
		*ppos = strlen(prediction_mode);
		return (strlen(prediction_mode)); 
	}
	return -1;
}

static ssize_t pmo_depth_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	char depth[256];
	snprintf(depth, 30, "%d\n", PMO_GET_PREDICTION_DEPTH());

	if (*ppos > 0 || count < 30)
		return 0;
	if(copy_to_user(ubuf, depth, 32) == 0) {
		*ppos = strlen(depth);
		return (strlen(depth)); 
	}
	return -1;
}

static ssize_t pmo_debug_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	char debug_state[256];
	snprintf(debug_state, 30, "%s\n", PMO_DEBUG_MODE_IS_ENABLED() ?
			"Debug Enabled\n" : "Debug Disabled\n");

	if (*ppos > 0 || count < 30)
		return 0;
	if(copy_to_user(ubuf, debug_state, 32) == 0) {
		*ppos = strlen(debug_state);
		return (strlen(debug_state)); 
	}
	return -1;
}


static struct proc_ops pmo_fops =  {
        .proc_read = pmo_proc_read,
        .proc_write = pmo_proc_write,
};

static struct proc_ops dram_fops = {
	.proc_read = pmo_dram_read,
	.proc_write = pmo_dram_write,
};

static struct proc_ops pred_fops = {
	.proc_read = pmo_pred_read,
	.proc_write = pmo_pred_write,
};

static struct proc_ops depth_fops = {
	.proc_read = pmo_depth_read,
	.proc_write = pmo_depth_write,
};

static struct proc_ops debug_fops = {
	.proc_read = pmo_debug_read,
	.proc_write = pmo_debug_write,
};

static struct proc_ops access_fops = {
	.proc_read = pmo_access_read,
	.proc_write = pmo_access_write,	
};

static struct proc_ops pmo_emulate_cxl_fops = {
	.proc_read = pmo_emulate_cxl_read,
	.proc_write = pmo_emulate_cxl_write,
};

static struct proc_ops pmo_async_checksum_fops = {
	.proc_read = pmo_async_checksum_read,
	.proc_write = pmo_asnyc_checksum_write,
};

void pmo_proc_init(void)
{
	struct proc_dir_entry *dir = proc_mkdir("pmo", NULL);
	pmo_proc_entry = proc_create("pmo", 0660, dir, &pmo_fops);
	pmo_dram_entry = proc_create("dram", 0660, dir, &dram_fops);
	pmo_pred_entry = proc_create("pred", 0660, dir, &pred_fops);
	pmo_depth_entry = proc_create("depth", 0660, dir, &depth_fops);
	pmo_debug_entry = proc_create("debug", 0660, dir, &debug_fops);
	pmo_access_entry = proc_create("access", 0660, dir, &access_fops);
	pmo_emulate_cxl_entry = proc_create("cxl_emulation", 0660, dir, &pmo_emulate_cxl_fops);
	pmo_async_checksum_entry = proc_create("async_checksum", 0660, dir, &pmo_async_checksum_fops);
	return;
}
