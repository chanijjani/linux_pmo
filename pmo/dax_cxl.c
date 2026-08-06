/*************************************************************************** 
 * Copyright (C) 2026 Derrick Greenspan and the University of Central	   *
 * Florida (UCF).							   *
 ***************************************************************************
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA.		   *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY   *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or	   *
 * FITNESS FOR A PARTICULAR PURPOSE.					   *
 ***************************************************************************
 * The specific code for the controller simulated in cxl-ssd-sim, for PMOs * 
 ***************************************************************************/


#include <linux/module.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/slab.h>

#define DRIVER_NAME "dax_cxl"
#define PCI_VENDOR_ID_CXL  0x8086
#define PCI_DEVICE_ID_CXL  0x7890

struct dax_cxl_dev {
	struct pci_dev *pdev;
	struct cdev cdev;
	struct class *class;
	struct mutex lock;

	resource_size_t bar_start;
	resource_size_t bar_len;
};

//static struct dax_cxl_dev *global_cxl_dev = NULL;

static int dax_cxl_open(struct inode *inode, struct file *filp)
{
	//filp->private_data = global_cxl_dev;
	struct dax_cxl_dev *dev = container_of(inode->i_cdev,
			struct dax_cxl_dev, cdev);
	filp->private_data = dev;
	return 0;
}

static int dax_cxl_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int dax_cxl_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct dax_cxl_dev *dev = filp->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pgoff = vma->vm_pgoff;
	unsigned long phys_addr;

	if (!dev) {
		pr_err("dax_cxl: returned ENODEV!\n");
		return -ENODEV;
	}

	/* Ensure we aren't mapping beyond the physical SSD size */
	if ((pgoff << PAGE_SHIFT) + size > dev->bar_len) {
		pr_err("dax_cxl: mmap request out of bounds!\n");
		return -EINVAL;
	}

	/* Target physical address is BAR0 + the offset passed by mmap */
	phys_addr = dev->bar_start + (pgoff << PAGE_SHIFT);

	/* Enforce strong DAX-like non-cached, direct I/O behaviors */
	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	printk("noncached\n");
	vma->vm_flags |= /* VM_IO | */ VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;

	pr_info("dax_cxl: Mapping virtual %lx to physical %lx (size: %ld KB)\n",
			vma->vm_start, phys_addr, size / 1024);

	/* Zero-copy mapping directly to the physical CXL window */
	if (remap_pfn_range(vma, vma->vm_start,
				phys_addr >> PAGE_SHIFT,
				size, vma->vm_page_prot))  {
		printk("Invalid mapping for phys_addr %lX\n", phys_addr);
		return -EAGAIN;
	}

	return 0;
}

static const struct file_operations dax_cxl_fops = {
	.owner = THIS_MODULE,
	.open = dax_cxl_open,
	.release = dax_cxl_release,
	.mmap = dax_cxl_mmap,
};


static int dax_cxl_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct dax_cxl_dev *dev;
	dev_t dev_num;
	int ret;

	/* Standard PCI initialization */
	ret = pci_enable_device(pdev);

	if (ret)
		return ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);

	if (!dev)
		return -ENOMEM;

	mutex_init(&dev->lock);
	dev->pdev = pdev;
	dev->bar_start = pci_resource_start(pdev, 0);
	dev->bar_len = pci_resource_len(pdev, 0);
	
	/* Character Device Registration */
	alloc_chrdev_region(&dev_num, 0, 1, DRIVER_NAME);
	cdev_init(&dev->cdev, &dax_cxl_fops);
	cdev_add(&dev->cdev, dev_num, 1);

	/* Class creation (5.15 style) */

	dev->class = class_create(THIS_MODULE, DRIVER_NAME);
	device_create(dev->class, NULL, dev_num, NULL, DRIVER_NAME);

	pci_set_drvdata(pdev, dev);
	pr_info("dax_cxl: cxl-mem-sim controller discovered at %pa\n",
			&dev->bar_start);

	return 0;
}

static void dax_cxl_remove(struct pci_dev *pdev)
{
	struct dax_cxl_dev *dev = pci_get_drvdata(pdev);
	dev_t dev_num = dev->cdev.dev;
	
	device_destroy(dev->class, dev_num);
	class_destroy(dev->class);
	cdev_del(&dev->cdev);
	unregister_chrdev_region(dev_num, 1);
	kfree(dev);
	return;
}

static const struct pci_device_id dax_cxl_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CXL, PCI_DEVICE_ID_CXL) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, dax_cxl_ids);

static struct pci_driver dax_cxl_driver = {
	.id_table = dax_cxl_ids,
	.name = DRIVER_NAME,
	.probe = dax_cxl_probe,
	.remove = dax_cxl_remove,
};

module_pci_driver(dax_cxl_driver);
MODULE_LICENSE("GPL");
