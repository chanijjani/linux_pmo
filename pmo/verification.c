/***************************************************************************
 * Copyright (C) 2025 The University of Central	Florida (UCF).	           *
 ***************************************************************************
 * verify handling, that comes from verify syscall	                       *
 ***************************************************************************/

#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include "../drivers/nvme/host/nvme.h"
#include "pmo.h"

#define CRC32_POLYNOMIAL 0xEDB88320UL

#define CRC32_TABLE_SIZE 256

#define CRC32_FINGERPRINT 0xFFFFFFFFUL

#define CHECKSUM_FILE "/tmp/checksum"

static uint32_t crc32_table[CRC32_TABLE_SIZE];

static void init_crc32_table(void)
{
	uint32_t i, j, crc;
	for (i = 0; i < CRC32_TABLE_SIZE; i++)
	{
		crc = i;
		for (j = 0; j < 8; j++)
		{
			crc = (crc >> 1) ^ ((crc & 1) ? CRC32_POLYNOMIAL : 0);
		}
		crc32_table[i] = crc;
	}
}

static uint32_t calculate_crc32(const void *buf, size_t len)
{
	uint32_t crc = CRC32_FINGERPRINT;
	const unsigned char *p = buf;

	while (len--)
	{
		crc = crc32_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
	}

	return crc ^ CRC32_FINGERPRINT;
}

static void verify_dram(struct file *file, unsigned long total_pages)
{
	unsigned long i;
	void *vaddr;
	uint32_t checksum = 0;
	int len;
	char buf[128];
	loff_t pos = 0;

	printk(KERN_INFO "===== VERIFYING DRAM MEMORY =====\n");

	for (i = 0; i < total_pages; i++)
	{
		struct page *page = pfn_to_page(i);
		vaddr = kmap_atomic(page);

		if (PageHighMem(page))
		{
			vaddr = kmap_atomic(page);
		}
		else
		{
			vaddr = page_address(page);
		}

		checksum = calculate_crc32(vaddr, PAGE_SIZE);

		if (PageHighMem(page))
		{
			kunmap_atomic(vaddr);
		}

		len = snprintf(buf, ARRAY_SIZE(buf), "vaddr[%p] --> Memory Page %lu checksum: %u (0x%08X)\n", vaddr, i, checksum, checksum);
		kernel_write(file, buf, len, &pos);
	}
}

static void verify_pmem(struct file *file, unsigned long total_pages)
{
	unsigned long num_pages = 0;
	unsigned long long start, end;
	void *addr;
	unsigned long i;
	uint32_t checksum = 0;
	int len;
	char buf[128];
	loff_t pos = 0;
	// struct resource *rsc;

	if (PMO_DAX_IS_ENABLED()) {
		printk(KERN_INFO "===== VERIFYING INTEL OPTANE PERSISTANT MEMORY =====\n");
	} else {
		printk(KERN_INFO "[Warning!] DAX Config is disabled, stop.\n");
		return;
	}
	
	dax_pmo_handle_init();
	printk(KERN_INFO "DAX Handle is initialized.\n");

	// rsc = get_dax_dev_resource(DAX_NAME);
	start = get_dax_dev_resource(DAX_NAME)->start;
	end = get_dax_dev_resource(DAX_NAME)->end;
	if (total_pages == 0) {
		num_pages = (end - start) / 4096;
	} else {
		num_pages = total_pages;
	}
	printk(KERN_INFO "Total number of pages in DAX = %lu\n", num_pages);

	addr = pmo_dax_map(0, (end - start));
	
	printk(KERN_INFO "===== PERSISTENT MEMORY CHECKSUM CALCULATIONS from (%p)=====\n", addr);
	for (i = 0; i < num_pages; i++)
	{
		void *offset = addr + PAGE_SIZE*i;
		checksum = calculate_crc32(offset, PAGE_SIZE);

		len = snprintf(buf, ARRAY_SIZE(buf), "offset[%p] --> PM Page %lu checksum: %u (0x%08X)\n", offset, i, checksum, checksum);
		kernel_write(file, buf, len, &pos);
	}
	
	printk(KERN_INFO "Finish checksum calculations.\n");
	pmo_dax_unmap(addr);
}

SYSCALL_DEFINE2(verify, __u64, num_pages, __u64, is_pm)
{
	unsigned long total_pages = 0;
	struct timespec64 ts;
	struct file *file;
	char file_name[64];

	printk(KERN_INFO "Starting memory page checksum calculation\n");

	init_crc32_table();

	printk(KERN_INFO "Total number of physical pages: %lu\n", get_num_physpages());
	if (num_pages > 0)
	{
		printk("Total page given: %llu\n", num_pages);
		total_pages = num_pages;
	}

	ktime_get_real_ts64(&ts);
	if (is_pm) {
		snprintf(file_name, ARRAY_SIZE(file_name), "%s_PM_%lld.%09ld", CHECKSUM_FILE, (long long)ts.tv_sec, ts.tv_nsec);
	} else {
		snprintf(file_name, ARRAY_SIZE(file_name), "%s_DRAM_%lld.%09ld", CHECKSUM_FILE, (long long)ts.tv_sec, ts.tv_nsec);
	}

	file = filp_open(file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(file))
	{
		printk(KERN_ERR "Failed to open file\n");
		return PTR_ERR(file);
	}

	printk(KERN_INFO "Total number of memory pages written: %lu\n", total_pages);

	if (is_pm) {
		verify_pmem(file, total_pages);
	} else {		
		verify_dram(file, total_pages);
	}

	filp_close(file, NULL);

	return total_pages;
}
