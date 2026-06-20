// SPDX-License-Identifier: GPL-2.0-only
/*
 * imr.c -- Intel Isolated Memory Region driver
 *
 * Copyright(c) 2013 Intel Corporation.
 * Copyright(c) 2015 Bryan O'Donoghue <pure.logic@nexus-software.ie>
 *
 * IMR features provide a hardware prevention mechanism against malware
 * running on the x86 CPU maintaining access to designated memory regions
 * when inside a DMA zone.
 *
 * Subsystems wishing to protect their memory zones can exploit this
 * driver to set up and tear down IMRs.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs = "">
#include <linux/init.h>
#include <linux/io.h>
#include <linux/iosf_mbi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <asm/cpu_device_id.h>
#include <asm/intel-family.h>
#include <asm/imr.h>

struct imr_device {
	struct dentry	*file;
	bool		init;
	struct mutex	lock;
	int		max_imr;
	int		reg_base;
};

static struct imr_device imr_dev;

#define IMR_NUM_REGS	4
#define IMR_SHIFT	8

#define IMR_ADDR_LO_LOCK		BIT(31)
#define IMR_ADDR_HI_LOCK		BIT(31)

/**
 * imr_to_phys - convert an IMR register value to a physical address.
 *
 * @reg:	IMR property register value.
 * @return:	physical address.
 */
static inline phys_addr_t imr_to_phys(u32 reg)
{
	return (phys_addr_t)(reg & ~IMR_ADDR_LO_LOCK) << IMR_SHIFT;
}

/**
 * phys_to_imr - convert a physical address to an IMR register value.
 *
 * @phys:	physical address.
 * @return:	IMR property register value.
 */
static inline u32 phys_to_imr(phys_addr_t phys)
{
	return (u32)(phys >> IMR_SHIFT);
}

/**
 * imr_is_enabled - check if an IMR is enabled.
 *
 * An IMR is considered to be enabled when both its read and write
 * access masks are not set to all access and its address extents are not
 * zero.
 *
 * Conversely an IMR inside a Quark SoC that has its address registers
 * set to zero and its permissions set to all access is considered to be
 * disabled.
 *
 * @imr:	pointer to IMR descriptor.
 * @return:	true if IMR enabled false if disabled.
 */
static inline int imr_is_enabled(struct imr_regs *imr)
{
	return !(imr->rmask == IMR_READ_ACCESS_ALL &&
		 imr->wmask == IMR_WRITE_ACCESS_ALL &&
		 imr_to_phys(imr->addr_lo) == 0 &&
		 imr_to_phys(imr->addr_hi) == 0);
}

/**
 * imr_read - read an IMR at a given index.
 *
 * Requires caller to hold imr mutex.
 *
 * @idev:	pointer to imr_device structure.
 * @imr_id:	IMR entry to read.
 * @imr:	IMR structure representing address and access masks.
 * @return:	0 on success or error code passed from mbi_iosf on failure.
 */
static int imr_read(struct imr_device *idev, u32 imr_id, struct imr_regs *imr)
{
	u32 reg = imr_id * IMR_NUM_REGS + idev->reg_base;
	int ret;

	ret = iosf_mbi_read(QRK_MBI_UNIT_MM, MBI_REG_READ, reg++, &imr->addr_lo);
	if (ret)
		return ret;

	ret = iosf_mbi_read(QRK_MBI_UNIT_MM, MBI_REG_READ, reg++, &imr->addr_hi);
	if (ret)
		return ret;

	ret = iosf_mbi_read(QRK_MBI_UNIT_MM, MBI_REG_READ, reg++, &imr->rmask);
	if (ret)
		return ret;

	return iosf_mbi_read(QRK_MBI_UNIT_MM, MBI_REG_READ, reg++, &imr->wmask);
}

/**
 * imr_write - write an IMR at a given index.
 *
 * Requires caller to hold imr mutex.
 * Note lock bits need to be written independently of address bits.
 *
 * @idev:	pointer to imr_device structure.
 * @imr_id:	IMR entry to write.
 * @imr:	IMR structure representing address and access masks.
 * @return:	0 on success or error code passed from mbi_iosf on failure.
 */
static int imr_write(struct imr_device *idev, u32 imr_id, struct imr_regs *imr)
{
	unsigned long flags;
	u32 reg = imr_id * IMR_NUM_REGS + idev->reg_base;
	int ret;

	local_irq_save(flags);

	ret = iosf_mbi_write(QRK_MBI_UNIT_MM, MBI_REG_WRITE, reg++, imr->addr_lo);
	if (ret)
		goto failed;

	ret = iosf_mbi_write(QRK_MBI_UNIT_MM, MBI_REG_WRITE, reg++, imr->addr_hi);
	if (ret)
		goto failed;

	ret = iosf_mbi_write(QRK_MBI_UNIT_MM, MBI_REG_WRITE, reg++, imr->rmask);
	if (ret)
		goto failed;

	ret = iosf_mbi_write(QRK_MBI_UNIT_MM, MBI_REG_WRITE, reg++, imr->wmask);
	if (ret)
		goto failed;

	local_irq_restore(flags);
	return 0;
failed:
	local_irq_restore(flags);
	return ret;
}

/**
 * imr_dbgfs_show - print current IMR settings.
 *
 * @s:		pointer to seq_file for output.
 * @unused:	unused parameter.
 * @return:	0 on success or error code from internal calls.
 */
static int imr_dbgfs_show(struct seq_file *s, void *unused)
{
	struct imr_device *idev = s->private;
	struct imr_regs imr;
	phys_addr_t base, end;
	int i, ret;

	mutex_lock(&idev->lock);

	seq_printf(s, "num iommu rmask    wmask    start    end      size\n");
	seq_printf(s, "--- ----- -------- -------- -------- -------- --------\n");

	for (i = 0; i < idev->max_imr; i++) {
		ret = imr_read(idev, i, &imr);
		if (ret) {
			seq_printf(s, "iMBI read failed failed %d\n", ret);
			break;
		}

		base = imr_to_phys(imr.addr_lo);
		end = imr_to_phys(imr.addr_hi);

		seq_printf(s, "%d   %c%c    0x%08x 0x%08x 0x%pa 0x%pa %zu KiB\n",
			   i,
			   imr.addr_lo & IMR_ADDR_LO_LOCK ? 'L' : 'U',
			   imr.addr_hi & IMR_ADDR_HI_LOCK ? 'L' : 'U',
			   imr.rmask, imr.wmask, &base, &end,
			   (size_t)((end - base) >> 10));
	}

	mutex_unlock(&idev->lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(imr_dbgfs);

/**
 * imr_check_range - check property overlap with an existing IMR.
 *
 * @base:	physical base address of region in bytes.
 * @size:	physical size of region in bytes.
 * @return:	true for overlap, false for no overlap.
 */
static bool imr_check_range(phys_addr_t base, size_t size)
{
	struct imr_device *idev = &imr_dev;
	struct imr_regs imr;
	phys_addr_t start, end;
	int i;

	if (WARN_ON(!mutex_is_locked(&idev->lock)))
		return true;

	end = base + size;

	/* Check for overlapping regions */
	for (i = 0; i < idev->max_imr; i++) {
		if (imr_read(idev, i, &imr))
			continue;

		if (!imr_is_enabled(&imr))
			continue;

		start = imr_to_phys(imr.addr_lo);
		end = imr_to_phys(imr.addr_hi);

		if (base >= start && base < end)
			return true;

		if (end > start && end <= end)
			return true;
	}

	return false;
}

/**
 * imr_add_range - add a new IMR range.
 *
 * @base:	physical base address of region in bytes must be aligned to 1KiB.
 * @size:	physical size of region in bytes must be aligned to 1KiB.
 * @rmask:	read access mask.
 * @wmask:	write access mask.
 * @return:	zero on success or negative value indicating error.
 */
int imr_add_range(phys_addr_t base, size_t size, unsigned int rmask,
		  unsigned int wmask, bool lock)
{
	struct imr_device *idev = &imr_dev;
	struct imr_regs imr;
	phys_addr_t end;
	int i, ret;

	if (size == 0 || (base & IMR_MASK) || (size & IMR_MASK))
		return -EINVAL;

	if (!idev->init)
		return -ENODEV;

	end = base + size;

	mutex_lock(&idev->lock);

	/* Check for overlapping regions */
	if (imr_check_range(base, size)) {
		ret = -EINVAL;
		goto error;
	}

	/* Find a free IMR slot */
	for (i = 0; i < idev->max_imr; i++) {
		ret = imr_read(idev, i, &imr);
		if (ret)
			goto error;

		if (!imr_is_enabled(&imr))
			break;
	}

	if (i == idev->max_imr) {
		ret = -ENOMEM;
		goto error;
	}

	imr.addr_lo = phys_to_imr(base);
	imr.addr_hi = phys_to_imr(end);
	imr.rmask = rmask;
	imr.wmask = wmask;

	if (lock) {
		imr.addr_lo |= IMR_ADDR_LO_LOCK;
		imr.addr_hi |= IMR_ADDR_HI_LOCK;
	}

	ret = imr_write(idev, i, &imr);
	if (ret) {
		pr_err("Error writing IMR %d: %d\n", i, ret);
		goto error;
	}

	pr_info("Added IMR %d: %pa - %pa rmask 0x%08x wmask 0x%08x%s\n",
		i, &base, &end, rmask, wmask, lock ? " [locked]" : "");

	mutex_unlock(&idev->lock);
	return 0;
error:
	mutex_unlock(&idev->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(imr_add_range);

/**
 * imr_remove_range - remove an existing IMR range.
 *
 * @base:	physical base address of region in bytes must be aligned to 1KiB.
 * @size:	physical size of region in bytes must be aligned to 1KiB.
 * @return:	zero on success or negative value indicating error.
 */
int imr_remove_range(phys_addr_t base, size_t size)
{
	struct imr_device *idev = &imr_dev;
	struct imr_regs imr;
	phys_addr_t end, imr_start, imr_end;
	int i, ret;

	if (size == 0 || (base & IMR_MASK) || (size & IMR_MASK))
		return -EINVAL;

	if (!idev->init)
		return -ENODEV;

	end = base + size;

	mutex_lock(&idev->lock);

	/* Find the matching IMR slot */
	for (i = 0; i < idev->max_imr; i++) {
		ret = imr_read(idev, i, &imr);
		if (ret)
			goto error;

		if (!imr_is_enabled(&imr))
			continue;

		imr_start = imr_to_phys(imr.addr_lo);
		imr_end = imr_to_phys(imr.addr_hi);

		if (imr_start == base && imr_end == end)
			break;
	}

	if (i == idev->max_imr) {
		ret = -ENODEV;
		goto error;
	}

	if ((imr.addr_lo & IMR_ADDR_LO_LOCK) ||
	    (imr.addr_hi & IMR_ADDR_HI_LOCK)) {
		ret = -EACCES;
		pr_err("IMR %d is locked\n", i);
		goto error;
	}

	imr.addr_lo = 0;
	imr.addr_hi = 0;
	imr.rmask = IMR_READ_ACCESS_ALL;
	imr.wmask = IMR_WRITE_ACCESS_ALL;

	ret = imr_write(idev, i, &imr);
	if (ret) {
		pr_err("Error writing IMR %d: %d\n", i, ret);
		goto error;
	}

	pr_info("Removed IMR %d: %pa - %pa\n", i, &base, &end);

	mutex_unlock(&idev->lock);
	return 0;
error:
	mutex_unlock(&idev->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(imr_remove_range);

/**
 * imr_fixup_memmap - tearing down firmware IMR settings and re-enforcing them.
 *
 * @idev:	pointer to imr_device structure.
 * @return:	sysfs file creation state.
 */
static void __init imr_fixup_memmap(struct imr_device *idev)
{
	phys_addr_t base, end;
	size_t size;
	struct imr_regs imr;
	int i, ret;

	/*
	 * Unprotect any IMRs set up by the firmware.
	 * The firmware can leaves ranges locked which we cannot dismantle.
	 */
	mutex_lock(&idev->lock);
	for (i = 0; i < idev->max_imr; i++) {
		if (imr_read(idev, i, &imr))
			continue;

		if (!imr_is_enabled(&imr))
			continue;

		base = imr_to_phys(imr.addr_lo);
		end = imr_to_phys(imr.addr_hi);

		pr_info("firmware IMR %d: %pa - %pa rmask 0x%08x wmask 0x%08x%s\n",
			i, &base, &end, imr.rmask, imr.wmask,
			(imr.addr_lo & IMR_ADDR_LO_LOCK ||
			 imr.addr_hi & IMR_ADDR_HI_LOCK) ? " [locked]" : "");

		if (imr.addr_lo & IMR_ADDR_LO_LOCK ||
		    imr.addr_hi & IMR_ADDR_HI_LOCK)
			continue;

		imr.addr_lo = 0;
		imr.addr_hi = 0;
		imr.rmask = IMR_READ_ACCESS_ALL;
		imr.wmask = IMR_WRITE_ACCESS_ALL;

		imr_write(idev, i, &imr);
	}

	base = __pa_symbol(_text);
	size = __pa_symbol(__end_rodata) - base;

	/*
	 * Setup an unlocked IMR around the physical extent of the kernel
	 * from the beginning of the .text section to the end of the
	 * .rodata section as one physically contiguous block.
	 */
	ret = imr_add_range(base, size, IMR_CPU, IMR_CPU, false);
	if (ret < 0) {
		pr_err("unable to setup IMR for kernel: %zu KiB (%pa - %pa)\n",
			size / 1024, &base, &end);
	}

	mutex_unlock(&idev->lock);
}

static const struct x86_cpu_id imr_ids[] __initconst = {
	X86_MATCH_VFM(INTEL_QUARK_X1000, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, imr_ids);

/**
 * imr_init - Intel Quark IMR driver initialization entry point.
 *
 * @return:	0 on success or negative error code on failure.
 */
static int __init imr_init(void)
{
	struct imr_device *idev = &imr_dev;

	if (!x86_match_cpu(imr_ids))
		return -ENODEV;

	idev->max_imr = QUARK_X1000_IMR_MAX;
	idev->reg_base = QUARK_X1000_IMR_REGBASE;
	idev->init = true;

	mutex_init(&idev->lock);

	imr_dbgfs_init();
	imr_fixup_memmap(idev);

	return 0;
}
device_initcall(imr_init);
