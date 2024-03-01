// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * currently write operations not supported
 *
 * Copyright (c) 2023 David Yang
 */

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/reset.h>

#include "advca.h"

#define OTP_CHANNEL_SEL		0x000
#define  OTP_CHANNEL_SEL_MASK		GENMASK(1, 0)
#define OTP_RW_CTRL		0x004
#define  OTP_WRITE_SEL			BIT(0)
#define  OTP_READ_EN			BIT(1)
#define  OTP_WRITE_EN			BIT(2)
#define  OTP_RW_WIDTH			GENMASK(5, 4)
#define OTP_WRITE_START		0x008
#define  OTP_WRITE_START_BIT		BIT(0)
#define OTP_CTRL_STATUS		0x00c
#define  OTP_CTRL_READY			BIT(0)
#define  OTP_FAIL_BIT			BIT(1)
#define  OTP_SOAK_BIT			BIT(2)
#define  OTP_READ_LOCK			BIT(4)
#define  OTP_WRITE_LOCK			BIT(5)
#define OTP_READ_DATA		0x010
#define OTP_WRITE_DATA		0x014
#define OTP_READ_ADDR		0x018
#define OTP_WRITE_ADDR		0x01c
#define OTP_MODE		0x020
#define  OTP_MAX_SOAK_TIMES		GENMASK(3, 0)
#define  OTP_TIME			GENMASK(7, 4)
#define  OTP_SOAK_EN			BIT(8)
#define  OTP_TIME_EN			BIT(9)
#define OTP_LOCK_ADDR_0		0x024
#define OTP_LOCK_ADDR_1		0x028
#define OTP_LOCK_ADDR_2		0x02c
#define OTP_LOCK_ADDR_3		0x030
#define OTP_ADDR_LOCK_EN	0x034
#define OTP_SOAK_TIME		0x048
#define OTP_DEBUG_ADDR_BEGIN	0x04c
#define OTP_DEBUG_ADDR_END	0x064
#define OTP_DEBUG_0		0x068
#define OTP_DEBUG_1		0x06c
#define OTP_DEBUG_3		0x074
#define OTP_DEBUG_4		0x078
#define OTP_PV_0		0x080
#define OTP_PV_1		0x084
#define OTP_PV_LOCK_0		0x088
#define OTP_PV_LOCK_1		0x08c
#define OTP_DATA_LOCK_0		0x090
#define OTP_DATA_LOCK_1		0x094
#define OTP_ONE_WAY_0		0x098
#define OTP_ONE_WAY_1		0x09c
#define OTP_CSA2_ROOTKEY0	0x0a0
#define OTP_CSA2_ROOTKEY1	0x0a4
#define OTP_CSA2_ROOTKEY2	0x0a8
#define OTP_CSA2_ROOTKEY3	0x0ac
#define OTP_R2R_ROOTKEY0	0x0b0
#define OTP_R2R_ROOTKEY1	0x0b4
#define OTP_R2R_ROOTKEY2	0x0b8
#define OTP_R2R_ROOTKEY3	0x0bc
#define OTP_SP_ROOTKEY0		0x0c0
#define OTP_SP_ROOTKEY1		0x0c4
#define OTP_SP_ROOTKEY2		0x0c8
#define OTP_SP_ROOTKEY3		0x0cc
#define OTP_CSA3_ROOTKEY0	0x0d0
#define OTP_CSA3_ROOTKEY1	0x0d4
#define OTP_CSA3_ROOTKEY2	0x0d8
#define OTP_CSA3_ROOTKEY3	0x0dc
#define OTP_JTAG_KEY0		0x0e0
#define OTP_JTAG_KEY1		0x0e4
#define OTP_CA_CHIP_ID0		0x0e8
#define OTP_CA_CHIP_ID1		0x0ec
#define OTP_ESCK0		0x0f0
#define OTP_ESCK1		0x0f4
#define OTP_ESCK2		0x0f8
#define OTP_ESCK3		0x0fc
#define OTP_STB_ROOTKEY0	0x100
#define OTP_STB_ROOTKEY1	0x104
#define OTP_STB_ROOTKEY2	0x108
#define OTP_STB_ROOTKEY3	0x10c
#define OTP_STB_SN0		0x110
#define OTP_STB_SN1		0x114
#define OTP_STB_SN2		0x118
#define OTP_STB_SN3		0x11c
#define OTP_MKTS_ID		0x120
#define OTP_DDR_ENC		0x180
#define OTP_W_ONCE_ONLY		0x184
#define OTP_DEBUG_00		0x18c
#define OTP_SEC_CPU_JTAG_KEY0	0x190
#define OTP_SEC_CPU_JTAG_KEY1	0x194
#define OTP_SEC_CPU_JTAG_KEY2	0x198
#define OTP_SEC_CPU_JTAG_KEY3	0x19c
#define OTP_DEBUG_11		0x1b4

#define OTP_MEM_SIZE	0x800

struct hica_otp_priv {
	void __iomem *base;

	struct clk *clk;
	struct reset_control *rst;

	bool read_locked : 1;
	bool write_locked : 1;
};

static int hica_otp_init(struct device *dev)
{
	struct hica_otp_priv *priv = dev_get_drvdata(dev);
	u32 val;

	if (priv->read_locked)
		return -ENOTSUPP;

	/* only channel 2 valid */
	writel_relaxed(2, priv->base + OTP_CHANNEL_SEL);

	val = readl_relaxed(priv->base + OTP_RW_CTRL);
	val &= ~OTP_WRITE_SEL;
	val |= OTP_READ_EN;
	val &= ~OTP_RW_WIDTH;
	val |= 2 << 4;  /* word operation */
	writel_relaxed(val, priv->base + OTP_RW_CTRL);

	return 0;
}

static int hica_otp_read(struct device *dev, unsigned int addr, void *data)
{
	struct hica_otp_priv *priv = dev_get_drvdata(dev);
	u32 val;
	int ret;

	if (addr & 3)
		return -EINVAL;
	if (priv->read_locked)
		return -ENOTSUPP;
	if (addr >= OTP_MEM_SIZE)
		return -ERANGE;

	writel_relaxed(addr, priv->base + OTP_READ_ADDR);

	ret = readl_relaxed_poll_timeout(priv->base + OTP_CTRL_STATUS,
					 val, val & OTP_CTRL_READY,
					 1300, 20 * 1000);
	if (ret)
		return ret;

	*(u32 *) data = readl_relaxed(priv->base + OTP_READ_DATA);
	return 0;
}

static int hica_otp_read_mem(struct device *dev, unsigned int addr,
			     unsigned int len, void *buf)
{
	if (addr & 3 || len & 3)
		return -EINVAL;

	for (unsigned int i = 0; i < len; i += sizeof(u32)) {
		int ret = hica_otp_read(dev, addr + i, buf + i);

		if (ret)
			return ret;
	}

	return 0;
}

static ssize_t
otp_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	unsigned int len = OTP_MEM_SIZE;
	int ret;

	ret = hica_otp_read_mem(dev, 0, len, buf);
	if (ret)
		return ret;

	return len;
}

static DEVICE_ATTR_RO(otp);

static ssize_t
read_locked_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hica_otp_priv *priv = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", priv->read_locked);
}

static DEVICE_ATTR_RO(read_locked);

static ssize_t
write_locked_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hica_otp_priv *priv = dev_get_drvdata(dev);
	return sprintf(buf, "%d\n", priv->write_locked);
}

static DEVICE_ATTR_RO(write_locked);

static struct attribute *hica_otp_attrs[] = {
	&dev_attr_otp.attr,
	&dev_attr_read_locked.attr,
	&dev_attr_write_locked.attr,
	NULL,
};

ATTRIBUTE_GROUPS(hica_otp);

hica_fn_resume(otp)
hica_fn_suspend(otp)

static int hica_otp_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct hica_otp_priv *priv;
	u32 val;

	do_hica_fn_probe(otp);

	if (readl_relaxed_poll_timeout(priv->base + OTP_CTRL_STATUS,
				       val, val & OTP_CTRL_READY, 1, 1000)) {
		dev_err(dev, "cannot bring up device\n");
		return -ENODEV;
	}

	priv->read_locked = val & OTP_READ_LOCK;
	priv->write_locked = val & OTP_WRITE_LOCK;
	hica_otp_init(dev);

	return 0;
}

static const struct of_device_id hica_otp_of_match[] = {
	{ .compatible = "hisilicon,advca-otp", },
	{ }
};

static struct platform_driver hica_otp_driver = {
	.probe = hica_otp_probe,
	.suspend = hica_otp_suspend,
	.resume = hica_otp_resume,
	.driver = {
		.name = "hisi-advca-otp",
		.of_match_table = hica_otp_of_match,
		.dev_groups = hica_otp_groups,
	},
};

module_platform_driver(hica_otp_driver);

MODULE_DESCRIPTION("HiSilicon Advanced Conditional Access Subsystem - one-time programmable memory");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Yang <mmyangfl@gmail.com>");
