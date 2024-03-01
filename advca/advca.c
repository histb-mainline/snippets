// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Device driver for HiSilicon Advanced Conditional Access Subsystem
 *
 * Copyright (c) 2023 David Yang
 */

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/reset.h>

struct hica_mkl_priv {
	void __iomem *base;

	struct clk *clk;
	struct reset_control *rst;
};

struct hica_otp_priv {
	void __iomem *base;

	struct clk *clk;
	struct reset_control *rst;

	bool read_locked : 1;
	bool write_locked : 1;
};

struct hica_rng_priv {
	void __iomem *base;

	struct clk *clk;
	struct reset_control *rst;
};

struct hica_rsa_priv {
	void __iomem *base;

	struct clk *clk;
	struct reset_control *rst;
};

struct hica_sha_priv {
	void __iomem *base;

	struct clk *clk;
	struct reset_control *rst;
};

#define SKC_BUFFER_FLAG_SET_IT		BIT(21)
#define SKC_BUFFER_FLAG_LIST_EOL	BIT(22)
#define SKC_BUFFER_MAX_LEN		GENMASK(19, 0)

/* register struct */
struct hica_skc_buffer {
	uint32_t phy_addr;
	uint32_t flags;
	uint32_t len;
	uint32_t iv_phy_addr;
};

struct hica_skc_key {
	char key[16];
};

struct hica_skc_channel {
	struct hica_skc_buffer *in_list;
	struct hica_skc_buffer *out_list;
	unsigned int num;
};

#define SKC_SINGLE_PACKET_CHAN	0
#define SKC_CHAN_MIN		1
#define SKC_CHAN_MAX		7	/* TODO: TEE -> 3 */
#define SKC_CHAN_NUM		(SKC_CHAN_MAX - SKC_CHAN_MIN + 1)

struct hica_skc_priv {
	void __iomem *base;
	void __iomem *mmu;

	struct clk *clk;
	struct clk *clk_bus;
	struct clk *clk_mmu;
	struct reset_control *rst;
	struct reset_control *rst_mmu;

	int irq;
	int irq_sec;

	struct hica_skc_channel channels[SKC_CHAN_NUM];
};

struct hica_priv {
	struct hica_mkl_priv mkl;
	struct hica_otp_priv otp;
	struct hica_rng_priv rng;
	struct hica_rsa_priv rsa;
	struct hica_sha_priv sha;
	struct hica_skc_priv skc;
};

#define hica_fn_resume(fn) \
static int hica_##fn##_resume(struct platform_device *pdev) \
{ \
	struct hica_priv *ca = platform_get_drvdata(pdev); \
	int ret; \
\
	ret = clk_prepare_enable(ca->fn.clk); \
	if (ret) \
		return ret; \
	ret = reset_control_deassert(ca->fn.rst); \
	if (ret) \
		return ret; \
\
	return 0; \
}

#define hica_fn_suspend(fn) \
static int hica_##fn##_suspend(struct platform_device *pdev, pm_message_t state) \
{ \
	struct hica_priv *ca = platform_get_drvdata(pdev); \
\
	reset_control_assert(ca->fn.rst); \
	clk_disable_unprepare(ca->fn.clk); \
\
	return 0; \
}

#define do_hica_fn_probe(fn) do { \
	ca->fn.base = devm_platform_ioremap_resource_byname(pdev, #fn); \
	if (IS_ERR(ca->fn.base)) \
		return -ENOMEM; \
\
	ca->fn.clk = devm_clk_get_optional_enabled(&pdev->dev, #fn); \
	if (IS_ERR(ca->fn.clk)) \
		return PTR_ERR(ca->fn.clk); \
\
	ca->fn.rst = devm_reset_control_get_optional_exclusive_released(&pdev->dev, #fn); \
	if (IS_ERR(ca->fn.rst)) \
		return PTR_ERR(ca->fn.rst); \
} while (0)

#define hica_fn_probe(fn) \
static int hica_##fn##_probe(struct platform_device *pdev, struct hica_priv *ca) \
{ \
	do_hica_fn_probe(fn); \
	return 0; \
}

/******** machine key ladder ********/

#define CONFIG_STATE		0x000
#define  STATE_VALID			BIT(0)
#define CSA2_CTRL		0x004
#define R2R_CTRL		0x008
#define SP_CTRL			0x00c
#define CSA3_CTRL		0x010
#define LP_CTRL			0x014
#define BL_CTRL_DEC		0x018
#define BL_CTRL_ENC		0x01c
#define MKL_NOMAL_DIN0		0x020
#define MKL_NOMAL_DIN1		0x024
#define MKL_NOMAL_DIN2		0x028
#define MKL_NOMAL_DIN3		0x02c
#define STB_KEY_CTRL		0x034
#define MKL_STATE		0x038
#define  KEY_LADDER_ERROR_STATE		GENMASK(3, 0)
#define  LAST_KEY_NOT_READY		BIT(4)
#define  CSA2_KEY_LADDER_0_READY	BIT(5)
#define  CSA2_KEY_LADDER_1_READY	BIT(6)
#define  CSA2_KEY_LADDER_2_READY	BIT(7)
#define  R2R_KEY_LADDER_0_READY		BIT(8)
#define  R2R_KEY_LADDER_1_READY		BIT(9)
#define  R2R_KEY_LADDER_2_READY		BIT(10)
#define  SP_KEY_LADDER_0_READY		BIT(11)
#define  SP_KEY_LADDER_1_READY		BIT(12)
#define  SP_KEY_LADDER_2_READY		BIT(13)
#define  CSA3_KEY_LADDER_0_READY	BIT(14)
#define  CSA3_KEY_LADDER_1_READY	BIT(15)
#define  CSA3_KEY_LADDER_2_READY	BIT(16)
#define  MISC_KEY_LADDER_0_READY	BIT(17)
#define  MISC_KEY_LADDER_1_READY	BIT(18)
#define  MISC_KEY_LADDER_2_READY	BIT(19)
#define  LP_KEY_LADDER_0_READY		BIT(20)
#define  LP_KEY_LADDER_1_READY		BIT(21)
#define  KEY_3_READY			BIT(22)
#define  KEY_2_READY			BIT(23)
#define  KEY_1_READY			BIT(24)
#define  KEY_LADDER_BUSY		BIT(31)
#define LEVEL_REG		0x03c
#define CHECKSUM_FLAG		0x040
#define MKL_VERSION		0x044
#define MKL_INT_RAW		0x048
#define SECURE_BOOT_STATE	0x04c
#define LP_PARAMETER_BASE	0x050
#define BLK_ENC_RSLT		0x060
#define GDRM_CTRL		0x070
#define DCAS_CTRL		0x074
#define  LEVEL_SEL			GENMASK(3, 0)
#define  AES_SEL			BIT(4)
#define  DSC_CODE_MC_ALG_SEL		GENMASK(23, 16)
#define  ODD_SEL			BIT(24)
#define  KEY_ADDR			GENMASK(31, 15)
#define DEBUG_INFO		0x078
#define CA_VERSION		0x07c
#define DA_NOUCE		0x080
#define TEST_KEY		0x090
#define TEST_RESULT		0x0a0
#define KEY_DOUT		0x0b0
#define MISC_CTRL		0x0c0
#define GDRM_FLAG		0x0c4
#define CFG_CMAC_CTRL		0x0cc
#define GDRM_ENC_REST0		0x0d0
#define GDRM_ENC_REST1		0x0d4
#define GDRM_ENC_REST2		0x0d8
#define GDRM_ENC_REST3		0x0dc
#define CFG_CMAC_OUT		0x0f0
#define TA_KL_CTRL		0x100
#define IVRK_CTRL		0x10c
#define CAUK_CTRL		0x110
#define MKL_SECURE_DIN0		0x1a0
#define MKL_SECURE_DIN1		0x1a4
#define MKL_SECURE_DIN2		0x1a8
#define MKL_SECURE_DIN3		0x1ac
#define MKL_SEC_EN		0x200

static ssize_t
ca_version_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_mkl_priv *priv = &ca->mkl;

	return sprintf(buf, "%x\n", readl_relaxed(priv->base + CA_VERSION));
}

static DEVICE_ATTR_RO(ca_version);

static ssize_t
mkl_version_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_mkl_priv *priv = &ca->mkl;

	return sprintf(buf, "%x\n", readl_relaxed(priv->base + MKL_VERSION));
}

static DEVICE_ATTR_RO(mkl_version);

hica_fn_resume(mkl)
hica_fn_suspend(mkl)

static int hica_mkl_probe(struct platform_device *pdev, struct hica_priv *ca)
{
	struct device *dev = &pdev->dev;
	struct hica_mkl_priv *priv = &ca->mkl;
	u32 val;

	do_hica_fn_probe(mkl);

	val = readl_relaxed(priv->base + CONFIG_STATE);
	if (!(val & STATE_VALID))
		return -ENODEV;

	dev_info(dev, "CA version %x\n", readl_relaxed(priv->base + CA_VERSION));
	dev_info(dev, "Machine Key Ladder version %x\n",
		 readl_relaxed(priv->base + MKL_VERSION));

	return 0;
}

/******** one-time programmable memory ********/

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

static int hica_otp_init(struct device *dev)
{
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_otp_priv *priv = &ca->otp;
	u32 val;

	if (priv->read_locked)
		return -ENOTSUPP;

	/* only channel 2 has practical data */
	writel_relaxed(2, priv->base + OTP_CHANNEL_SEL);

	val = readl_relaxed(priv->base + OTP_RW_CTRL);
	val &= ~OTP_WRITE_SEL;
	val |= OTP_READ_EN;
	val &= ~OTP_RW_WIDTH;
	val |= 2 << 4;  /* word operation */
	writel_relaxed(val, priv->base + OTP_RW_CTRL);

	return 0;
}

/* addr % 4 == 0 */
static int hica_otp_read(struct device *dev, unsigned int addr, void *data)
{
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_otp_priv *priv = &ca->otp;
	u32 val;
	int ret;

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

/* addr % 4 == 0, len % 4 == 0 */
static int hica_otp_read_mem(struct device *dev, unsigned int addr,
			     unsigned int len, void *buf)
{
	int ret;
	unsigned int i;

	for (i = 0; i < len; i += sizeof(u32)) {
		ret = hica_otp_read(dev, addr + i, buf + i);
		if (ret)
			return ret;
	}

	return 0;
}

static ssize_t
otp_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_otp_priv *priv = &ca->otp;
	unsigned int len = OTP_MEM_SIZE;
	int ret;

	if (!priv->base)
		return -ENODEV;

	ret = hica_otp_read_mem(dev, 0, len, buf);
	if (ret)
		return ret;

	return len;
}

static DEVICE_ATTR_RO(otp);

static ssize_t
read_locked_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_otp_priv *priv = &ca->otp;

	if (!priv->base)
		return -ENODEV;

	return sprintf(buf, "%d\n", priv->read_locked);
}

static DEVICE_ATTR_RO(read_locked);

static ssize_t
write_locked_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_otp_priv *priv = &ca->otp;

	if (!priv->base)
		return -ENODEV;

	return sprintf(buf, "%d\n", priv->write_locked);
}

static DEVICE_ATTR_RO(write_locked);

hica_fn_resume(otp)
hica_fn_suspend(otp)

static int hica_otp_probe(struct platform_device *pdev, struct hica_priv *ca)
{
	struct device *dev = &pdev->dev;
	struct hica_otp_priv *priv = &ca->otp;
	u32 val;

	do_hica_fn_probe(otp);

	val = readl_relaxed(priv->base + OTP_CTRL_STATUS);
	if (!(val & OTP_CTRL_READY))
		return -ENODEV;

	priv->read_locked = val & OTP_READ_LOCK;
	priv->write_locked = val & OTP_WRITE_LOCK;

	if (!priv->read_locked)
		hica_otp_init(dev);

	return 0;
}

/******** RNG ********/

#include <linux/hw_random.h>

#define RNG_CTRL	0x200
#define RNG_FIFO_DATA	0x204
#define RNG_DATA_ST	0x208
#define  RNG_DATA_COUNT		GENMASK(2, 0)	/* max 4 */

static int hica_rng_wait(struct hwrng *rng)
{
	void __iomem *base = (void __iomem *) rng->priv;
	u32 val;

	return readl_relaxed_poll_timeout(base + RNG_DATA_ST,
					  val, val & RNG_DATA_COUNT, 1000,
					  30 * 1000);
}

static int hica_rng_read(struct hwrng *rng, void *data, size_t max, bool wait)
{
	void __iomem *base = (void __iomem *) rng->priv;
	size_t i;

	for (i = 0; i < max; i += sizeof(u32)) {
		if (!(readl_relaxed(base + RNG_DATA_ST) & RNG_DATA_COUNT)) {
			if (!wait)
				break;
			if (hica_rng_wait(rng)) {
				pr_err("failed to generate random number, generated %zu\n",
				       i);
				if (i)
					break;
				return -ETIMEDOUT;
			}
		}
		*(u32 *) (data + i) = readl_relaxed(base + RNG_FIFO_DATA);
	}

	return i;
}

hica_fn_resume(rng)
hica_fn_suspend(rng)

static int hica_rng_probe(struct platform_device *pdev, struct hica_priv *ca)
{
	struct device *dev = &pdev->dev;
	struct hica_rng_priv *priv = &ca->rng;
	struct hwrng *rng;
	u32 val;
	int ret;

	do_hica_fn_probe(rng);

	val = readl_relaxed(priv->base + RNG_DATA_ST);
	if (!(val & RNG_DATA_COUNT))
		return -ENODEV;

	rng = devm_kzalloc(dev, sizeof(*rng), GFP_KERNEL);
	if (!rng)
		return -ENOMEM;

	rng->name = KBUILD_MODNAME;
	rng->read = hica_rng_read;
	rng->priv = (unsigned long) priv->base;

	ret = devm_hwrng_register(dev, rng);
	if (ret) {
		dev_err(dev, "failed to register %s (%d)\n", rng->name, ret);
		return ret;
	}

	return 0;
}

/******** RSA ********/

#define RSA_BUSY	0x50
#define  RSA_BUSY_BIT		BIT(0)
#define RSA_MOD		0x54
#define RSA_WREG	0x58
#define RSA_WDAT	0x5c
#define RSA_RPKT	0x60
#define RSA_RRSLT	0x64
#define RSA_START	0x68
#define  RSA_START_BIT		BIT(0)
#define RSA_ADDR	0x6c
#define RSA_ERROR	0x70
#define RSA_CRC16	0x74
#define RSA_KEY_RANDOM_1	0x7c
#define RSA_KEY_RANDOM_2	0x94

hica_fn_resume(rsa)
hica_fn_suspend(rsa)
hica_fn_probe(rsa)

/******** SHA ********/

#define SHA_TOTALLEN_LOW_ADDR	0x00
#define SHA_TOTALLEN_HIGH_ADDR	0x04
#define SHA_STATUS_ADDR		0x08
#define SHA_CTRL_ADDR		0x0c
#define SHA_START_ADDR		0x10
#define SHA_DMA_START_ADDR	0x14
#define SHA_DMA_LEN		0x18
#define SHA_DATA_IN		0x1c
#define SHA_REC_LEN0		0x20
#define SHA_REC_LEN1		0x24
#define SHA_SHA_OUT0		0x30
#define SHA_SHA_OUT1		0x34
#define SHA_SHA_OUT2		0x38
#define SHA_SHA_OUT3		0x3c
#define SHA_SHA_OUT4		0x40
#define SHA_SHA_OUT5		0x44
#define SHA_SHA_OUT6		0x48
#define SHA_SHA_OUT7		0x4c
#define SHA_MCU_KEY0		0x70
#define SHA_MCU_KEY1		0x74
#define SHA_MCU_KEY2		0x78
#define SHA_MCU_KEY3		0x7c
#define SHA_KL_KEY0		0x80
#define SHA_KL_KEY1		0x84
#define SHA_KL_KEY2		0x88
#define SHA_KL_KEY3		0x8c
#define SHA_INIT1_UPDATE	0x90

hica_fn_resume(sha)
hica_fn_suspend(sha)
hica_fn_probe(sha)

/******** symmetric key ciphers********/

#define SKC_CHAN0_DATA_OUT0	0x00
#define SKC_CHAN0_DATA_OUT1	0x04
#define SKC_CHAN0_DATA_OUT2	0x08
#define SKC_CHAN0_DATA_OUT3	0x0c
#define SKC_CHANn_IV_OUT0(n)	(0x10 + 0x10 * (n))
#define SKC_CHANn_IV_OUT1(n)	(0x14 + 0x10 * (n))
#define SKC_CHANn_IV_OUT2(n)	(0x18 + 0x10 * (n))
#define SKC_CHANn_IV_OUT3(n)	(0x1c + 0x10 * (n))
#define SKC_CHANn_KEY0(n)	(0x90 + 0x20 * (n))
#define SKC_CHANn_KEY1(n)	(0x94 + 0x20 * (n))
#define SKC_CHANn_KEY2(n)	(0x98 + 0x20 * (n))
#define SKC_CHANn_KEY3(n)	(0x9c + 0x20 * (n))
#define SKC_CHANn_KEY4(n)	(0xa0 + 0x20 * (n))
#define SKC_CHANn_KEY5(n)	(0xa4 + 0x20 * (n))
#define SKC_CHANn_KEY6(n)	(0xa8 + 0x20 * (n))
#define SKC_CHANn_KEY7(n)	(0xac + 0x20 * (n))

#define SKC_CTRL_ST0		0x800
#define SKC_CTRL_ST1		0x804
#define SKC_CTRL_ST2		0x808
#define SKC_SRAM_ST0		0x80c
#define SKC_HDCP_HOST_ROOTKEY	0x810
#define SKC_HDCP_MODE_CTRL	0x820
#define SKC_SEC_CHAN_CFG	0x824
#define  SKC_SEC_CHANn_BIT(n)		BIT(n)
#define SKC_HL_APP_CBC_CTRL	0x828
#define SKC_HL_APP_LEN		0x82c
#define SKC_HL_APP_CBC_MAC_REF	0x830

#define SKC_CHANn_BUF_NUM_MASK	GENMASK(15, 0)

#define SKC_CHAN0_CTRL			0x1000
#define  SKC_CHAN_CTRL_DECRYPT			BIT(0)
#define  SKC_CHAN_CTRL_MODE			GENMASK(3, 1)  /* other: as 0 */
#define   SKC_CHAN_CTRL_MODE_ECB			0
#define   SKC_CHAN_CTRL_MODE_CBC			1
#define   SKC_CHAN_CTRL_MODE_CFB			2
#define   SKC_CHAN_CTRL_MODE_OFB			3
#define   SKC_CHAN_CTRL_MODE_CTR			4  /* not for DES */
#define  SKC_CHAN_CTRL_ALG			GENMASK(5, 4)  /* other: as 0 */
#define   SKC_CHAN_CTRL_ALG_DES				0
#define   SKC_CHAN_CTRL_ALG_3DES			1
#define   SKC_CHAN_CTRL_ALG_AES				2
#define  SKC_CHAN_CTRL_WIDTH			GENMASK(7, 6)  /* other: as 0 */
#define   SKC_CHAN_CTRL_WIDTH_DES_64B			0
#define   SKC_CHAN_CTRL_WIDTH_AES_128B			0
#define   SKC_CHAN_CTRL_WIDTH_8B			1
#define   SKC_CHAN_CTRL_WIDTH_1B			2
#define  SKC_CHAN0_CTRL_SET_IV			BIT(8)
#define  SKC_CHAN_CTRL_KEY_LENGTH		GENMASK(10, 9)  /* other: as 0 */
#define   SKC_CHAN_CTRL_KEY_LENGTH_3DES_3KEY		0
#define   SKC_CHAN_CTRL_KEY_LENGTH_3DES_2KEY		3
#define   SKC_CHAN_CTRL_KEY_LENGTH_AES_128B		0
#define   SKC_CHAN_CTRL_KEY_LENGTH_AES_192B		1
#define   SKC_CHAN_CTRL_KEY_LENGTH_AES_256B		2
#define  SKC_CHAN_CTRL_KEY_FROM_MKL		BIT(13)
#define  SKC_CHAN_CTRL_KEY_ID			GENMASK(16, 14)
#define  SKC_CHAN_CTRL_PRIORITY			GENMASK(31, 22)
#define SKC_CHAN0_IV_IN0		0x1004
#define SKC_CHAN0_IV_IN1		0x1008
#define SKC_CHAN0_IV_IN2		0x100c
#define SKC_CHAN0_IV_IN3		0x1010
#define SKC_CHAN0_DATA_IN0		0x1014
#define SKC_CHAN0_DATA_IN1		0x1018
#define SKC_CHAN0_DATA_IN2		0x101c
#define SKC_CHAN0_DATA_IN3		0x1020
#define SKC_CHANn_IN_BUF_NUM(n)		(0x1000 + 0x80 * (n) + 0x00)
#define SKC_CHANn_IN_BUF_CNT(n)		(0x1000 + 0x80 * (n) + 0x04)
#define SKC_CHANn_IN_EMPTY_CNT(n)	(0x1000 + 0x80 * (n) + 0x08)
#define SKC_CHANn_INT_IN_CNT_CFG(n)	(0x1000 + 0x80 * (n) + 0x0c)
#define SKC_CHANn_CTRL(n)		(0x1000 + 0x80 * (n) + 0x10)
#define SKC_CHANn_SRC_LST_ADDR(n)	(0x1000 + 0x80 * (n) + 0x14)
#define SKC_CHANn_IN_AGE_TIMER(n)	(0x1000 + 0x80 * (n) + 0x18)
#define SKC_CHANn_IN_AGE_CNT(n)		(0x1000 + 0x80 * (n) + 0x1c)
#define SKC_CHANn_SRC_LST_HEAD(n)	(0x1000 + 0x80 * (n) + 0x20)
#define SKC_CHANn_SRC_ADDR(n)		(0x1000 + 0x80 * (n) + 0x24)
#define SKC_CHANn_SRC_LENGTH(n)		(0x1000 + 0x80 * (n) + 0x28)
#define SKC_CHANn_IN_LEFT_BYTE0(n)	(0x1000 + 0x80 * (n) + 0x2c)
#define SKC_CHANn_IN_LEFT_WORD0(n)	(0x1000 + 0x80 * (n) + 0x30)
#define SKC_CHANn_IN_LEFT_WORD1(n)	(0x1000 + 0x80 * (n) + 0x34)
#define SKC_CHANn_IN_LEFT_WORD2(n)	(0x1000 + 0x80 * (n) + 0x38)
#define SKC_CHANn_OUT_BUF_NUM(n)	(0x1000 + 0x80 * (n) + 0x3c)
#define SKC_CHANn_OUT_BUF_CNT(n)	(0x1000 + 0x80 * (n) + 0x40)
#define SKC_CHANn_OUT_FULL_CNT(n)	(0x1000 + 0x80 * (n) + 0x44)
#define SKC_CHANn_INT_OUT_CNT_CFG(n)	(0x1000 + 0x80 * (n) + 0x48)
#define SKC_CHANn_DEST_LST_ADDR(n)	(0x1000 + 0x80 * (n) + 0x4c)
#define SKC_CHANn_OUT_AGE_TIMER(n)	(0x1000 + 0x80 * (n) + 0x50)
#define SKC_CHANn_OUT_AGE_CNT(n)	(0x1000 + 0x80 * (n) + 0x54)
#define SKC_CHANn_DEST_LST_HEAD(n)	(0x1000 + 0x80 * (n) + 0x58)
#define SKC_CHANn_DEST_ADDR(n)		(0x1000 + 0x80 * (n) + 0x5c)
#define SKC_CHANn_DEST_LENGTH(n)	(0x1000 + 0x80 * (n) + 0x60)
#define SKC_CHANn_OUT_LEFT_BYTE(n)	(0x1000 + 0x80 * (n) + 0x64)

#define  SKC_INT_CHANn_IN_BUF_BIT(n)		BIT(n)
#define  SKC_INT_CHAN0_DATA_DISPOSE_BIT		BIT(8)
#define  SKC_INT_CHANn_OUT_BUF_BIT(n)		BIT(8 + n)
#define SKC_INT_STATUS			0x1400
#define SKC_INT_EN			0x1404
#define  SKC_INT_SEC_EN				BIT(30)
#define  SKC_INT_EN_BIT				BIT(31)
#define SKC_INT_CLR			0x1408
#define SKC_RST_STATUS			0x140c
#define  SKC_STATE_VALID			BIT(0)
#define SKC_CHAN0_CFG			0x1410
#define  SKC_CHAN0_START			BIT(0)
#define  SKC_CHAN0_BUSY				BIT(1)
#define SKC_SRC_ADDR_SMMU_BYPASS	0x1418
#define SKC_DEST_ADDR_SMMU_BYPASS	0x141c
#define SKC_BRAM_ST0			0x1420
#define SKC_IN_ST0			0x1424
#define SKC_IN_ST1			0x1428
#define SKC_IN_ST2			0x142c
#define SKC_IN_ST3			0x1430
#define SKC_OUT_ST0			0x1434
#define SKC_OUT_ST1			0x1438
#define SKC_OUT_ST2			0x143c

/* SKC_BUF_NUM <= SKC_CHANn_BUF_NUM_MASK */
#define SKC_BUF_NUM	128

static int hica_skc_channel_init(struct device *dev, unsigned int i)
{
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_skc_priv *priv = &ca->skc;
	struct hica_skc_channel *channel = &priv->channels[i];

	channel->num = SKC_BUF_NUM;

	channel->in_list = devm_kzalloc(dev, sizeof(*channel->in_list) * channel->num,
					GFP_KERNEL);
	if (!channel->in_list)
		return -ENOMEM;
	channel->out_list = devm_kzalloc(dev, sizeof(*channel->out_list) * channel->num,
					 GFP_KERNEL);
	if (!channel->out_list)
		return -ENOMEM;

	writel_relaxed(virt_to_phys(channel->in_list),
		       priv->base + SKC_CHANn_SRC_LST_ADDR(i));
	writel_relaxed(channel->num, priv->base + SKC_CHANn_IN_BUF_NUM(i));
	writel_relaxed(0, priv->base + SKC_CHANn_IN_BUF_CNT(i));
	writel_relaxed(0, priv->base + SKC_CHANn_IN_AGE_CNT(i));

	writel_relaxed(virt_to_phys(channel->out_list),
		       priv->base + SKC_CHANn_DEST_LST_ADDR(i));
	writel_relaxed(channel->num, priv->base + SKC_CHANn_OUT_BUF_NUM(i));
	writel_relaxed(channel->num, priv->base + SKC_CHANn_OUT_BUF_CNT(i));
	writel_relaxed(0, priv->base + SKC_CHANn_OUT_AGE_CNT(i));

	return 0;
}

static void
hica_skc_channel_ctrl(struct device *dev, unsigned int chn, bool decrypt,
		      unsigned int alg, unsigned int mode, unsigned int key_len,
		      unsigned int width, bool chn0_iv, bool key_from_mkl)
{
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_skc_priv *priv = &ca->skc;
	void __iomem *ctrl = priv->base + (chn == 0 ? SKC_CHAN0_CTRL : SKC_CHANn_CTRL(chn));
	u32 val;

	val = readl_relaxed(ctrl);

	if (decrypt)
		val |= SKC_CHAN_CTRL_DECRYPT;
	else
		val &= ~SKC_CHAN_CTRL_DECRYPT;

	val &= ~SKC_CHAN_CTRL_MODE;
	val |= (mode << 1) & SKC_CHAN_CTRL_MODE;

	val &= ~SKC_CHAN_CTRL_ALG;
	val |= (alg << 4) & SKC_CHAN_CTRL_ALG;

	val &= ~SKC_CHAN_CTRL_WIDTH;
	val |= (width << 6) & SKC_CHAN_CTRL_WIDTH;

	if (chn0_iv)
		val |= SKC_CHAN0_CTRL_SET_IV;
	else
		val &= ~SKC_CHAN0_CTRL_SET_IV;

	val &= ~SKC_CHAN_CTRL_KEY_LENGTH;
	val |= (key_len << 9) & SKC_CHAN_CTRL_KEY_LENGTH;

	if (key_from_mkl)
		val |= SKC_CHAN_CTRL_KEY_FROM_MKL;
	else {
		val &= ~SKC_CHAN_CTRL_KEY_FROM_MKL;
		val &= ~SKC_CHAN_CTRL_KEY_ID;
		val |= (chn << 14) & SKC_CHAN_CTRL_KEY_ID;
	}

	writel_relaxed(val, ctrl);
}

static void
hica_skc_channel0_encrypt(struct device *dev, bool decrypt, const void *ket,
			  const void *iv, void *dst, const void *src)
{
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_skc_priv *priv = &ca->skc;
	u32 val;
	int i;

	hica_skc_channel_ctrl(dev, 0, decrypt, SKC_CHAN_CTRL_ALG_AES, SKC_CHAN_CTRL_MODE_ECB, SKC_CHAN_CTRL_KEY_LENGTH_AES_256B, SKC_CHAN_CTRL_WIDTH_AES_128B, true, false);

	writel_relaxed(1, priv->base + SKC_CHANn_INT_OUT_CNT_CFG(0));

	/* set iv */
	if (i == 0 && iv)
		for (i = 0; i < 16; i += sizeof(u32))
			writel_relaxed(((const u32 *) iv + i), priv->base + SKC_CHAN0_IV_IN0 + i);

	/* set key */
	for (i = 0; i < 32; i += sizeof(u32))
		writel_relaxed(((const u32 *) iv + i), priv->base + SKC_CHANn_KEY0(0) + i);

	/* set data */
	for (i = 0; i < 16; i += sizeof(u32))
		writel_relaxed(((const u32 *) src + i), priv->base + SKC_CHAN0_DATA_IN0 + i);

	val = readl_relaxed(priv->base + SKC_CHAN0_CFG);
	val |= SKC_CHAN0_START;
	writel_relaxed(val, priv->base + SKC_CHAN0_CFG);
}
/*
static int hica_cipher_wait(struct platform_device *pdev)
{
	struct hica_priv *ca = platform_get_drvdata(pdev);
	int ret;
	u32 val;
#ifdef DEBUG
	static ktime_t last;
	ktime_t now;
#endif

	ret = readl_relaxed_poll_timeout(priv->base + CA_STATE,
					 val, !(val & KEY_LADDER_BUSY),
					 priv->delay_us, priv->timeout_us);
#ifdef DEBUG
	now = ktime_get();
	pr_info("%s: cost %lld\n", __func__, now - last);
	last = now;
#endif

	return ret;
}

static int hica_sk_setkey(struct crypto_tfm *tfm, const u8 *in_key, unsigned int key_len)
{
	struct aes_ctx *ctx = aes_ctx(tfm);
	const u32 *key = (const u32 *) in_key;

	if (key_len != 16)
		return -EINVAL;

	writel_relaxed(key[0], priv->base + CHANn_KEY0(chn));
	writel_relaxed(key[1], priv->base + CHANn_KEY1(chn));
	writel_relaxed(key[2], priv->base + CHANn_KEY2(chn));
	writel_relaxed(key[3], priv->base + CHANn_KEY3(chn));

	writel_relaxed(iv[0], priv->base + CHAN0_IVIN0);
	writel_relaxed(iv[1], priv->base + CHAN0_IVIN1);
	writel_relaxed(iv[2], priv->base + CHAN0_IVIN2);
	writel_relaxed(iv[3], priv->base + CHAN0_IVIN3);

	return 0;
}
*/

static int hica_skc_init(struct device *dev)
{


	return 0;
}

static int hica_skc_resume(struct platform_device *pdev)
{
	struct hica_priv *ca = platform_get_drvdata(pdev);
	struct hica_skc_priv *priv = &ca->skc;
	int ret;

	ret = clk_prepare_enable(priv->clk_mmu);
	if (ret)
		return ret;
	ret = reset_control_deassert(priv->rst_mmu);
	if (ret)
		return ret;

	ret = clk_prepare_enable(priv->clk_bus);
	if (ret)
		return ret;
	ret = clk_prepare_enable(priv->clk);
	if (ret)
		return ret;
	ret = reset_control_deassert(priv->rst);
	if (ret)
		return ret;

	enable_irq(priv->irq);
	if (priv->irq_sec >= 0)
		enable_irq(priv->irq_sec);

	return 0;
}

static int hica_skc_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct hica_priv *ca = platform_get_drvdata(pdev);
	struct hica_skc_priv *priv = &ca->skc;

	if (priv->irq_sec >= 0)
		disable_irq(priv->irq_sec);
	disable_irq(priv->irq);

	reset_control_assert(priv->rst);
	clk_disable_unprepare(priv->clk);
	clk_disable_unprepare(priv->clk_bus);

	reset_control_assert(priv->rst_mmu);
	clk_disable_unprepare(priv->clk_mmu);

	return 0;
}

static irqreturn_t hica_skc_handle(int irq, void *dev_id)
{
	struct device *dev = (struct device *) dev_id;
	struct hica_priv *ca = dev_get_drvdata(dev);
	struct hica_skc_priv *priv = &ca->skc;
	u32 val;

	val = readl(priv->base + SKC_INT_STATUS);
	printk("skc get interrput %x\n", val);

	if (unlikely(!val)) {
		dev_dbg(dev, "skc get no interrputs, wired...\n");
		return IRQ_HANDLED;
	}

	printk("skc get interrput %x\n", val);
	writel_relaxed(val, priv->base + SKC_INT_CLR);

	return IRQ_HANDLED;
}

static void hica_skc_test(void __iomem *base)
{
	ktime_t last;
	int ret;
	u32 val;
	int i;

	for (i = 0; i < 10; i++) {

		val = readl_relaxed(base + SKC_CHAN0_CFG);
		val |= SKC_CHAN0_START;
		writel_relaxed(val, base + SKC_CHAN0_CFG);

	ktime_t last;
		last = ktime_get();
		ret = readl_relaxed_poll_timeout(base + SKC_CHAN0_CFG,
						 val, !(val & SKC_CHAN0_BUSY),
						 1, 1000);
		pr_info("%s: cost %lld\n", __func__, ktime_get() - last);
	}
}

static int hica_skc_probe(struct platform_device *pdev, struct hica_priv *ca)
{
	struct device *dev = &pdev->dev;
	struct hica_skc_priv *priv = &ca->skc;
	u32 val;
	int ret;
	int i;

	do_hica_fn_probe(skc);

	priv->clk_bus = devm_clk_get_optional_enabled(dev, "skc-bus");
	if (IS_ERR(priv->clk_bus))
		return PTR_ERR(priv->clk_bus);
	priv->clk_mmu = devm_clk_get_optional_enabled(dev, "skc-mmu");
	if (IS_ERR(priv->clk_mmu))
		return PTR_ERR(priv->clk_mmu);

	priv->rst_mmu = devm_reset_control_get_optional_exclusive_released(dev, "skc-mmu");
	if (IS_ERR(priv->rst_mmu))
		return PTR_ERR(priv->rst_mmu);

	priv->irq = platform_get_irq_byname(pdev, "skc");
	if (priv->irq < 0)
		return -ENODEV;
	priv->irq_sec = platform_get_irq_byname_optional(pdev, "skc-sec");

	/* bring up device */
	val = readl_relaxed(priv->base + SKC_RST_STATUS);
	if (!(val & SKC_STATE_VALID))
		return -ENODEV;

	/* request and set control memory */
	for (i = SKC_CHAN_MIN; i <= SKC_CHAN_MAX; i++) {
		ret = hica_skc_channel_init(dev, i);
		if (ret)
			return ret;
	}

	/* clear all interrupts */
	val = readl_relaxed(priv->base + SKC_INT_CLR);
	for (i = SKC_CHAN_MIN; i <= SKC_CHAN_MAX; i++) {
		val |= SKC_INT_CHANn_IN_BUF_BIT(i);
		val |= SKC_INT_CHANn_OUT_BUF_BIT(i);
	}
	val |= SKC_INT_CHAN0_DATA_DISPOSE_BIT;
	writel_relaxed(val, priv->base + SKC_INT_CLR);

	/* give me irq! */
	ret = devm_request_irq(dev, priv->irq, hica_skc_handle,
			       IRQF_SHARED, pdev->name, dev);
	if (ret) {
		dev_err(dev, "devm_request_irq skc failed (%d)\n", priv->irq);
		return ret;
	}
	if (priv->irq_sec >= 0) {
		ret = devm_request_irq(dev, priv->irq_sec, hica_skc_handle,
				       IRQF_SHARED, pdev->name, dev);
		if (ret) {
			dev_err(dev, "devm_request_irq skc-sec failed (%d)\n",
				priv->irq);
			return ret;
		}
	}

	/* enable interrupts */
	val = readl_relaxed(priv->base + SKC_INT_EN);
	for (i = SKC_CHAN_MIN; i <= SKC_CHAN_MAX; i++) {
		val |= SKC_INT_CHANn_IN_BUF_BIT(i);
		val |= SKC_INT_CHANn_OUT_BUF_BIT(i);
	}
	val |= SKC_INT_CHAN0_DATA_DISPOSE_BIT;
	val |= SKC_INT_SEC_EN;
	val |= SKC_INT_EN_BIT;
	writel_relaxed(val, priv->base + SKC_INT_EN);
	printk("debug %x\n",val);

	/* enable in-chip secure channel */
	/*
	val = readl_relaxed(priv->base + SKC_SEC_CHAN_CFG);
	val |= SKC_SEC_CHANn_BIT(0);
	for (i = SKC_CHAN_MIN; i <= SKC_CHAN_MAX; i++) {
		val |= SKC_SEC_CHANn_BIT(i);
	}
	writel_relaxed(val, priv->base + SKC_SEC_CHAN_CFG);
	*/

	pr_info("%s: now aes 128\n", __func__);
	writel_relaxed(0x120, priv->base + SKC_CHAN0_CTRL);
	hica_skc_test(priv->base);

	pr_info("%s: now aes 196\n", __func__);
	writel_relaxed(0x320, priv->base + SKC_CHAN0_CTRL);
	hica_skc_test(priv->base);

	pr_info("%s: now aes 256\n", __func__);
	writel_relaxed(0x520, priv->base + SKC_CHAN0_CTRL);
	hica_skc_test(priv->base);

	pr_info("%s: now des\n", __func__);
	writel_relaxed(0x100, priv->base + SKC_CHAN0_CTRL);
	hica_skc_test(priv->base);

	pr_info("%s: now 3des\n", __func__);
	writel_relaxed(0x110, priv->base + SKC_CHAN0_CTRL);
	hica_skc_test(priv->base);

	return 0;
}

/******** platform device ********/

static struct attribute *hica_attrs[] = {
	&dev_attr_ca_version.attr,
	&dev_attr_mkl_version.attr,
	&dev_attr_otp.attr,
	&dev_attr_read_locked.attr,
	&dev_attr_write_locked.attr,
	NULL,
};

ATTRIBUTE_GROUPS(hica);

static int hica_resume(struct platform_device *pdev)
{
	struct hica_priv *ca = platform_get_drvdata(pdev);
	int ret;

	ret = hica_mkl_resume(pdev);
	if (ret)
		return ret;
	if (ca->otp.base) {
		ret = hica_otp_resume(pdev);
		if (ret)
			return ret;
	}
	if (ca->rsa.base) {
		ret = hica_rsa_resume(pdev);
		if (ret)
			return ret;
	}
	if (ca->sha.base) {
		ret = hica_sha_resume(pdev);
		if (ret)
			return ret;
	}
	if (ca->skc.base) {
		ret = hica_skc_resume(pdev);
		if (ret)
			return ret;
	}

	return 0;
}

static int hica_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct hica_priv *ca = platform_get_drvdata(pdev);

	if (ca->skc.base)
		hica_skc_suspend(pdev, state);
	if (ca->sha.base)
		hica_sha_suspend(pdev, state);
	if (ca->rsa.base)
		hica_rsa_suspend(pdev, state);
	if (ca->otp.base)
		hica_otp_suspend(pdev, state);
	hica_mkl_suspend(pdev, state);

	return 0;
}

static int hica_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct hica_priv *ca;
	struct resource *res;
	int ret;

	ca = devm_kzalloc(dev, sizeof(*ca), GFP_KERNEL);
	if (!ca)
		return -ENOMEM;

	platform_set_drvdata(pdev, ca);
	dev_set_drvdata(dev, ca);

	ret = hica_mkl_probe(pdev, ca);
	if (ret == -EPROBE_DEFER)
		return ret;
	if (ret) {
		dev_err(dev, "cannot register Machine Key Ladder (%d)\n", ret);
		return ret;
	}

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "otp");
	if (res) {
		ret = hica_otp_probe(pdev, ca);
		if (ret == -EPROBE_DEFER)
			return ret;
		if (ret) {
			dev_err(dev, "cannot register OTP device (%d)\n", ret);
			ca->otp.base = NULL;
		}
	}

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "rsa");
	if (res) {
		ret = hica_rsa_probe(pdev, ca);
		if (ret == -EPROBE_DEFER)
			return ret;
		if (ret) {
			dev_err(dev, "cannot register RSA device (%d)\n", ret);
			ca->rsa.base = NULL;
		}
	}

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "sha");
	if (res) {
		ret = hica_sha_probe(pdev, ca);
		if (ret == -EPROBE_DEFER)
			return ret;
		if (ret) {
			dev_err(dev, "cannot register SHA device (%d)\n", ret);
			ca->sha.base = NULL;
		}
	}

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "skc");
	if (res) {
		ret = hica_skc_probe(pdev, ca);
		if (ret == -EPROBE_DEFER)
			return ret;
		if (ret) {
			dev_err(dev, "cannot register symmetric key ciphers (%d)\n", ret);
			ca->skc.base = NULL;
		}
	}

	return 0;
}

static const struct of_device_id hica_of_match[] = {
	{ .compatible = "hisilicon,advca", },
	{ }
};

static struct platform_driver hica_driver = {
	.probe = hica_probe,
	.suspend = hica_suspend,
	.resume = hica_resume,
	.driver = {
		.name = "hisi-advca",
		.of_match_table = of_match_ptr(hica_of_match),
		.dev_groups = hica_groups,
	},
};

module_platform_driver(hica_driver);

MODULE_DESCRIPTION("HiSilicon Advanced Conditional Access Subsystem");
MODULE_LICENSE("GPL");
