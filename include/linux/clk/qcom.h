/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 */

#ifndef __LINUX_CLK_QCOM_H_
#define __LINUX_CLK_QCOM_H_

#include <linux/clk.h>
#include <linux/kconfig.h>
#include <linux/regulator/consumer.h>

enum branch_mem_flags {
	CLKFLAG_RETAIN_PERIPH,
	CLKFLAG_NORETAIN_PERIPH,
	CLKFLAG_RETAIN_MEM,
	CLKFLAG_NORETAIN_MEM,
	CLKFLAG_PERIPH_OFF_SET,
	CLKFLAG_PERIPH_OFF_CLEAR,
};

#if IS_REACHABLE(CONFIG_COMMON_CLK_QCOM)
int qcom_clk_get_voltage(struct clk *clk, unsigned long rate);
int qcom_clk_set_flags(struct clk *clk, unsigned long flags);
void qcom_clk_dump(struct clk *clk, struct regulator *regulator,
		   bool calltrace);
void qcom_clk_bulk_dump(int num_clks, struct clk_bulk_data *clks,
			struct regulator *regulator, bool calltrace);
#else
static inline int qcom_clk_get_voltage(struct clk *clk, unsigned long rate)
{
	return 0;
}

static inline int qcom_clk_set_flags(struct clk *clk, unsigned long flags)
{
	return 0;
}

static inline void qcom_clk_dump(struct clk *clk, struct regulator *regulator,
				 bool calltrace)
{
}

static inline void qcom_clk_bulk_dump(int num_clks, struct clk_bulk_data *clks,
				      struct regulator *regulator,
				      bool calltrace)
{
}
#endif

#endif  /* __LINUX_CLK_QCOM_H_ */
