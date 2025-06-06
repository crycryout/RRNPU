// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2019, 2023 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#ifdef CFG_IMX_TRUSTED_ARM_CE
#include <drivers/imx_trusted_arm_ce.h>
#endif
#include <drivers/imx_uart.h>
#include <imx.h>
#include <kernel/boot.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_fast.h>
#define OCRAM_START 0x20480000
#define OCRAM_SIZE 640*1024

static struct imx_uart_data console_data __nex_bss;

#ifdef CONSOLE_UART_BASE
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
			CORE_MMU_PGDIR_SIZE);
#endif
#ifdef GIC_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, CORE_MMU_PGDIR_SIZE);
#endif
#ifdef ANATOP_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, ANATOP_BASE, CORE_MMU_PGDIR_SIZE);
#endif
#ifdef GICD_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, 0x10000);
#endif
#ifdef AIPS0_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AIPS0_BASE,
			ROUNDUP(AIPS0_SIZE, CORE_MMU_PGDIR_SIZE));
#endif
#ifdef AIPS1_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AIPS1_BASE,
			ROUNDUP(AIPS1_SIZE, CORE_MMU_PGDIR_SIZE));
#endif
#ifdef AIPS2_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AIPS2_BASE,
			ROUNDUP(AIPS2_SIZE, CORE_MMU_PGDIR_SIZE));
#endif
#ifdef AIPS3_BASE
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AIPS3_BASE,
			ROUNDUP(AIPS3_SIZE, CORE_MMU_PGDIR_SIZE));
#endif
#ifdef IRAM_BASE
register_phys_mem(MEM_AREA_TEE_COHERENT,
		  ROUNDDOWN(IRAM_BASE, CORE_MMU_PGDIR_SIZE),
		  CORE_MMU_PGDIR_SIZE);
#endif
#ifdef M4_AIPS_BASE
register_phys_mem(MEM_AREA_IO_SEC, M4_AIPS_BASE, M4_AIPS_SIZE);
#endif
#ifdef IRAM_S_BASE
register_phys_mem(MEM_AREA_TEE_COHERENT,
		  ROUNDDOWN(IRAM_S_BASE, CORE_MMU_PGDIR_SIZE),
		  CORE_MMU_PGDIR_SIZE);
#endif

#if defined(CFG_PL310)
register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			ROUNDDOWN(PL310_BASE, CORE_MMU_PGDIR_SIZE),
			CORE_MMU_PGDIR_SIZE);
#endif

#ifdef CFG_DRAM_BASE
register_ddr(CFG_DRAM_BASE, CFG_DDR_SIZE);
#endif
#ifdef CFG_NSEC_DDR_1_BASE
register_ddr(CFG_NSEC_DDR_1_BASE, CFG_NSEC_DDR_1_SIZE);
#endif
register_phys_mem_pgdir(MEM_AREA_RAM_SEC, OCRAM_START, OCRAM_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, 0x4a900000, 0x1000 );

void console_init(void)
{
#ifdef CONSOLE_UART_BASE
	imx_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
#endif
}

void boot_primary_init_intc(void)
{
#ifdef GICD_BASE
	gic_init(0, GICD_BASE);
#else
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);
#endif
}

#if CFG_TEE_CORE_NB_CORE > 1
void boot_secondary_init_intc(void)
{
	gic_cpu_init();
}
#endif

/* Overriding the default __weak tee_entry_fast() */
void tee_entry_fast(struct thread_smc_args *args)
{
	switch (args->a0) {
#ifdef CFG_IMX_TRUSTED_ARM_CE
	case IMX_SMC_ENCRYPT_CBC:
		imx_smc_cipher_cbc(args, true);
		break;
	case IMX_SMC_DECRYPT_CBC:
		imx_smc_cipher_cbc(args, false);
		break;
	case IMX_SMC_ENCRYPT_XTS:
		imx_smc_cipher_xts(args, true);
		break;
	case IMX_SMC_DECRYPT_XTS:
		imx_smc_cipher_xts(args, false);
		break;
#endif
	default:
		__tee_entry_fast(args);
		break;
	}
}
