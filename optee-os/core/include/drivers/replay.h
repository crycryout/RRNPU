/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025 Your Name or Org
 *
 * Header for the Ethos‑U replay driver.
 */

 #ifndef REPLAY_H
 #define REPLAY_H
 
 #include <types_ext.h>
 #include <io.h>
 #include <mm/core_memprot.h>
 
 /* Physical base addresses and sizes */
 #define REPLAY_NPU_REG_BASE   0x4A900000UL
 #define REPLAY_NPU_REG_SIZE   0x00001000UL  /* 4 KB */
 
 #define REPLAY_OCRAM_BASE     0x20480000UL
 #define REPLAY_OCRAM_SIZE     (640 * 1024UL) /* 640 KB */
 
 /*
  * Driver data: holds mapped virtual addresses for
  * NPU registers and OCRAM.
  */
 struct replay_data {
     struct io_pa_va npu_regs;  /* PA/VA for NPU MMIO */
     struct io_pa_va ocram;     /* PA/VA for OCRAM */
 };
 
 /*
  * Initialize the replay driver:
  *  - maps NPU MMIO and OCRAM into secure virtual address space.
  *  - fills in rd->npu_regs.va and rd->ocram.va
  * Returns 0 on success or < 0 on error.
  */
 int replay_driver_init(struct replay_data *rd);
 
 /*
  * Perform the "initialization & verification" phase
  * of the Ethos‑U replay sequence.
  */
 void replay_initialization_verification(struct replay_data *rd);
 
 /*
  * Perform the "inference" phase of the
  * Ethos‑U replay sequence.
  */
 void replay_inference(struct replay_data *rd);
 
 /*
  * Handle any pending Ethos‑U interrupts by
  * replaying recorded IRQ operations.
  */
 void replay_handle_interrupt(struct replay_data *rd);
 
 #endif /* REPLAY_H */
 