// SPDX-License-Identifier: BSD-2-Clause
/*
 * Ethos‑U replay driver for OP‑TEE Core
 * Driver init 阶段（每个核）做一次映射，后续统一使用 global_rd
 */

 #include <initcall.h>
 #include <kernel/dt.h>
 #include <mm/core_memprot.h>
 #include <trace.h>
 #include <string.h>
 
 #include <drivers/replay.h>       /* struct replay_data, 函数声明 */
 #include "replay_templates.h"     /* register_access_records, op_*_data 等 */
 
 #define REPLAY_NPU_REG_BASE   0x4A900000UL
 #define REPLAY_NPU_REG_SIZE   0x00001000UL  /* 4 KB */
 #define REPLAY_OCRAM_BASE     0x20480000UL
 #define REPLAY_OCRAM_SIZE     (640 * 1024UL) /* 640 KB */
 
 /* 全局保存 driver_init 阶段映射结果 */
 static struct replay_data global_rd;
 
 /*
  * 根据物理地址计算虚拟 MMIO 寄存器地址
  */
 static inline volatile uint32_t *get_reg_va(uintptr_t pa)
 {
     size_t offset = pa - REPLAY_NPU_REG_BASE;
     void *va = (void *)(global_rd.npu_regs.va + offset);
 
     DMSG("replay: get_reg_va: PA=0x%08" PRIxPTR " -> VA=%p (off=0x%zx)\n",
          pa, va, offset);
     return (volatile uint32_t *)va;
 }
 
 /*
  * 单次寄存器读写（重放一条记录）
  */
 static uint32_t do_register_access(reg_op_record_t *rec)
 {
     uintptr_t pa = (uintptr_t)rec->reg_address;
     volatile uint32_t *addr;
     uint32_t result = 0;
 
     DMSG("replay: op_order=%u op_type=%u PA=0x%08" PRIxPTR "\n",
          rec->op_order, rec->op_type, pa);
 
     /* OCRAM 预写数据 */
     switch (rec->op_order) {
     case 24:
         memcpy((void *)(global_rd.ocram.va + (0x20480200 - REPLAY_OCRAM_BASE)),
                op_24_data, sizeof(op_24_data));
         break;
     case 28:
         memcpy((void *)(global_rd.ocram.va + (0x20480110 - REPLAY_OCRAM_BASE)),
                op_28_model_record_data, sizeof(op_28_model_record_data));
         break;
     case 34:
         memcpy((void *)(global_rd.ocram.va + (0x20480000 - REPLAY_OCRAM_BASE)),
                op_34model_head_data, sizeof(op_34model_head_data));
         break;
     case 37:
         memcpy((void *)(global_rd.ocram.va + (0x20484050 - REPLAY_OCRAM_BASE)),
                op_37_input_record_data, sizeof(op_37_input_record_data));
         break;
     default:
         break;
     }
 
     if (rec->op_type == REG_OP_WRITE) {
         addr = get_reg_va(pa);
         *addr = rec->reg_value;
         DMSG("replay: WRITE VA=%p = 0x%08x\n", addr, rec->reg_value);
         result = rec->reg_value;
     } else {
         addr = get_reg_va(pa);
         result = *addr;
         DMSG("replay: READ  VA=%p -> 0x%08x (exp=0x%08x)\n",
              addr, result, rec->reg_value);
     }
     return result;
 }
 
 /*
  * 驱动接口：初始化 & 验证阶段
  */
 void replay_initialization_verification(struct replay_data *rd __unused)
 {
     for (int i = INIT_VERIFICATION_START; i <= INIT_VERIFICATION_END; i++) {
         if (i != WAIT) {
             do_register_access(&register_access_records[i]);
         } else {
             int j = 0;
             do {
                 do_register_access(&register_access_records[i]);
             } while (++j < 100000);
         }
     }
 }
 
 /*
  * 驱动接口：推理（inference）阶段
  */
 void replay_inference(struct replay_data *rd __unused)
 {
     for (int i = RUN_STREAM_COMMAND_START; i <= RUN_STREAM_COMMAND_END; i++)
         do_register_access(&register_access_records[i]);
 }
 
 /*
  * 驱动接口：中断处理阶段
  */
 void replay_handle_interrupt(struct replay_data *rd __unused)
 {
     for (int i = INTERRUPT_HANDLING_START; i < INTERRUPT_HANDLING_END; i++) {
         reg_op_record_t *rec = &register_access_records[i];
         volatile uint32_t *addr = get_reg_va((uintptr_t)rec->reg_address);
         uint32_t exp = (rec->op_order == INTERRUPT_HANDLING_START) ?
                        1 : rec->reg_value;
         if (rec->op_type == REG_OP_WRITE) {
             *addr = rec->reg_value;
             DMSG("replay: IRQ WRITE VA=%p = 0x%08x\n",
                  addr, rec->reg_value);
         } else {
             uint32_t v;
             do {
                 v = *addr;
             } while (v != exp);
             DMSG("replay: IRQ READ OK VA=%p = 0x%08x\n", addr, v);
         }
     }
 }
 
 /*
  * 真正做映射的函数
  */
 static int do_global_init(void)
 {
     vaddr_t va;
 
     /* 1) 映射 NPU MMIO */
     va = core_mmu_get_va(REPLAY_NPU_REG_BASE,
                          MEM_AREA_IO_SEC, REPLAY_NPU_REG_SIZE);
     if (!va) {
         EMSG("replay: map NPU MMIO failed");
         return -1;
     }
     global_rd.npu_regs.pa = REPLAY_NPU_REG_BASE;
     global_rd.npu_regs.va = va;
 
     /* 2) 映射 OCRAM */
     va = core_mmu_get_va(REPLAY_OCRAM_BASE,
                          MEM_AREA_RAM_SEC, REPLAY_OCRAM_SIZE);
     if (!va) {
         EMSG("replay: map OCRAM failed");
         return -1;
     }
     global_rd.ocram.pa = REPLAY_OCRAM_BASE;
     global_rd.ocram.va = va;
 
     DMSG("replay: mapped NPU @%p, OCRAM @%p\n",
          (void *)global_rd.npu_regs.va,
          (void *)global_rd.ocram.va);
     return 0;
 }
 
 /*
  * 每个核启动驱动时都调用一次，确保 multi-core 下 global_rd 被初始化
  */
 static TEE_Result _replay_init_driver(void)
 {
     return do_global_init() < 0 ? TEE_ERROR_GENERIC : TEE_SUCCESS;
 }
 driver_init(_replay_init_driver);
 
 /*
  * PTA 链接存根：PTA 路径中调用此函数时不做重复映射
  */
 int replay_driver_init(struct replay_data *rd __unused)
 {
     return 0;
 }
 