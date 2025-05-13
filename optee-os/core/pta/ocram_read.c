// SPDX-License-Identifier: BSD-2-Clause
/*
 * ocram_read.pta
 *
 * A pseudo-TA that waits until a flag at physical 0x20490000 becomes 1,
 * then reads up to 128 bytes from OCRAM physical address 0x20484000
 * and returns it to a calling TA via MEMREF_OUTPUT.
 * Performs cache maintenance to ensure data visibility on Cortex-M33.
 */

 #include <compiler.h>
 #include <kernel/pseudo_ta.h>
 #include <mm/core_memprot.h>
 #include <trace.h>
 #include <tee_api_types.h>        /* TEE_Param, TEE_Result, etc. */
 #include <kernel/cache_helpers.h> /* dcache_* APIs */
 #include <string.h>               /* memcpy */
 
 #define TA_NAME           "ocram_read.pta"
 #define OCRAM_READ_UUID   \
     { 0xfa152bfd, 0x7c9e, 0x4c33, \
       { 0xb8, 0xac, 0x7f, 0x5c, 0x2b, 0x64, 0x49, 0x92 } }
 
 /* Command ID: read from OCRAM once flag is set */
 #define OCRAM_READ_CMD    0
 
 static TEE_Result pta_read_from_ocram(uint32_t ptypes,
                                       TEE_Param params[TEE_NUM_PARAMS])
 {
     const paddr_t flag_pa = 0x20490000; /* 循环等待的标志位 */
     const paddr_t src_pa  = 0x20484000; /* OCRAM 数据起始地址 */
     void *flag_va = NULL;
     void *src_va  = NULL;
     uint32_t req_size = params[0].memref.size;
     const uint32_t MAX_READ = 1024;
 
     DMSG("pta_read_from_ocram called, ptypes=0x%" PRIx32, ptypes);
 
     /* 参数类型必须是单输出 MEMREF */
     if (TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                         TEE_PARAM_TYPE_NONE,
                         TEE_PARAM_TYPE_NONE,
                         TEE_PARAM_TYPE_NONE) != ptypes) {
         EMSG("Invalid parameter types, expected MEMREF_OUTPUT");
         return TEE_ERROR_BAD_PARAMETERS;
     }
 
     /* 大小检查 */
     if (req_size == 0 || req_size > MAX_READ) {
         EMSG("Requested read size %u invalid (max %u)", req_size, MAX_READ);
         return TEE_ERROR_BAD_PARAMETERS;
     }
 
     /* 1) 映射并循环等待 flag 变为 1 */
     flag_va = phys_to_virt(flag_pa, MEM_AREA_RAM_SEC, 1);
     if (!flag_va) {
         EMSG("Failed to map flag PA 0x%" PRIxPA, flag_pa);
         return TEE_ERROR_GENERIC;
     }
 
     DMSG("Waiting for flag at PA 0x%" PRIxPA, flag_pa);
     while (true) {
         dcache_inv_range(flag_va, 1);
         if (*(volatile uint8_t *)flag_va == 1)
             break;
     }
     DMSG("Flag is set, proceed to read OCRAM");
 
     /* 2) 映射 OCRAM 数据区 */
     src_va = phys_to_virt(src_pa, MEM_AREA_RAM_SEC, MAX_READ);
     if (!src_va) {
         EMSG("Failed to map OCRAM PA 0x%" PRIxPA, src_pa);
         return TEE_ERROR_GENERIC;
     }
 
     /* 3) Invalidate D-Cache，保证写入的数据是最新的 */
     dcache_inv_range(src_va, req_size);
     DMSG("Invalidated D-Cache for OCRAM VA 0x%" PRIxVA " size %u",
          (uintptr_t)src_va, req_size);
 
     /* 4) 拷贝数据到输出缓冲区 */
  /*   memcpy(params[0].memref.buffer, src_va, req_size);
     DMSG("Copied %u bytes from OCRAM PA 0x%" PRIxPA " to output buffer",
          req_size, src_pa);
          */

    /* 4) 每 16 字节一行打印 */
    uint32_t i, j;
    char line[16 * 3 + 1];
    int len;
    const char hex[] = "0123456789abcdef";
    for (i = 0; i < req_size; i += 16) {
        len = 0;
        /* 拼接本行最多 16 个字节的 hex */
        for (j = 0; j < 16 && i + j < req_size; j++) {
            uint8_t v = *(volatile uint8_t *)((uintptr_t)src_va + i + j);
            /* 高 4 位 */
            line[len++] = hex[v >> 4];
            /* 低 4 位 */
            line[len++] = hex[v & 0xF];
            /* 空格分隔 */
            line[len++] = ' ';
        }
        line[len] = '\0';
        DMSG("OCRAM[PA 0x%" PRIxPA " + %03u..%03u]: %s",
             src_pa, i, i + j - 1, line);
    }


 
     return TEE_SUCCESS;
 }
 
 static TEE_Result invoke_command(void *psess __unused,
                                  uint32_t cmd,
                                  uint32_t ptypes,
                                  TEE_Param params[TEE_NUM_PARAMS])
 {
     if (cmd == OCRAM_READ_CMD)
         return pta_read_from_ocram(ptypes, params);
     return TEE_ERROR_BAD_PARAMETERS;
 }
 
 pseudo_ta_register(.uuid = OCRAM_READ_UUID,
                    .name = TA_NAME,
                    .flags = PTA_DEFAULT_FLAGS,
                    .invoke_command_entry_point = invoke_command);
 