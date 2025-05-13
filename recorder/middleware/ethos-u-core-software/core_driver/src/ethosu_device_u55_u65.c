 /*
 * Copyright (c) 2019-2025 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*******************************************************************************
 *  NOTE
 *  ----
 *  This version of the driver augments every register access record with the
 *  exact source-file and line‑number of the call‑site.  The change is fully
 *  backward‑compatible: **no existing call‑sites need to be modified.**
 *
 *  How it works
 *  ------------
 *  1. `reg_op_record_t` gains two fields: `file_name` and `line_number`.
 *  2. The original `record_reg_op()` implementation is renamed to
 *     `record_reg_op_impl()` and given two extra parameters.
 *  3. A macro of the old name forwards to the new implementation while
 *     injecting `__FILE__` and `__LINE__` automatically.
 *  4. `dump_reg_op_records()` now prints the extra information.
 ******************************************************************************/


//#include "pad_model.hpp"
//#include "transpose_model.hpp"
//#include "quantize_model.hpp"
//#include "strided_model.hpp"
//#include "relu_model.hpp"
//#include "add_model.hpp"
#include "conv2d_model.hpp"
#include "ethosu_interface.h"
#include "ethosu_device.h"
#include "ethosu_log.h"

#ifdef ETHOSU55
#include "ethosu_config_u55.h"
#else
#include "ethosu_config_u65.h"
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>    /* for memcpy */

/* -------------------------------------------------------------------------- */
/* Global monotonic counter for register‑access ordering                       */
/* -------------------------------------------------------------------------- */
static uint32_t g_npu_op_counter = 0;

#define ETHOSU_PRODUCT_U55 0
#define ETHOSU_PRODUCT_U65 1

#define BASEP_OFFSET 4

#ifdef ETHOSU65
#define ADDRESS_BITS 40
#else
#define ADDRESS_BITS 32
#endif

#define ADDRESS_MASK ((1ull << ADDRESS_BITS) - 1)
#define NPU_CMD_PWR_CLK_MASK (0xC)

/* -------------------------------------------------------------------------- */
/* Structures & bookkeeping for register‑operation recording                   */
/* -------------------------------------------------------------------------- */

typedef enum {
    REG_OP_READ,
    REG_OP_WRITE
} reg_op_type_t;

typedef struct {
    uint32_t        op_order;       /* Sequential order of the operation        */
    reg_op_type_t   op_type;        /* READ or WRITE                            */
    volatile void  *reg_address;    /* Register address                         */
    uint32_t        reg_value;      /* Value read/written                       */
    void           *data_ptr;       /* Optional associated data pointer         */
    uint32_t        data_size;      /* Size of data pointed to by data_ptr      */
    uint8_t        *data_snapshot;  /* Heap copy of the data (may be NULL)      */
    const char     *func_name;      /* Function in which the op occurred        */
    const char     *file_name;      /*  source file                             */
    uint32_t        line_number;    /*  source line                             */
} reg_op_record_t;

#define MAX_REG_OP_RECORDS 1024
static reg_op_record_t reg_op_records[MAX_REG_OP_RECORDS];
static uint32_t        reg_op_record_count = 0;

/* -------------------------------------------------------------------------- */
/* Internal implementation — do not call directly, use the macro below        */
/* -------------------------------------------------------------------------- */
static void record_reg_op_impl(reg_op_type_t type,
    volatile void *reg_addr,
    uint32_t value,
    uint32_t op_order,
    void *data_ptr,
    uint32_t data_size,
    const char *func_name,
    const char *file_name,
    uint32_t line_number)
{
// 替换原有实现，只保留一个定义
if (reg_op_record_count >= MAX_REG_OP_RECORDS)
return;

reg_op_record_t *rec = &reg_op_records[reg_op_record_count++];

rec->op_order    = op_order;
rec->op_type     = type;
rec->reg_address = reg_addr;
rec->reg_value   = value;
rec->data_ptr    = NULL;
rec->data_size   = 0;
rec->data_snapshot = NULL;
rec->func_name   = func_name;
rec->file_name   = file_name;
rec->line_number = line_number;

// 若需输出内存区域数据，通过 UART 一次性打印整行
if (data_ptr != NULL && data_size > 0) {
uint8_t *bytes = (uint8_t *)data_ptr;
size_t buf_size = (size_t)data_size * 3 + 128;
char *dump_buf = (char *)malloc(buf_size);
if (dump_buf) {
// 使用 %lu 并转换类型以匹配 uint32_t
size_t idx = snprintf(dump_buf, buf_size,
       "Record %lu: Data snapshot at %p : ",
       (unsigned long)op_order,
       data_ptr,
       (unsigned long)data_size);
for (uint32_t j = 0; j < data_size && idx < buf_size; ++j) {
idx += snprintf(dump_buf + idx, buf_size - idx, "%02x ", bytes[j]);
}
LOG_INFO("%s", dump_buf);
free(dump_buf);
} else {
// memory allocation failed
LOG_INFO("Record %lu: Data snapshot at %p (size %lu bytes): <memory allocation failed>",
(unsigned long)op_order,
data_ptr,
(unsigned long)data_size);
}
}
}

/* -------------------------------------------------------------------------- */
/* Public macro — keeps the old signature intact while injecting file/line    */
/* -------------------------------------------------------------------------- */
#define record_reg_op(type, addr, val, order, ptr, size, func) \
    record_reg_op_impl((type), (addr), (val), (order), (ptr), (size), \
                       (func), __FILE__, __LINE__)
/* -------------------------------------------------------------------------- */
/* Replay & dump utilities                                                     */
/* -------------------------------------------------------------------------- */
void replay_reg_operations(void)
{
    for (uint32_t i = 0; i < reg_op_record_count; i++) {
        reg_op_record_t *rec = &reg_op_records[i];

        /* Restore any recorded memory content first */
        if (rec->data_snapshot != NULL && rec->data_size > 0) {
            memcpy((void *)rec->reg_address, rec->data_snapshot, rec->data_size);
        }

        /* Only re‑issue write operations */
        if (rec->op_type == REG_OP_WRITE) {
            *((volatile uint32_t *)rec->reg_address) = rec->reg_value;
        }
    }
}
/**
 *  dump_reg_op_records – print all register‑operation records over UART
 */
void dump_reg_op_records(void)
{
    for (uint32_t i = 0; i < reg_op_record_count; i++) {
        reg_op_record_t *rec = &reg_op_records[i];
        const char *otype = (rec->op_type == REG_OP_READ) ? "READ" : "WRITE";

        char buf[256];  
        int len = snprintf(buf, sizeof(buf), "Record %u (%s:%u, %s): Type:%s, Address:%p, Value:0x%08x",
                           rec->op_order, rec->file_name, rec->line_number,
                           rec->func_name, otype, rec->reg_address, rec->reg_value);
        if (len > 0) {
            LOG_INFO("%s", buf);
        }

        if (rec->data_snapshot != NULL && rec->data_size > 0) {
            size_t buf_size = rec->data_size * 3 + 1;
            char *dump_buf = (char *)malloc(buf_size);
            if (dump_buf != NULL) {
                size_t idx = 0;
                for (uint32_t j = 0; j < rec->data_size; j++) {
                    idx += snprintf(dump_buf + idx, buf_size - idx, "%02x ", rec->data_snapshot[j]);
                }
                LOG_INFO("    Data (total %u bytes): %s", rec->data_size, dump_buf);
                free(dump_buf);
            } else {
                LOG_INFO("    Data (total %u bytes): <memory allocation failed>", rec->data_size);
            }
        }

        if (rec->data_snapshot != NULL) {
            free(rec->data_snapshot);
            rec->data_snapshot = NULL;
        }
    }
}


 //==============================================================================
 
/*---------------------------------------------------------------
 * 函数: ethosu_dev_init
 * 说明: 初始化 Ethos‑U 设备
 *---------------------------------------------------------------*/
struct ethosu_device *ethosu_dev_init(const void *base_address,
    uint32_t      secure_enable,
    uint32_t      privilege_enable)
{
LOG_INFO("ethosu_dev_init called.");

struct ethosu_device *dev = malloc(sizeof(struct ethosu_device));
if (!dev) {
LOG_ERR("Failed to allocate memory for Ethos‑U device");
return NULL;
}

dev->reg        = (volatile struct NPU_REG *)base_address;
dev->secure     = secure_enable;
dev->privileged = privilege_enable;

/* ---------- 记录 CONFIG.word 的读取 ---------- */
uint32_t cfg_word = dev->reg->CONFIG.word;
{
uint32_t order_val = ++g_npu_op_counter;
record_reg_op(REG_OP_READ,
(volatile void *)&dev->reg->CONFIG.word,
cfg_word,
order_val,
NULL, 0,
"ethosu_dev_init");
LOG_DEBUG("RD: CONFIG.word addr=%p, value=0x%08x, order=%u",
(void *)&dev->reg->CONFIG.word, cfg_word, order_val);
}

/* 通过位域结构体解析 product 字段 */
const struct config_r *cfg = (const struct config_r *)&cfg_word;

#ifdef ETHOSU55
if (cfg->product != ETHOSU_PRODUCT_U55)
#else
if (cfg->product != ETHOSU_PRODUCT_U65)
#endif
{
LOG_ERR("Failed to initialize device. Driver compiled for product 0x%x, "
"but CONFIG.product=0x%x",
#ifdef ETHOSU55
ETHOSU_PRODUCT_U55, cfg->product);
#else
ETHOSU_PRODUCT_U65, cfg->product);
#endif
goto err;
}

/* 使 NPU 进入已知状态 */
if (ethosu_dev_soft_reset(dev) != ETHOSU_SUCCESS) {
goto err;
}

return dev;

err:
free(dev);
return NULL;
}

 /*---------------------------------------------------------------
  * 函数: ethosu_dev_axi_init
  * 说明: 初始化 AXI 相关寄存器
  *---------------------------------------------------------------*/
 enum ethosu_error_codes ethosu_dev_axi_init(struct ethosu_device *dev)
 {
     LOG_INFO("ethosu_dev_axi_init called.");
     struct regioncfg_r rcfg = {0};
     struct axi_limit0_r l0  = {0};
     struct axi_limit1_r l1  = {0};
     struct axi_limit2_r l2  = {0};
     struct axi_limit3_r l3  = {0};
 
     /* QCONFIG */
     dev->reg->QCONFIG.word = NPU_QCONFIG;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: QCONFIG.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->QCONFIG.word, NPU_QCONFIG, order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->QCONFIG.word,
                       NPU_QCONFIG, order_val, NULL, 0, "ethosu_dev_axi_init");
     }
 
     /* REGIONCFG */
     rcfg.region0 = NPU_REGIONCFG_0;
     rcfg.region1 = NPU_REGIONCFG_1;
     rcfg.region2 = NPU_REGIONCFG_2;
     rcfg.region3 = NPU_REGIONCFG_3;
     rcfg.region4 = NPU_REGIONCFG_4;
     rcfg.region5 = NPU_REGIONCFG_5;
     rcfg.region6 = NPU_REGIONCFG_6;
     rcfg.region7 = NPU_REGIONCFG_7;
     dev->reg->REGIONCFG.word = rcfg.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: REGIONCFG.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->REGIONCFG.word, rcfg.word, order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->REGIONCFG.word,
                       rcfg.word, order_val, NULL, 0, "ethosu_dev_axi_init");
     }
 
     /* AXI_LIMIT registers */
     l0.max_beats = AXI_LIMIT0_MAX_BEATS_BYTES;
     l0.memtype = AXI_LIMIT0_MEM_TYPE;
     l0.max_outstanding_read_m1 = AXI_LIMIT0_MAX_OUTSTANDING_READS - 1;
     l0.max_outstanding_write_m1 = AXI_LIMIT0_MAX_OUTSTANDING_WRITES - 1;
 
     l1.max_beats = AXI_LIMIT1_MAX_BEATS_BYTES;
     l1.memtype = AXI_LIMIT1_MEM_TYPE;
     l1.max_outstanding_read_m1 = AXI_LIMIT1_MAX_OUTSTANDING_READS - 1;
     l1.max_outstanding_write_m1 = AXI_LIMIT1_MAX_OUTSTANDING_WRITES - 1;
 
     l2.max_beats = AXI_LIMIT2_MAX_BEATS_BYTES;
     l2.memtype = AXI_LIMIT2_MEM_TYPE;
     l2.max_outstanding_read_m1 = AXI_LIMIT2_MAX_OUTSTANDING_READS - 1;
     l2.max_outstanding_write_m1 = AXI_LIMIT2_MAX_OUTSTANDING_WRITES - 1;
 
     l3.max_beats = AXI_LIMIT3_MAX_BEATS_BYTES;
     l3.memtype = AXI_LIMIT3_MEM_TYPE;
     l3.max_outstanding_read_m1 = AXI_LIMIT3_MAX_OUTSTANDING_READS - 1;
     l3.max_outstanding_write_m1 = AXI_LIMIT3_MAX_OUTSTANDING_WRITES - 1;
 
     dev->reg->AXI_LIMIT0.word = l0.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: AXI_LIMIT0.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->AXI_LIMIT0.word, l0.word, order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->AXI_LIMIT0.word,
                       l0.word, order_val, NULL, 0, "ethosu_dev_axi_init");
     }
     dev->reg->AXI_LIMIT1.word = l1.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: AXI_LIMIT1.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->AXI_LIMIT1.word, l1.word, order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->AXI_LIMIT1.word,
                       l1.word, order_val, NULL, 0, "ethosu_dev_axi_init");
     }
     dev->reg->AXI_LIMIT2.word = l2.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: AXI_LIMIT2.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->AXI_LIMIT2.word, l2.word, order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->AXI_LIMIT2.word,
                       l2.word, order_val, NULL, 0, "ethosu_dev_axi_init");
     }
     dev->reg->AXI_LIMIT3.word = l3.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: AXI_LIMIT3.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->AXI_LIMIT3.word, l3.word, order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->AXI_LIMIT3.word,
                       l3.word, order_val, NULL, 0, "ethosu_dev_axi_init");
     }
 
     return ETHOSU_SUCCESS;
 }
 
 /*---------------------------------------------------------------
  * 函数: ethosu_dev_run_command_stream
  * 说明: 运行命令流，将命令写入相关寄存器
  *---------------------------------------------------------------*/
 void ethosu_dev_run_command_stream(struct ethosu_device *dev,
                                    const uint8_t *cmd_stream_ptr,
                                    uint32_t cms_length,
                                    const uint64_t *base_addr,
                                    int num_base_addr)
 {
     LOG_INFO("ethosu_dev_run_command_stream called.");
     assert(num_base_addr <= NPU_REG_BASEP_ARRLEN);
 
     struct cmd_r cmd;
     uint64_t qbase = (uintptr_t)cmd_stream_ptr + BASEP_OFFSET;
     assert(qbase <= ADDRESS_MASK);
     LOG_DEBUG("QBASE=0x%016llx, QSIZE=%u, base_pointer_offset=0x%08x",
               qbase, cms_length, BASEP_OFFSET);
 
     // 记录 cmd_stream_ptr 指向内存的数据内容
     {
         uint32_t order_val = ++g_npu_op_counter;
         record_reg_op(REG_OP_READ, (volatile void *)cmd_stream_ptr,
                       0, order_val, (void *)cmd_stream_ptr, cms_length, "ethosu_dev_run_command_stream");
     }
 
     /* Write QBASE lower 32 bits */
     dev->reg->QBASE.word[0] = qbase & 0xffffffff;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: QBASE.word[0] addr=%p, value=0x%08llx, order=%u",
                   (void*)&dev->reg->QBASE.word[0],
                   (unsigned long long)(qbase & 0xffffffff),
                   order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->QBASE.word[0],
                       (uint32_t)(qbase & 0xffffffff), order_val, NULL, 0, "ethosu_dev_run_command_stream");
     }
 #ifdef ETHOSU65
     /* Write QBASE higher 32 bits */
     dev->reg->QBASE.word[1] = qbase >> 32;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: QBASE.word[1] addr=%p, value=0x%08llx, order=%u",
                   (void*)&dev->reg->QBASE.word[1],
                   (unsigned long long)(qbase >> 32),
                   order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->QBASE.word[1],
                       (uint32_t)(qbase >> 32), order_val, NULL, 0, "ethosu_dev_run_command_stream");
     }
 #endif
 
     /* Write QSIZE */
     dev->reg->QSIZE.word = cms_length;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: QSIZE.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->QSIZE.word,
                   cms_length,
                   order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->QSIZE.word,
                       cms_length, order_val, NULL, 0, "ethosu_dev_run_command_stream");
     }
 
     /* Write BASEP array registers */
     for (int i = 0; i < num_base_addr; i++)
     {
         uint64_t addr = base_addr[i] + BASEP_OFFSET;
         assert(addr <= ADDRESS_MASK);
         LOG_DEBUG("BASEP%d=0x%016llx", i, addr);
 
         // 根据已知信息，假定 base_addr[0] 指向模型数据，base_addr[1] 指向输入数据，
         // 否则可以根据实际情况调整记录长度
         uint32_t data_length = MODEL_LENGTH;
         {
             uint32_t order_val = ++g_npu_op_counter;
             record_reg_op(REG_OP_READ,
                           (volatile void *)(uintptr_t)base_addr[i],
                           0, order_val,
                           (void *)(uintptr_t)base_addr[i],
                           data_length, "ethosu_dev_run_command_stream");
         }
 
         dev->reg->BASEP[i].word[0] = addr & 0xffffffff;
         {
             uint32_t order_val = ++g_npu_op_counter;
             LOG_DEBUG("WR: BASEP[%d].word[0] addr=%p, value=0x%08llx, order=%u",
                       i,
                       (void*)&dev->reg->BASEP[i].word[0],
                       (unsigned long long)(addr & 0xffffffff),
                       order_val);
             record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->BASEP[i].word[0],
                           (uint32_t)(addr & 0xffffffff), order_val, NULL, 0, "ethosu_dev_run_command_stream");
         }
 #ifdef ETHOSU65
         dev->reg->BASEP[i].word[1] = addr >> 32;
         {
             uint32_t order_val = ++g_npu_op_counter;
             LOG_DEBUG("WR: BASEP[%d].word[1] addr=%p, value=0x%08llx, order=%u",
                       i,
                       (void*)&dev->reg->BASEP[i].word[1],
                       (unsigned long long)(addr >> 32),
                       order_val);
             record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->BASEP[i].word[1],
                           (uint32_t)(addr >> 32), order_val, NULL, 0, "ethosu_dev_run_command_stream");
         }
 #endif
     }
 
     /* Read and modify CMD register */
     cmd.word = dev->reg->CMD.word & NPU_CMD_PWR_CLK_MASK;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("RD: CMD.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->CMD.word,
                   cmd.word,
                   order_val);
         record_reg_op(REG_OP_READ, (volatile void *)&dev->reg->CMD.word,
                       cmd.word, order_val, NULL, 0, "ethosu_dev_run_command_stream");
     }
     cmd.transition_to_running_state = 1;
     dev->reg->CMD.word = cmd.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: CMD.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->CMD.word,
                   cmd.word,
                   order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->CMD.word,
                       cmd.word, order_val, NULL, 0, "ethosu_dev_run_command_stream");
     }
 
     LOG_INFO("Test Case 6: transition_to_running_state %u",
              cmd.transition_to_running_state);
 }
 
 /*---------------------------------------------------------------
  * 函数: ethosu_dev_print_err_status
  * 说明: 打印设备错误状态
  *---------------------------------------------------------------*/
 void ethosu_dev_print_err_status(struct ethosu_device *dev)
{
    LOG_INFO("ethosu_dev_print_err_status called.");

    /* ---------- 读取 STATUS & QREAD 并记录 ---------- */
    uint32_t status_word = dev->reg->STATUS.word;
    uint32_t qread_word  = dev->reg->QREAD.word;

    {
        uint32_t order_val = ++g_npu_op_counter;
        record_reg_op(REG_OP_READ,
                      (volatile void *)&dev->reg->STATUS.word,
                      status_word,
                      order_val,
                      NULL, 0,
                      "ethosu_dev_print_err_status");
        LOG_DEBUG("RD: STATUS.word addr=%p, value=0x%08" PRIx32 ", order=%" PRIu32,
                  (void *)&dev->reg->STATUS.word, status_word, order_val);
    }
    {
        uint32_t order_val = ++g_npu_op_counter;
        record_reg_op(REG_OP_READ,
                      (volatile void *)&dev->reg->QREAD.word,
                      qread_word,
                      order_val,
                      NULL, 0,
                      "ethosu_dev_print_err_status");
        LOG_DEBUG("RD: QREAD.word addr=%p, value=0x%08" PRIx32 ", order=%" PRIu32,
                  (void *)&dev->reg->QREAD.word, qread_word, order_val);
    }

    /* ---------- 解析位域并输出 ---------- */
    const struct status_r *sts = (const struct status_r *)&status_word;

    LOG_ERR("STATUS=0x%08" PRIx32 ", qread=%" PRIu32
            ", cmd_end_reached=%" PRIu32
            ", bus_status=%" PRIu32 ", cmd_parse_error=%" PRIu32
            ", wd_fault=%" PRIu32 ", ecc_fault=%" PRIu32,
            status_word, qread_word,
            sts->cmd_end_reached,
            sts->bus_status, sts->cmd_parse_error,
            sts->wd_fault, sts->ecc_fault);

    if (sts->bus_status) {
        LOG_ERR("faulting_interface=%" PRIu32 ", faulting_channel=%" PRIu32,
                sts->faulting_interface, sts->faulting_channel);
    }
}
 /*---------------------------------------------------------------
 * 函数: ethosu_dev_handle_interrupt
 * 说明: 处理中断并清除中断标志
 *---------------------------------------------------------------*/
bool ethosu_dev_handle_interrupt(struct ethosu_device *dev)
{
    LOG_INFO("ethosu_dev_handle_interrupt called.");

    /* ---------- 读 CMD.word（保留时钟/电源位） ---------- */
    struct cmd_r cmd;
    cmd.word = dev->reg->CMD.word & NPU_CMD_PWR_CLK_MASK;
    {
        uint32_t order_val = ++g_npu_op_counter;
        record_reg_op(REG_OP_READ,
                      (volatile void *)&dev->reg->CMD.word,
                      cmd.word,
                      order_val,
                      NULL, 0,
                      "ethosu_dev_handle_interrupt");
        LOG_DEBUG("RD: CMD.word addr=%p, value=0x%08" PRIx32 ", order=%" PRIu32,
                  (void *)&dev->reg->CMD.word, cmd.word, order_val);
    }

    /* ---------- 写回 CMD.word，置 clear_irq ---------- */
    cmd.clear_irq      = 1;
    dev->reg->CMD.word = cmd.word;
    {
        uint32_t order_val = ++g_npu_op_counter;
        record_reg_op(REG_OP_WRITE,
                      (volatile void *)&dev->reg->CMD.word,
                      cmd.word,
                      order_val,
                      NULL, 0,
                      "ethosu_dev_handle_interrupt");
        LOG_DEBUG("WR: CMD.word addr=%p, value=0x%08" PRIx32 ", order=%" PRIu32,
                  (void *)&dev->reg->CMD.word, cmd.word, order_val);
    }

    /* ---------- 读取 STATUS & QREAD 并记录 ---------- */
    uint32_t status_word = dev->reg->STATUS.word;
    uint32_t qread_word  = dev->reg->QREAD.word;

    {
        uint32_t order_val = ++g_npu_op_counter;
        record_reg_op(REG_OP_READ,
                      (volatile void *)&dev->reg->STATUS.word,
                      status_word,
                      order_val,
                      NULL, 0,
                      "ethosu_dev_handle_interrupt");
        LOG_DEBUG("RD: STATUS.word addr=%p, value=0x%08" PRIx32 ", order=%" PRIu32,
                  (void *)&dev->reg->STATUS.word, status_word, order_val);
    }
    {
        uint32_t order_val = ++g_npu_op_counter;
        record_reg_op(REG_OP_READ,
                      (volatile void *)&dev->reg->QREAD.word,
                      qread_word,
                      order_val,
                      NULL, 0,
                      "ethosu_dev_handle_interrupt");
        LOG_DEBUG("RD: QREAD.word addr=%p, value=0x%08" PRIx32 ", order=%" PRIu32,
                  (void *)&dev->reg->QREAD.word, qread_word, order_val);
    }

    /* ---------- 解析位域并打印 ---------- */
    const struct status_r *sts = (const struct status_r *)&status_word;

    LOG_INFO("bus_status=%" PRIu32 ", cmd_parse_error=%" PRIu32
             ", wd_fault=%" PRIu32 ", ecc_fault=%" PRIu32
             ", cmd_end_reached=%" PRIu32 ", full_status=0x%08" PRIx32,
             sts->bus_status, sts->cmd_parse_error,
             sts->wd_fault, sts->ecc_fault,
             sts->cmd_end_reached, status_word);

    if (sts->bus_status) {
        LOG_INFO("faulting_interface=%" PRIu32 ", faulting_channel=%" PRIu32,
                 sts->faulting_interface, sts->faulting_channel);
    }
    LOG_INFO("QREAD (cmd‑stream offset) = %" PRIu32, qread_word);

    /* ---------- 判断错误 / 完成条件 ---------- */
    if (sts->bus_status      ||
        sts->cmd_parse_error ||
        sts->wd_fault        ||
        sts->ecc_fault       ||
        !sts->cmd_end_reached)
    {
        return false;   /* 推理未成功或出现错误 */
    }
    {
        #define RESULT_DATA_ADDR  ((volatile void *)0x20484000)
        #define RESULT_DATA_SIZE  MODEL_LENGTH
        uint32_t order_val = ++g_npu_op_counter;
        record_reg_op(REG_OP_READ,
                      RESULT_DATA_ADDR,        
                      0,                      
                      order_val,
                      (void *)RESULT_DATA_ADDR,
                      RESULT_DATA_SIZE,
                      "ethosu_dev_handle_interrupt");
        LOG_DEBUG("Record inference result snapshot: addr=%p, size=%u, order=%u",
                  RESULT_DATA_ADDR, RESULT_DATA_SIZE, order_val);
    }
    return true;        /* 推理完成且无错误 */
}
 /*---------------------------------------------------------------
  * 函数: ethosu_dev_verify_access_state
  * 说明: 验证设备的安全/特权访问状态
  *---------------------------------------------------------------*/
 bool ethosu_dev_verify_access_state(struct ethosu_device *dev)
{
    LOG_INFO("ethosu_dev_verify_access_state called.");
    
    // 直接读取整个 PROT 寄存器的 32 位值
    uint32_t prot_word = dev->reg->PROT.word;  // 假设 'word' 是 PROT 寄存器的 32 位值

    {
        uint32_t order_val = ++g_npu_op_counter;
        // 记录整个 PROT 寄存器的值
        record_reg_op(REG_OP_READ, (volatile void *)&dev->reg->PROT.word,
                      prot_word, order_val, NULL, 0, "ethosu_dev_verify_access_state");
        LOG_DEBUG("RD: PROT.word value=0x%08x, order=%u", prot_word, order_val);
    }

    // 获取 active_CSL 和 active_CPL 的值（通过位运算提取）
    uint32_t prot_active_CSL = (prot_word >> 1) & 0x1;  // active_CSL 是第 1 位
    uint32_t prot_active_CPL = prot_word & 0x1;          // active_CPL 是第 0 位

    // 校验
    if (prot_active_CSL != (dev->secure ? SECURITY_LEVEL_SECURE : SECURITY_LEVEL_NON_SECURE) ||
        prot_active_CPL != (dev->privileged ? PRIVILEGE_LEVEL_PRIVILEGED : PRIVILEGE_LEVEL_USER))
    {
        return false;
    }
    return true;
}

 /*---------------------------------------------------------------
  * 函数: ethosu_dev_soft_reset
  * 说明: 对设备执行软复位
  *---------------------------------------------------------------*/
 enum ethosu_error_codes ethosu_dev_soft_reset(struct ethosu_device *dev)
 {
     LOG_INFO("ethosu_dev_soft_reset called.");
     struct reset_r reset;
 
     reset.word = 0;
     reset.pending_CPL = dev->privileged ? PRIVILEGE_LEVEL_PRIVILEGED : PRIVILEGE_LEVEL_USER;
     reset.pending_CSL = dev->secure     ? SECURITY_LEVEL_SECURE     : SECURITY_LEVEL_NON_SECURE;
 
     LOG_INFO("Soft reset NPU");
     LOG_INFO("Test Case 7: soft reset NPU");
 
     /* 写 RESET.word */
     dev->reg->RESET.word = reset.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: RESET.word addr=%p, value=0x%08" PRIx32 ", order=%" PRIu32,
                   (void*)&dev->reg->RESET.word, reset.word, order_val);
 
         record_reg_op(REG_OP_WRITE,
                       (volatile void *)&dev->reg->RESET.word,
                       reset.word,
                       order_val,
                       NULL,
                       0,
                       "ethosu_dev_soft_reset");
     }
 
     /* 轮询等待 reset_status == 0 */
     for (int i = 0; i < 100000 && dev->reg->STATUS.reset_status != 0; i++) {
         // 可选：这里也可记录 dev->reg->STATUS.word 的读取
     }
 
     /* 读取整字 STATUS.word，再从中解出 reset_status */
     uint32_t sts_word = dev->reg->STATUS.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         // 修改：这里对 STATUS.word 做 record
         LOG_DEBUG("RD: STATUS.word addr=%p, full=0x%08" PRIx32 ", order=%" PRIu32,
                   (void *)&dev->reg->STATUS.word, sts_word, order_val);
 
         record_reg_op(REG_OP_READ,
                       (volatile void *)&dev->reg->STATUS.word,
                       sts_word,
                       order_val,
                       NULL,
                       0,
                       "ethosu_dev_soft_reset");
     }
 
     /* 用位域 struct 来解析 sts_word */
     const struct status_r *sts = (const struct status_r *)&sts_word;
     if (sts->reset_status != 0) {
         LOG_ERR("Soft reset timed out");
         return ETHOSU_GENERIC_FAILURE;
     }
 
     LOG_INFO("Test Case 15: reset.pending_CPL=0x%x, pending_CSL=0x%x",
              reset.pending_CPL, reset.pending_CSL);
 
     if (!ethosu_dev_verify_access_state(dev)) {
         LOG_ERR("Failed to switch security state and privilege level");
         return ETHOSU_GENERIC_FAILURE;
     }
 
     ethosu_dev_axi_init(dev);
     return ETHOSU_SUCCESS;
 } 
 /*---------------------------------------------------------------
  * 函数: ethosu_dev_get_hw_info
  * 说明: 获取设备硬件信息
  *---------------------------------------------------------------*/
 void ethosu_dev_get_hw_info(struct ethosu_device *dev, struct ethosu_hw_info *hwinfo)
 {
     LOG_INFO("ethosu_dev_get_hw_info called.");
     struct config_r cfg;
     struct id_r id;
 
     cfg.word = dev->reg->CONFIG.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("RD: CONFIG.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->CONFIG.word, cfg.word, order_val);
         record_reg_op(REG_OP_READ, (volatile void *)&dev->reg->CONFIG.word,
                       cfg.word, order_val, NULL, 0, "ethosu_dev_get_hw_info");
     }
     id.word = dev->reg->ID.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("RD: ID.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->ID.word, id.word, order_val);
         record_reg_op(REG_OP_READ, (volatile void *)&dev->reg->ID.word,
                       id.word, order_val, NULL, 0, "ethosu_dev_get_hw_info");
     }
 
     hwinfo->cfg.cmd_stream_version = cfg.cmd_stream_version;
     hwinfo->cfg.custom_dma         = cfg.custom_dma;
     hwinfo->cfg.macs_per_cc        = cfg.macs_per_cc;
 
     hwinfo->version.arch_major_rev = id.arch_major_rev;
     hwinfo->version.arch_minor_rev = id.arch_minor_rev;
     hwinfo->version.arch_patch_rev = id.arch_patch_rev;
     hwinfo->version.product_major  = id.product_major;
     hwinfo->version.version_major  = id.version_major;
     hwinfo->version.version_minor  = id.version_minor;
     hwinfo->version.version_status = id.version_status;
 
     LOG_INFO("Test Case 1-2: id.arch_major_rev %lu", id.arch_major_rev);
     LOG_INFO("Test Case 1-2: id.arch_minor_rev %lu", id.arch_minor_rev);
     LOG_INFO("Test Case 1-2: id.arch_patch_rev %lu", id.arch_patch_rev);
     LOG_INFO("Test Case 1-2: id.version_major %lu", id.version_major);
     LOG_INFO("Test Case 1-2: id.version_minor %lu", id.version_minor);
     LOG_INFO("Test Case 1-2: id.version_status %lu", id.version_status);
     LOG_INFO("Test Case 3: config.macs_per_cc %lu", cfg.macs_per_cc);
     LOG_INFO("Test Case 3: config.cmd_stream_verison %lu", cfg.cmd_stream_version);
     LOG_INFO("Test Case 3: config.shram_size %lu", cfg.shram_size);
 }
 
 /*---------------------------------------------------------------
  * 函数: ethosu_dev_set_clock_and_power
  * 说明: 设置设备的时钟和电源状态
  *---------------------------------------------------------------*/
 enum ethosu_error_codes ethosu_dev_set_clock_and_power(struct ethosu_device *dev,
                                                         enum ethosu_clock_q_request clock_q,
                                                         enum ethosu_power_q_request power_q)
 {
     LOG_INFO("ethosu_dev_set_clock_and_power called.");
     struct cmd_r cmd = {0};
     cmd.word = dev->reg->CMD.word & NPU_CMD_PWR_CLK_MASK;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("RD: CMD.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->CMD.word, cmd.word, order_val);
         record_reg_op(REG_OP_READ, (volatile void *)&dev->reg->CMD.word,
                       cmd.word, order_val, NULL, 0, "ethosu_dev_set_clock_and_power");
     }
 
     if (power_q != ETHOSU_POWER_Q_UNCHANGED)
     {
         cmd.power_q_enable = (power_q == ETHOSU_POWER_Q_ENABLE) ? 1 : 0;
     }
     if (clock_q != ETHOSU_CLOCK_Q_UNCHANGED)
     {
         cmd.clock_q_enable = (clock_q == ETHOSU_CLOCK_Q_ENABLE) ? 1 : 0;
     }
 
     dev->reg->CMD.word = cmd.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("WR: CMD.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->CMD.word, cmd.word, order_val);
         record_reg_op(REG_OP_WRITE, (volatile void *)&dev->reg->CMD.word,
                       cmd.word, order_val, NULL, 0, "ethosu_dev_set_clock_and_power");
     }
 
     LOG_INFO("Test Case 4: power_q_enable 0x%x", cmd.power_q_enable);
     LOG_INFO("Test Case 5: clock_q_enable 0x%x", cmd.clock_q_enable);
     return ETHOSU_SUCCESS;
 }
 
 /*---------------------------------------------------------------
  * 函数: ethosu_dev_verify_optimizer_config
  * 说明: 验证设备的优化器配置
  *---------------------------------------------------------------*/
 bool ethosu_dev_verify_optimizer_config(struct ethosu_device *dev, uint32_t cfg_in, uint32_t id_in)
 {
     LOG_INFO("ethosu_dev_verify_optimizer_config called.");
     struct config_r *opt_cfg = (struct config_r *)&cfg_in;
     struct config_r hw_cfg;
     struct id_r *opt_id = (struct id_r *)&id_in;
     struct id_r hw_id;
     bool ret = true;
 
     hw_cfg.word = dev->reg->CONFIG.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("RD: CONFIG.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->CONFIG.word, hw_cfg.word, order_val);
         record_reg_op(REG_OP_READ, (volatile void *)&dev->reg->CONFIG.word,
                       hw_cfg.word, order_val, NULL, 0, "ethosu_dev_verify_optimizer_config");
     }
     hw_id.word = dev->reg->ID.word;
     {
         uint32_t order_val = ++g_npu_op_counter;
         LOG_DEBUG("RD: ID.word addr=%p, value=0x%08x, order=%u",
                   (void*)&dev->reg->ID.word, hw_id.word, order_val);
         record_reg_op(REG_OP_READ, (volatile void *)&dev->reg->ID.word,
                       hw_id.word, order_val, NULL, 0, "ethosu_dev_verify_optimizer_config");
     }
 
     LOG_INFO("Optimizer config. product=%d, cmd_stream_version=%d, macs_per_cc=%d, shram_size=%d, custom_dma=%d",
              opt_cfg->product,
              opt_cfg->cmd_stream_version,
              opt_cfg->macs_per_cc,
              opt_cfg->shram_size,
              opt_cfg->custom_dma);
     LOG_INFO("Optimizer config. arch version: %d.%d.%d",
              opt_id->arch_major_rev,
              opt_id->arch_minor_rev,
              opt_id->arch_patch_rev);
     LOG_INFO("Ethos-U config. product=%d, cmd_stream_version=%d, macs_per_cc=%d, shram_size=%d, custom_dma=%d",
              hw_cfg.product,
              hw_cfg.cmd_stream_version,
              hw_cfg.macs_per_cc,
              hw_cfg.shram_size,
              hw_cfg.custom_dma);
     LOG_INFO("Ethos-U. arch version=%d.%d.%d",
              hw_id.arch_major_rev, hw_id.arch_minor_rev, hw_id.arch_patch_rev);
 
     if (opt_cfg->word != hw_cfg.word)
     {
         if (hw_cfg.product != opt_cfg->product)
         {
             LOG_ERR("NPU config mismatch. npu.product=%d, optimizer.product=%d",
                     hw_cfg.product, opt_cfg->product);
             ret = false;
         }
 
         if (hw_cfg.macs_per_cc != opt_cfg->macs_per_cc)
         {
             LOG_ERR("NPU config mismatch. npu.macs_per_cc=%d, optimizer.macs_per_cc=%d",
                     hw_cfg.macs_per_cc, opt_cfg->macs_per_cc);
             ret = false;
         }
 
         if (hw_cfg.cmd_stream_version != opt_cfg->cmd_stream_version)
         {
             LOG_ERR("NPU config mismatch. npu.cmd_stream_version=%d, optimizer.cmd_stream_version=%d",
                     hw_cfg.cmd_stream_version, opt_cfg->cmd_stream_version);
             ret = false;
         }
 
         if (!hw_cfg.custom_dma && opt_cfg->custom_dma)
         {
             LOG_ERR("NPU config mismatch. npu.custom_dma=%d, optimizer.custom_dma=%d",
                     hw_cfg.custom_dma, opt_cfg->custom_dma);
             ret = false;
         }
     }
     if (ret == true)
         LOG_INFO("Test Case 16: handle_optimizer_config: NPU config match");
 
     if ((hw_id.arch_major_rev != opt_id->arch_major_rev) || (hw_id.arch_minor_rev < opt_id->arch_minor_rev))
     {
         LOG_ERR("NPU arch mismatch. npu.arch=%d.%d.%d, optimizer.arch=%d.%d.%d",
                 hw_id.arch_major_rev,
                 hw_id.arch_minor_rev,
                 hw_id.arch_patch_rev,
                 opt_id->arch_major_rev,
                 opt_id->arch_minor_rev,
                 opt_id->arch_patch_rev);
         ret = false;
     }
     if (ret == true)
         LOG_INFO("Test Case 17: handle_optimizer_config: NPU arch match");
 
     return ret;
 }
 