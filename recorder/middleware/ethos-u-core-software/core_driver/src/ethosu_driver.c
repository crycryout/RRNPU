/*
 * Copyright (c) 2019-2022 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/******************************************************************************
 * Includes
 ******************************************************************************/

 #include "clock_config.h"
 #include "ethosu_driver.h"
 #include "ethosu_device.h"
 #include "ethosu_log.h"
 #include "ethosu_shared.h"
 #include "pmu_ethosu.h"
 
 #ifdef ETHOSU55
 #include "ethosu_config_u55.h"
 #else
 #include "ethosu_config_u65.h"
 #endif
 
 #include <assert.h>
 #include <cmsis_compiler.h>
 #include <inttypes.h>
 #include <stdbool.h>
 #include <stddef.h>
 #include <stdlib.h>
 #include <string.h>
 
 /******************************************************************************
  * Defines
  ******************************************************************************/
 
 #define UNUSED(x) ((void)x)
 
 #define BYTES_IN_32_BITS 4
 #define MASK_16_BYTE_ALIGN (0xF)
 #define OPTIMIZER_CONFIG_LENGTH_32_BIT_WORD 2
 #define DRIVER_ACTION_LENGTH_32_BIT_WORD 1
 #define ETHOSU_FOURCC ('1' << 24 | 'P' << 16 | 'O' << 8 | 'C') // "Custom Operator Payload 1"
 
 #define FAST_MEMORY_BASE_ADDR_INDEX 2
 
 /******************************************************************************
  * Types
  ******************************************************************************/
 
 // Driver actions
 enum DRIVER_ACTION_e
 {
     RESERVED         = 0,
     OPTIMIZER_CONFIG = 1,
     COMMAND_STREAM   = 2,
     NOP              = 5,
 };
 
 // Custom operator payload data struct
 struct cop_data_s
 {
     union
     {
         // Driver action data
         struct
         {
             uint8_t driver_action_command; // (valid values in DRIVER_ACTION_e)
             uint8_t reserved;
 
             // Driver action data
             union
             {
                 // DA_CMD_OPT_CFG
                 struct
                 {
                     uint16_t rel_nbr : 4;
                     uint16_t patch_nbr : 4;
                     uint16_t opt_cfg_reserved : 8;
                 };
 
                 // DA_CMD_CMSTRM
                 struct
                 {
                     uint16_t length;
                 };
 
                 uint16_t driver_action_data;
             };
         };
 
         uint32_t word;
     };
 };
 
 // optimizer config struct
 struct opt_cfg_s
 {
     struct cop_data_s da_data;
     uint32_t cfg;
     uint32_t id;
 };
 
 /******************************************************************************
  * Variables
  ******************************************************************************/
 
 // Registered drivers linked list HEAD
 static struct ethosu_driver *registered_drivers = NULL;
 
 /******************************************************************************
  * Weak functions - Cache
  *
  * Default NOP operations. Override if available on the targeted device.
  ******************************************************************************/
 
 /*
  * Flush/clean the data cache by address and size. Passing NULL as p argument
  * expects the whole cache to be flushed.
  */
 void __attribute__((weak)) ethosu_flush_dcache(uint32_t *p, size_t bytes)
 {
     LOG_INFO("ethosu_flush_dcache called.");
     UNUSED(p);
     UNUSED(bytes);
 }
 
 /*
  * Invalidate the data cache by address and size. Passing NULL as p argument
  * expects the whole cache to be invalidated.
  */
 void __attribute__((weak)) ethosu_invalidate_dcache(uint32_t *p, size_t bytes)
 {
     LOG_INFO("ethosu_invalidate_dcache called."); // [Called]
     UNUSED(p);
     UNUSED(bytes);
 }
 
 /******************************************************************************
  * Weak functions - Semaphore/Mutex for multi NPU
  *
  * Following section handles the minimal semaphore and mutex implementation in
  * case of baremetal applications. Weak symbols will be overridden by RTOS
  * definitions and implement true thread-safety (in application layer).
  ******************************************************************************/
 
 struct ethosu_semaphore_t
 {
     uint8_t count;
 };
 
 static void *ethosu_mutex;
 static void *ethosu_semaphore;
 
 void *__attribute__((weak)) ethosu_mutex_create(void)
 {
     LOG_INFO("ethosu_mutex_create called.");
     return NULL;
 }
 
 void __attribute__((weak)) ethosu_mutex_destroy(void *mutex)
 {
     LOG_INFO("ethosu_mutex_destroy called.");
     UNUSED(mutex);
 }
 
 int __attribute__((weak)) ethosu_mutex_lock(void *mutex)
 {
     LOG_INFO("ethosu_mutex_lock called."); // [Called]
     UNUSED(mutex);
     return 0;
 }
 
 int __attribute__((weak)) ethosu_mutex_unlock(void *mutex)
 {
     LOG_INFO("ethosu_mutex_unlock called."); // [Called]
     UNUSED(mutex);
     return 0;
 }
 
 // Baremetal implementation of creating a semaphore
 void *__attribute__((weak)) ethosu_semaphore_create(void)
 {
     LOG_INFO("ethosu_semaphore_create called.");
     struct ethosu_semaphore_t *sem = malloc(sizeof(*sem));
     sem->count = 0;
     return sem;
 }
 
 void __attribute__((weak)) ethosu_semaphore_destroy(void *sem)
 {
     LOG_INFO("ethosu_semaphore_destroy called.");
     free((struct ethosu_semaphore_t *)sem);
 }
 
 // Baremetal simulation of waiting/sleeping for and then taking a semaphore using intrinsics
 int __attribute__((weak)) ethosu_semaphore_take(void *sem)
 {
     LOG_INFO("ethosu_semaphore_take called."); // [Called]
     struct ethosu_semaphore_t *s = sem;
     while (s->count == 0)
     {
         __WFE();
     }
     s->count = 0;
     return 0;
 }
 
 // Baremetal simulation of giving a semaphore and waking up processes using intrinsics
 int __attribute__((weak)) ethosu_semaphore_give(void *sem)
 {
     LOG_INFO("ethosu_semaphore_give called."); // [Called]
     struct ethosu_semaphore_t *s = sem;
     s->count = 1;
     __SEV();
     return 0;
 }
 
 /******************************************************************************
  * Weak functions - Inference begin/end callbacks
  ******************************************************************************/
 void __attribute__((weak)) ethosu_inference_begin(struct ethosu_driver *drv, void *user_arg)
 {
     LOG_INFO("ethosu_inference_begin called.");
     UNUSED(user_arg);
     UNUSED(drv);
 }
 
 void __attribute__((weak)) ethosu_inference_end(struct ethosu_driver *drv, void *user_arg)
 {
     LOG_INFO("ethosu_inference_end called."); // [Called]
     UNUSED(user_arg);
     UNUSED(drv);
 }
 
 /******************************************************************************
  * Static functions
  ******************************************************************************/
 static void ethosu_register_driver(struct ethosu_driver *drv)
 {
     LOG_INFO("ethosu_register_driver called.");
     // Register driver as new HEAD of list
     drv->next = registered_drivers;
     registered_drivers = drv;
 
     LOG_INFO("New NPU driver registered (handle: 0x%p, NPU: 0x%p)", drv, drv->dev->reg);
 }
 
 static int ethosu_deregister_driver(struct ethosu_driver *drv)
 {
     LOG_INFO("ethosu_deregister_driver called.");
     struct ethosu_driver *cur   = registered_drivers;
     struct ethosu_driver **prev = &registered_drivers;
 
     while (cur != NULL)
     {
         if (cur == drv)
         {
             *prev = cur->next;
             LOG_INFO("NPU driver handle %p deregistered.", drv);
             return 0;
         }
 
         prev = &cur->next;
         cur  = cur->next;
     }
 
     LOG_ERR("No NPU driver handle registered at address %p.", drv);
     return -1;
 }
 
 static struct ethosu_driver *ethosu_find_and_reserve_driver(void)
 {
     LOG_INFO("ethosu_find_and_reserve_driver called.");
     struct ethosu_driver *drv = registered_drivers;
 
     while (drv != NULL)
     {
         if (!drv->reserved)
         {
             drv->reserved = true;
             LOG_INFO("NPU driver handle %p reserved.", drv);
             return drv;
         }
         drv = drv->next;
     }
 
     LOG_WARN("No NPU driver handle available.");
     return NULL;
 }
 
 static void ethosu_reset_job(struct ethosu_driver *drv)
 {
     LOG_INFO("ethosu_reset_job called."); // [Called]
     memset(&drv->job, 0, sizeof(struct ethosu_job));
 }
 
 static int handle_optimizer_config(struct ethosu_driver *drv, struct opt_cfg_s *opt_cfg_p)
 {
     LOG_INFO("handle_optimizer_config called.");
     LOG_INFO("Optimizer release nbr: %d patch: %d", opt_cfg_p->da_data.rel_nbr, opt_cfg_p->da_data.patch_nbr);
 
     if (ethosu_dev_verify_optimizer_config(drv->dev, opt_cfg_p->cfg, opt_cfg_p->id) != true)
     {
         return -1;
     }
     return 0;
 }
 
 static int handle_command_stream(struct ethosu_driver *drv, const uint8_t *cmd_stream, const int cms_length)
 {
     LOG_INFO("handle_command_stream called.");
     uint32_t cms_bytes = cms_length * BYTES_IN_32_BITS;
     ptrdiff_t cmd_stream_ptr = (ptrdiff_t)cmd_stream;
 
     LOG_INFO("handle_command_stream: cmd_stream=%p, cms_length %d", cmd_stream, cms_length);
 
     if (0 != ((ptrdiff_t)cmd_stream & MASK_16_BYTE_ALIGN))
     {
         LOG_ERR("Command stream addr %p not aligned to 16 bytes", cmd_stream);
         return -1;
     }
 
     // Verify 16 byte alignment for base address
     for (int i = 0; i < drv->job.num_base_addr; i++)
     {
         if (0 != (drv->job.base_addr[i] & MASK_16_BYTE_ALIGN))
         {
             LOG_ERR("Base addr %d: 0x%llx not aligned to 16 bytes", i, drv->job.base_addr[i]);
             return -1;
         }
     }
 
     if (drv->job.base_addr_size != NULL)
     {
         ethosu_flush_dcache((uint32_t *)cmd_stream_ptr, cms_bytes);
         for (int i = 0; i < drv->job.num_base_addr; i++)
         {
             ethosu_flush_dcache((uint32_t *)(uintptr_t)drv->job.base_addr[i], drv->job.base_addr_size[i]);
         }
     }
     else
     {
         ethosu_flush_dcache(NULL, 0);
     }
 
     if (!ethosu_request_power(drv))
     {
         LOG_ERR("Failed to request power");
         return -1;
     }
 
     drv->job.state = ETHOSU_JOB_RUNNING;
 
     ethosu_inference_begin(drv, drv->job.user_arg);
 
     ethosu_dev_run_command_stream(drv->dev, cmd_stream, cms_bytes, drv->job.base_addr, drv->job.num_base_addr);
     return 0;
 }
 
 /******************************************************************************
  * Weak functions - Interrupt handler
  ******************************************************************************/
 void __attribute__((weak)) ethosu_irq_handler(struct ethosu_driver *drv)
 {
     LOG_INFO("ethosu_irq_handler called."); // [Called]
     LOG_INFO("Got interrupt from Ethos-U");
     LOG_INFO("Test Case 8: Got interrupt from Ethos-U");
 
     drv = registered_drivers;
     drv->job.state = ETHOSU_JOB_DONE;
     if (!ethosu_dev_handle_interrupt(drv->dev))
     {
         drv->status_error = true;
     }
     ethosu_semaphore_give(drv->semaphore);
 }
 
 /******************************************************************************
  * Functions API
  ******************************************************************************/
 
 int ethosu_init(struct ethosu_driver *drv,
                 const void *base_address,
                 const void *fast_memory,
                 const size_t fast_memory_size,
                 uint32_t secure_enable,
                 uint32_t privilege_enable)
 {
     LOG_INFO("ethosu_init called.");
     LOG_INFO("Initializing NPU: base_address=%p, fast_memory=%p, fast_memory_size=%zu, secure=%" PRIu32 ", privileged=%" PRIu32,
              base_address, fast_memory, fast_memory_size, secure_enable, privilege_enable);
 
     if (!ethosu_mutex)
     {
         ethosu_mutex = ethosu_mutex_create();
     }
     if (!ethosu_semaphore)
     {
         ethosu_semaphore = ethosu_semaphore_create();
     }
 
     drv->fast_memory = (uint32_t)fast_memory;
     drv->fast_memory_size = fast_memory_size;
     drv->power_request_counter = 0;
 
     drv->dev = ethosu_dev_init(base_address, secure_enable, privilege_enable);
     if (drv->dev == NULL)
     {
         LOG_ERR("Failed to initialize Ethos-U device");
         return -1;
     }
 
     drv->semaphore = ethosu_semaphore_create();
     drv->status_error = false;
 
     ethosu_reset_job(drv);
     ethosu_register_driver(drv);
 
     return 0;
 }
 
 void ethosu_deinit(struct ethosu_driver *drv)
 {
     LOG_INFO("ethosu_deinit called.");
     ethosu_deregister_driver(drv);
     ethosu_semaphore_destroy(drv->semaphore);
     ethosu_dev_deinit(drv->dev);
     drv->dev = NULL;
 }
 
 bool ethosu_soft_reset(struct ethosu_driver *drv)
 {
     LOG_INFO("ethosu_soft_reset called.");
     if (ethosu_dev_soft_reset(drv->dev) != ETHOSU_SUCCESS)
     {
         LOG_ERR("Failed to soft-reset NPU");
         return false;
     }
 
     ethosu_dev_set_clock_and_power(drv->dev,
                                    drv->power_request_counter > 0 ? ETHOSU_CLOCK_Q_DISABLE : ETHOSU_CLOCK_Q_ENABLE,
                                    drv->power_request_counter > 0 ? ETHOSU_POWER_Q_DISABLE : ETHOSU_POWER_Q_ENABLE);
     return true;
 }
 
 bool ethosu_request_power(struct ethosu_driver *drv)
 {
     LOG_INFO("ethosu_request_power called.");
     if (drv->power_request_counter++ == 0)
     {
         if (ethosu_soft_reset(drv) == false)
         {
             LOG_ERR("Failed to request power for Ethos-U");
             drv->power_request_counter--;
             return false;
         }
     }
     return true;
 }
 
 void ethosu_release_power(struct ethosu_driver *drv)
 {
     LOG_INFO("ethosu_release_power called."); // [Called]
     if (drv->power_request_counter == 0)
     {
         LOG_WARN("No power request left to release, reference counter is 0");
     }
     else
     {
         if (--drv->power_request_counter == 0)
         {
             ethosu_dev_set_clock_and_power(drv->dev, ETHOSU_CLOCK_Q_ENABLE, ETHOSU_POWER_Q_ENABLE);
         }
     }
 }
 
 void ethosu_get_driver_version(struct ethosu_driver_version *ver)
 {
     LOG_INFO("ethosu_get_driver_version called.");
     assert(ver != NULL);
     ver->major = ETHOSU_DRIVER_VERSION_MAJOR;
     ver->minor = ETHOSU_DRIVER_VERSION_MINOR;
     ver->patch = ETHOSU_DRIVER_VERSION_PATCH;
 }
 
 void ethosu_get_hw_info(struct ethosu_driver *drv, struct ethosu_hw_info *hw)
 {
     LOG_INFO("ethosu_get_hw_info called.");
     assert(hw != NULL);
     drv = registered_drivers;
     ethosu_dev_get_hw_info(drv->dev, hw);
 }
 
 int ethosu_wait(struct ethosu_driver *drv, bool block)
 {
     LOG_INFO("ethosu_wait called."); // [Called]
     int ret = 0;
 
     switch (drv->job.state)
     {
         case ETHOSU_JOB_IDLE:
             LOG_ERR("Inference job not running...");
             ret = -2;
             break;
         case ETHOSU_JOB_RUNNING:
             if (!block)
             {
                 ret = 1;
                 break;
             }
             // fall through
         case ETHOSU_JOB_DONE:
             ethosu_semaphore_take(drv->semaphore);
             ethosu_inference_end(drv, drv->job.user_arg);
             ethosu_release_power(drv);
             if (drv->status_error)
             {
                 LOG_ERR("NPU error(s) occured during inference.");
                 ethosu_dev_print_err_status(drv->dev);
                 (void)ethosu_soft_reset(drv);
                 drv->status_error = false;
                 ret = -1;
             }
             if (ret == 0)
             {
                 if (drv->job.base_addr_size != NULL)
                 {
                     for (int i = 0; i < drv->job.num_base_addr; i++)
                     {
                         ethosu_invalidate_dcache((uint32_t *)(uintptr_t)drv->job.base_addr[i], drv->job.base_addr_size[i]);
                     }
                 }
                 else
                 {
                     ethosu_invalidate_dcache(NULL, 0);
                 }
                 LOG_INFO("Test Case 18: read at end of command stream");
                 LOG_INFO("Inference finished successfully...");
             }
             ethosu_reset_job(drv);
             break;
         default:
             LOG_ERR("Unexpected job state");
             ethosu_reset_job(drv);
             ret = -1;
             break;
     }
     return ret;
 }
 
 int ethosu_invoke_async(struct ethosu_driver *drv,
                         const void *custom_data_ptr,
                         const int custom_data_size,
                         const uint64_t *base_addr,
                         const size_t *base_addr_size,
                         const int num_base_addr,
                         void *user_arg)
 {
     LOG_INFO("ethosu_invoke_async called.");
     const struct cop_data_s *data_ptr = custom_data_ptr;
     const struct cop_data_s *data_end = (const struct cop_data_s *)((ptrdiff_t)custom_data_ptr + custom_data_size);
 
     LOG_INFO("custom_data_ptr: 0x%x, custom_data_size %d", custom_data_ptr, custom_data_size);
     for (int i = 0; i < num_base_addr; i++) {
         LOG_INFO("base_addr[%d]: %x", i, (uint32_t)base_addr[i]);
     }
 
     if (drv->job.state != ETHOSU_JOB_IDLE)
     {
         LOG_ERR("Inference already running, or waiting to be cleared...");
         return -1;
     }
 
     drv->job.state            = ETHOSU_JOB_IDLE;
     drv->job.custom_data_ptr  = custom_data_ptr;
     drv->job.custom_data_size = custom_data_size;
     drv->job.base_addr        = base_addr;
     drv->job.base_addr_size   = base_addr_size;
     drv->job.num_base_addr    = num_base_addr;
     drv->job.user_arg         = user_arg;
 
     if (data_ptr->word != ETHOSU_FOURCC)
     {
         LOG_ERR("Custom Operator Payload: %" PRIu32 " is not correct, expected %x", data_ptr->word, ETHOSU_FOURCC);
         goto err;
     }
 
     if ((custom_data_size % BYTES_IN_32_BITS) != 0)
     {
         LOG_ERR("custom_data_size=0x%x not a multiple of 4", custom_data_size);
         goto err;
     }
 
     data_ptr++;
 
     if (drv->fast_memory != 0 && num_base_addr >= FAST_MEMORY_BASE_ADDR_INDEX)
     {
         uint64_t *fast_memory = (uint64_t *)&base_addr[FAST_MEMORY_BASE_ADDR_INDEX];
         if (base_addr_size != NULL && base_addr_size[FAST_MEMORY_BASE_ADDR_INDEX] > drv->fast_memory_size)
         {
             LOG_ERR("Fast memory area too small. fast_memory_size=%u, base_addr_size=%u",
                     drv->fast_memory_size, base_addr_size[FAST_MEMORY_BASE_ADDR_INDEX]);
             goto err;
         }
         *fast_memory = drv->fast_memory;
     }
 
     for (int i = 0; i < num_base_addr; i++) {
         LOG_INFO("Updated base_addr[%d]: %x", i, (uint32_t)base_addr[i]);
     }
 
     drv->status_error = false;
 
     while (data_ptr < data_end)
     {
         switch (data_ptr->driver_action_command)
         {
             case OPTIMIZER_CONFIG:
             {
                 LOG_INFO("OPTIMIZER_CONFIG");
                 struct opt_cfg_s *opt_cfg_p = (struct opt_cfg_s *)data_ptr;
                 if (handle_optimizer_config(drv, opt_cfg_p) < 0)
                 {
                     goto err;
                 }
                 data_ptr += DRIVER_ACTION_LENGTH_32_BIT_WORD + OPTIMIZER_CONFIG_LENGTH_32_BIT_WORD;
                 break;
             }
             case COMMAND_STREAM:
             {
                 LOG_INFO("COMMAND_STREAM");
                 void *command_stream = (uint8_t *)(data_ptr) + sizeof(struct cop_data_s);
                 int cms_length = (data_ptr->reserved << 16) | data_ptr->length;
                 if (handle_command_stream(drv, command_stream, cms_length) < 0)
                 {
                     goto err;
                 }
                 data_ptr += DRIVER_ACTION_LENGTH_32_BIT_WORD + cms_length;
                 break;
             }
             case NOP:
             {
                 LOG_INFO("NOP");
                 data_ptr += DRIVER_ACTION_LENGTH_32_BIT_WORD;
                 break;
             }
             default:
             {
                 LOG_ERR("UNSUPPORTED driver_action_command: %d", data_ptr->driver_action_command);
                 goto err;
             }
         }
     }
     return 0;
 err:
     LOG_ERR("Failed to invoke inference.");
     ethosu_reset_job(drv);
     return -1;
 }
 
 int ethosu_invoke_v3(struct ethosu_driver *drv,
                      const void *custom_data_ptr,
                      const int custom_data_size,
                      const uint64_t *base_addr,
                      const size_t *base_addr_size,
                      const int num_base_addr,
                      void *user_arg)
 {
     LOG_INFO("ethosu_invoke_v3 called.");
     if (ethosu_invoke_async(drv, custom_data_ptr, custom_data_size, base_addr, base_addr_size, num_base_addr, user_arg) < 0)
     {
         return -1;
     }
     return ethosu_wait(drv, true);
 }
 
 struct ethosu_driver *ethosu_reserve_driver(void)
 {
     LOG_INFO("ethosu_reserve_driver called.");
     struct ethosu_driver *drv = NULL;
     do
     {
         ethosu_mutex_lock(ethosu_mutex);
         drv = ethosu_find_and_reserve_driver();
         ethosu_mutex_unlock(ethosu_mutex);
 
         if (drv != NULL)
         {
             break;
         }
         LOG_INFO("Waiting for NPU driver handle to become available...");
         ethosu_semaphore_take(ethosu_semaphore);
     } while (1);
     return drv;
 }
 
 void ethosu_release_driver(struct ethosu_driver *drv)
 {
     LOG_INFO("ethosu_release_driver called."); // [Called]
     ethosu_mutex_lock(ethosu_mutex);
     if (drv != NULL && drv->reserved)
     {
         if (drv->job.state == ETHOSU_JOB_RUNNING || drv->job.state == ETHOSU_JOB_DONE)
         {
             if (ethosu_wait(drv, false) == 1)
             {
                 drv->power_request_counter = 0;
                 ethosu_soft_reset(drv);
                 ethosu_reset_job(drv);
                 drv->status_error = false;
                 ethosu_semaphore_give(drv->semaphore);
             }
         }
         drv->reserved = false;
         LOG_INFO("NPU driver handle %p released", drv);
         ethosu_semaphore_give(ethosu_semaphore);
     }
     ethosu_mutex_unlock(ethosu_mutex);
 }
 
 void ethosu_suspend(void)
 {
     LOG_INFO("ethosu_suspend called.");
     const clock_root_config_t mlClkCfg = {
         .clockOff = false,
         .mux = 0, // 24Mhz source
         .div = 1
     };
 
     const clock_root_config_t mlapbClkCfg = {
         .clockOff = false,
         .mux = 0, // 24Mhz source
         .div = 1
     };
 
     CLOCK_SetRootClock(kCLOCK_Root_Ml, &mlClkCfg);
     CLOCK_SetRootClock(kCLOCK_Root_MlApb, &mlapbClkCfg);
 }
 
 void ethosu_resume(void)
 {
     LOG_INFO("ethosu_resume called.");
     const clock_root_config_t mlClkCfg = {
         .clockOff = false,
         .mux = 1, // 1000Mhz source
         .div = 1
     };
 
     const clock_root_config_t mlapbClkCfg = {
         .clockOff = false,
         .mux = 1, // 500Mhz source
         .div = 1
     };
 
     CLOCK_SetRootClock(kCLOCK_Root_Ml, &mlClkCfg);
     CLOCK_SetRootClock(kCLOCK_Root_MlApb, &mlapbClkCfg);
 }
 