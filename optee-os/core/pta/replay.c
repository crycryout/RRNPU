/*
 * replay_pta.c
 * PTA wrapper for Ethos‑U register-access replay
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <kernel/pseudo_ta.h>
#include <trace.h>
#include <tee_api_types.h>
#include <drivers/replay.h>  /* replay_driver_init + replay_* 三大接口 */

#define REPLAY_UUID \
    { 0xbdf42668, 0x3cf8, 0x45a3, \
      { 0x81, 0x6e, 0x76, 0x86, 0x1c, 0xb0, 0x27, 0x47 } }
#define REPLAY_CMD_RUN 0

static TEE_Result run_replay(uint32_t ptypes, TEE_Param params[TEE_NUM_PARAMS])
{
    struct replay_data rd;

    if (ptypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    /* 1) 初始化驱动：映射 NPU 和 OCRAM */
    if (replay_driver_init(&rd) < 0) {
        EMSG("replay: replay_driver_init() failed");
        return TEE_ERROR_GENERIC;
    }

    /* 2) 三大阶段依次执行 */
    replay_initialization_verification(&rd);
    replay_inference(&rd);
    replay_handle_interrupt(&rd);

    return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *psess __unused,
                                 uint32_t cmd,
                                 uint32_t ptypes,
                                 TEE_Param params[TEE_NUM_PARAMS])
{
    if (cmd == REPLAY_CMD_RUN)
        return run_replay(ptypes, params);
    return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(
    .uuid = REPLAY_UUID,
    .name = "replay.pta",
    .flags = PTA_DEFAULT_FLAGS,
    .invoke_command_entry_point = invoke_command
);
