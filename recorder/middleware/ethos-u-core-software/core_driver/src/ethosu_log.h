/*
 * Copyright (c) 2021 Arm Limited. All rights reserved.
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

#ifndef ETHOSU_LOG_H
#define ETHOSU_LOG_H

/******************************************************************************
 * Includes
 ******************************************************************************/

#include <stdio.h>
#include <string.h>

#include "fsl_debug_console.h"

/******************************************************************************
 * Defines
 ******************************************************************************/

// Log severity levels
#define ETHOSU_LOG_ERR 0
#define ETHOSU_LOG_WARN 1
#define ETHOSU_LOG_INFO 2
#define ETHOSU_LOG_DEBUG 3

#define ETHOSU_LOG_SEVERITY ETHOSU_LOG_DEBUG

// Define default log severity
#ifndef ETHOSU_LOG_SEVERITY
#define ETHOSU_LOG_SEVERITY ETHOSU_LOG_WARN
#endif

// Log formatting

#define LOG(f, ...) PRINTF(f, ##__VA_ARGS__)

#if ETHOSU_LOG_SEVERITY >= ETHOSU_LOG_ERR
#define LOG_ERR(f, ...) PRINTF("E: " f " (%s:%d)\r\n", ##__VA_ARGS__, strrchr("/" __FILE__, '/') + 1, __LINE__)
#else
#define LOG_ERR(f, ...)
#endif

#if ETHOSU_LOG_SEVERITY >= ETHOSU_LOG_WARN
#define LOG_WARN(f, ...) PRINTF("W: " f "\r\n", ##__VA_ARGS__)
#else
#define LOG_WARN(f, ...)
#endif

#if ETHOSU_LOG_SEVERITY >= ETHOSU_LOG_INFO
#define LOG_INFO(f, ...) PRINTF("I: " f "\r\n", ##__VA_ARGS__)
#else
#define LOG_INFO(f, ...)
#endif

#if ETHOSU_LOG_SEVERITY >= ETHOSU_LOG_DEBUG
#define LOG_DEBUG(f, ...) PRINTF("D: %s(): " f "\r\n", __FUNCTION__, ##__VA_ARGS__)
#else
#define LOG_DEBUG(f, ...)
#endif

#endif
