/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_debug_console.h"
#include "fsl_flexcan.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"

#include "fsl_common.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define EXAMPLE_CAN           CAN2
#define RX_MESSAGE_BUFFER_NUM (9)
#define TX_MESSAGE_BUFFER_NUM (8)

#define FLEXCAN_CLOCK_ROOT         (kCLOCK_Root_Can2)
#define FLEXCAN_CLOCK_GATE         kCLOCK_Can2
#define EXAMPLE_CAN_CLK_FREQ       CLOCK_GetIpFreq(FLEXCAN_CLOCK_ROOT)
#define USE_IMPROVED_TIMING_CONFIG (1U)
/* Fix MISRA_C-2012 Rule 17.7. */
#define LOG_INFO (void)PRINTF
#if (defined(USE_CANFD) && USE_CANFD)
/*
 *    DWORD_IN_MB    DLC    BYTES_IN_MB             Maximum MBs
 *    2              8      kFLEXCAN_8BperMB        64
 *    4              10     kFLEXCAN_16BperMB       42
 *    8              13     kFLEXCAN_32BperMB       25
 *    16             15     kFLEXCAN_64BperMB       14
 *
 * Dword in each message buffer, Length of data in bytes, Payload size must align,
 * and the Message Buffers are limited corresponding to each payload configuration:
 */
#define DLC         (15)
#define BYTES_IN_MB kFLEXCAN_64BperMB
#else
#define DLC (8)
#endif
/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
flexcan_handle_t flexcanHandle;
volatile bool txComplete = false;
volatile bool rxComplete = false;
volatile bool wakenUp    = false;
flexcan_mb_transfer_t txXfer, rxXfer;
#if (defined(USE_CANFD) && USE_CANFD)
flexcan_fd_frame_t frame;
#else
flexcan_frame_t frame;
#endif
uint32_t txIdentifier;
uint32_t rxIdentifier;

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief CAN transceiver configuration function
 */
static void FLEXCAN_PHY_Config(void)
{
#if (defined(USE_PHY_TJA1152) && USE_PHY_TJA1152)
    /* Initialize TJA1152. */
    /* STB=H, configuration CAN messages are expected from the local host via TXD pin. */
    RGPIO_PortSet(EXAMPLE_STB_RGPIO, 1u << EXAMPLE_STB_RGPIO_PIN);   

    /* Classical CAN messages with standard identifier 0x555 must be transmitted 
     * by the local host controller until acknowledged by the TJA1152 for
     * automatic bit rate detection. Do not set frame.brs = 1U to keep nominal
     * bit rate in CANFD frame data phase. */
    frame.id     = FLEXCAN_ID_STD(0x555);
    frame.format = (uint8_t)kFLEXCAN_FrameFormatStandard;
    frame.type   = (uint8_t)kFLEXCAN_FrameTypeData;
    frame.length = 0U;
    txXfer.mbIdx = (uint8_t)TX_MESSAGE_BUFFER_NUM;
#if (defined(USE_CANFD) && USE_CANFD)
    txXfer.framefd = &frame;
    (void)FLEXCAN_TransferFDSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#else
    txXfer.frame = &frame;
    (void)FLEXCAN_TransferSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#endif
    while (!txComplete)
    {
    };
    txComplete = false;

    /* Configuration of spoofing protection. */
    /* Add 0x321 and 0x123 to Transmission Whitelist. */
    frame.id     = FLEXCAN_ID_EXT(0x18DA00F1);
    frame.format = (uint8_t)kFLEXCAN_FrameFormatExtend;
    frame.type   = (uint8_t)kFLEXCAN_FrameTypeData;
    frame.length = 6U;
#if (defined(USE_CANFD) && USE_CANFD)
    frame.dataWord[0] = CAN_WORD_DATA_BYTE_0(0x10) | CAN_WORD_DATA_BYTE_1(0x00) | CAN_WORD_DATA_BYTE_2(0x33) |
                        CAN_WORD_DATA_BYTE_3(0x21);
    frame.dataWord[1] = CAN_WORD_DATA_BYTE_4(0x11) | CAN_WORD_DATA_BYTE_5(0x23);
    (void)FLEXCAN_TransferFDSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer); 
#else
    frame.dataWord0 = CAN_WORD0_DATA_BYTE_0(0x10) | CAN_WORD0_DATA_BYTE_1(0x00) | CAN_WORD0_DATA_BYTE_2(0x33) |
                      CAN_WORD0_DATA_BYTE_3(0x21);
    frame.dataWord1 = CAN_WORD1_DATA_BYTE_4(0x11) | CAN_WORD1_DATA_BYTE_5(0x23);
    (void)FLEXCAN_TransferSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#endif
    while (!txComplete)
    {
    };
    txComplete = false;

    /* Configuration of command message ID. */
    /* Reconfiguration is only accepted locally. Keep CONFIG_ID as default value 0x18DA00F1. */
    frame.length = 5U;
#if (defined(USE_CANFD) && USE_CANFD)
    frame.dataWord[0] = CAN_WORD_DATA_BYTE_0(0x60) | CAN_WORD_DATA_BYTE_1(0x98) | CAN_WORD_DATA_BYTE_2(0xDA) |
                        CAN_WORD_DATA_BYTE_3(0x00);
    frame.dataWord[1] = CAN_WORD_DATA_BYTE_4(0xF1);
    (void)FLEXCAN_TransferFDSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#else
    frame.dataWord0 = CAN_WORD0_DATA_BYTE_0(0x60) | CAN_WORD0_DATA_BYTE_1(0x98) | CAN_WORD0_DATA_BYTE_2(0xDA) |
                      CAN_WORD0_DATA_BYTE_3(0x00);
    frame.dataWord1 = CAN_WORD1_DATA_BYTE_4(0xF1); 
    (void)FLEXCAN_TransferSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#endif
    while (!txComplete)
    {
    };
    txComplete = false;

    /* Leaving configuration mode. */
    /* Configuration into volatile memory only. */
    frame.length = 8U;

#if (defined(USE_CANFD) && USE_CANFD)
    frame.dataWord[0] = CAN_WORD_DATA_BYTE_0(0x71) | CAN_WORD_DATA_BYTE_1(0x02) | CAN_WORD_DATA_BYTE_2(0x03) |
                        CAN_WORD_DATA_BYTE_3(0x04);
    frame.dataWord[1] = CAN_WORD_DATA_BYTE_4(0x05) | CAN_WORD_DATA_BYTE_5(0x06) | CAN_WORD_DATA_BYTE_6(0x07) |
                        CAN_WORD_DATA_BYTE_7(0x08);
    (void)FLEXCAN_TransferFDSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#else
    frame.dataWord0 = CAN_WORD0_DATA_BYTE_0(0x71) | CAN_WORD0_DATA_BYTE_1(0x02) | CAN_WORD0_DATA_BYTE_2(0x03) |
                      CAN_WORD0_DATA_BYTE_3(0x04);
    frame.dataWord1 = CAN_WORD1_DATA_BYTE_4(0x05) | CAN_WORD1_DATA_BYTE_5(0x06) | CAN_WORD1_DATA_BYTE_6(0x07) |
                      CAN_WORD1_DATA_BYTE_7(0x08);
    (void)FLEXCAN_TransferSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#endif
    while (!txComplete)
    {
    };
    txComplete = false;

    LOG_INFO("Initialize TJA1152 successfully!\r\n\r\n");

    /* STB=L, TJA1152 switch from secure standby mode to normal mode. */
    RGPIO_PortClear(EXAMPLE_STB_RGPIO, 1u << EXAMPLE_STB_RGPIO_PIN);
    /* Initialize TJA1152 end. */
#endif
}

/*!
 * @brief FlexCAN Call Back function
 */
static FLEXCAN_CALLBACK(flexcan_callback)
{
    switch (status)
    {
        case kStatus_FLEXCAN_RxIdle:
            if (RX_MESSAGE_BUFFER_NUM == result)
            {
                rxComplete = true;
            }
            break;

        case kStatus_FLEXCAN_TxIdle:
            if (TX_MESSAGE_BUFFER_NUM == result)
            {
                txComplete = true;
            }
            break;

        case kStatus_FLEXCAN_WakeUp:
            wakenUp = true;
            break;

        default:
            break;
    }
}

/*!
 * @brief Main function
 */
int main(void)
{
    flexcan_config_t flexcanConfig;
    flexcan_rx_mb_config_t mbConfig;
    uint8_t node_type;

    /* Initialize board hardware. */
    /* clang-format off */

    const clock_root_config_t flexcanClkCfg = {
        .clockOff = false,
	.mux = 2,
	.div = 10
    };
    const clock_root_config_t lpi2cClkCfg = {
        .clockOff = false,
        .mux = 0, // 24MHz oscillator source
        .div = 1
    };
    /* clang-format on */
    BOARD_InitBootPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    CLOCK_SetRootClock(FLEXCAN_CLOCK_ROOT, &flexcanClkCfg);
    CLOCK_EnableClock(FLEXCAN_CLOCK_GATE);
    CLOCK_SetRootClock(BOARD_ADP5585_I2C_CLOCK_ROOT, &lpi2cClkCfg);
    CLOCK_EnableClock(BOARD_ADP5585_I2C_CLOCK_GATE);

    /* Select CAN2 signals */
    adp5585_handle_t handle1;
    BOARD_InitADP5585(&handle1);
    ADP5585_SetDirection(&handle1, (1 << BOARD_ADP5585_EXP_SEL), kADP5585_Output);
    ADP5585_ClearPins(&handle1, (1 << BOARD_ADP5585_EXP_SEL));

    /* Select CAN_STBY signals */
    adp5585_handle_t handle;
    BOARD_InitADP5585(&handle);
    ADP5585_SetDirection(&handle, (1 << BOARD_ADP5585_CAN_STBY), kADP5585_Output);
    ADP5585_ClearPins(&handle, (1 << BOARD_ADP5585_CAN_STBY));

    LOG_INFO("********* FLEXCAN Interrupt EXAMPLE *********\r\n");
    LOG_INFO("    Message format: Standard (11 bit id)\r\n");
    LOG_INFO("    Message buffer %d used for Rx.\r\n", RX_MESSAGE_BUFFER_NUM);
    LOG_INFO("    Message buffer %d used for Tx.\r\n", TX_MESSAGE_BUFFER_NUM);
    LOG_INFO("    Interrupt Mode: Enabled\r\n");
    LOG_INFO("    Operation Mode: TX and RX --> Normal\r\n");
    LOG_INFO("*********************************************\r\n\r\n");

    do
    {
        LOG_INFO("Please select local node as A or B:\r\n");
        LOG_INFO("Note: Node B should start first.\r\n");
        LOG_INFO("Node:");
        node_type = GETCHAR();
        LOG_INFO("%c", node_type);
        LOG_INFO("\r\n");
    } while ((node_type != 'A') && (node_type != 'B') && (node_type != 'a') && (node_type != 'b'));

    /* Select mailbox ID. */
    if ((node_type == 'A') || (node_type == 'a'))
    {
        txIdentifier = 0x321;
        rxIdentifier = 0x123;
    }
    else
    {
        txIdentifier = 0x123;
        rxIdentifier = 0x321;
    }

    /* Get FlexCAN module default Configuration. */
    /*
     * flexcanConfig.clkSrc                 = kFLEXCAN_ClkSrc0;
     * flexcanConfig.bitRate               = 1000000U;
     * flexcanConfig.bitRateFD             = 2000000U;
     * flexcanConfig.maxMbNum               = 16;
     * flexcanConfig.enableLoopBack         = false;
     * flexcanConfig.enableSelfWakeup       = false;
     * flexcanConfig.enableIndividMask      = false;
     * flexcanConfig.disableSelfReception   = false;
     * flexcanConfig.enableListenOnlyMode   = false;
     * flexcanConfig.enableDoze             = false;
     */
    FLEXCAN_GetDefaultConfig(&flexcanConfig);

    flexcanConfig.bitRate = 500000U;

#if defined(EXAMPLE_CAN_CLK_SOURCE)
    flexcanConfig.clkSrc = EXAMPLE_CAN_CLK_SOURCE;
#endif

#if defined(EXAMPLE_CAN_BIT_RATE)
    flexcanConfig.bitRate = EXAMPLE_CAN_BIT_RATE;
#endif

/* If special quantum setting is needed, set the timing parameters. */
#if (defined(SET_CAN_QUANTUM) && SET_CAN_QUANTUM)
    flexcanConfig.timingConfig.phaseSeg1 = PSEG1;
    flexcanConfig.timingConfig.phaseSeg2 = PSEG2;
    flexcanConfig.timingConfig.propSeg   = PROPSEG;
#if (defined(FSL_FEATURE_FLEXCAN_HAS_FLEXIBLE_DATA_RATE) && FSL_FEATURE_FLEXCAN_HAS_FLEXIBLE_DATA_RATE)
    flexcanConfig.timingConfig.fphaseSeg1 = FPSEG1;
    flexcanConfig.timingConfig.fphaseSeg2 = FPSEG2;
    flexcanConfig.timingConfig.fpropSeg   = FPROPSEG;
#endif
#endif

#if (defined(USE_IMPROVED_TIMING_CONFIG) && USE_IMPROVED_TIMING_CONFIG)
    flexcan_timing_config_t timing_config;
    memset(&timing_config, 0, sizeof(flexcan_timing_config_t));
#if (defined(USE_CANFD) && USE_CANFD)
    if (FLEXCAN_FDCalculateImprovedTimingValues(EXAMPLE_CAN, flexcanConfig.bitRate, flexcanConfig.bitRateFD,
                                                EXAMPLE_CAN_CLK_FREQ, &timing_config))
    {
        /* Update the improved timing configuration*/
        memcpy(&(flexcanConfig.timingConfig), &timing_config, sizeof(flexcan_timing_config_t));
    }
    else
    {
        LOG_INFO("No found Improved Timing Configuration. Just used default configuration\r\n\r\n");
    }
#else
    if (FLEXCAN_CalculateImprovedTimingValues(EXAMPLE_CAN, flexcanConfig.bitRate, EXAMPLE_CAN_CLK_FREQ, &timing_config))
    {
        /* Update the improved timing configuration*/
        memcpy(&(flexcanConfig.timingConfig), &timing_config, sizeof(flexcan_timing_config_t));
    }
    else
    {
        LOG_INFO("No found Improved Timing Configuration. Just used default configuration\r\n\r\n");
    }
#endif
#endif

#if (defined(USE_CANFD) && USE_CANFD)
    FLEXCAN_FDInit(EXAMPLE_CAN, &flexcanConfig, EXAMPLE_CAN_CLK_FREQ, BYTES_IN_MB, true);
#else
    FLEXCAN_Init(EXAMPLE_CAN, &flexcanConfig, EXAMPLE_CAN_CLK_FREQ);
#endif

    /* Create FlexCAN handle structure and set call back function. */
    FLEXCAN_TransferCreateHandle(EXAMPLE_CAN, &flexcanHandle, flexcan_callback, NULL);

    /* Set Rx Masking mechanism. */
    FLEXCAN_SetRxMbGlobalMask(EXAMPLE_CAN, FLEXCAN_RX_MB_STD_MASK(rxIdentifier, 0, 0));

    /* Setup Rx Message Buffer. */
    mbConfig.format = kFLEXCAN_FrameFormatStandard;
    mbConfig.type   = kFLEXCAN_FrameTypeData;
    mbConfig.id     = FLEXCAN_ID_STD(rxIdentifier);
#if (defined(USE_CANFD) && USE_CANFD)
    FLEXCAN_SetFDRxMbConfig(EXAMPLE_CAN, RX_MESSAGE_BUFFER_NUM, &mbConfig, true);
#else
    FLEXCAN_SetRxMbConfig(EXAMPLE_CAN, RX_MESSAGE_BUFFER_NUM, &mbConfig, true);
#endif

/* Setup Tx Message Buffer. */
#if (defined(USE_CANFD) && USE_CANFD)
    FLEXCAN_SetFDTxMbConfig(EXAMPLE_CAN, TX_MESSAGE_BUFFER_NUM, true);
#else
    FLEXCAN_SetTxMbConfig(EXAMPLE_CAN, TX_MESSAGE_BUFFER_NUM, true);
#endif

    /* Configure CAN transceiver */
    FLEXCAN_PHY_Config();

    if ((node_type == 'A') || (node_type == 'a'))
    {
        LOG_INFO("Press any key to trigger one-shot transmission\r\n\r\n");
        frame.dataByte0 = 0;
    }
    else
    {
        LOG_INFO("Start to Wait data from Node A\r\n\r\n");
    }

    while (true)
    {
        if ((node_type == 'A') || (node_type == 'a'))
        {
            GETCHAR();

            frame.id     = FLEXCAN_ID_STD(txIdentifier);
            frame.format = (uint8_t)kFLEXCAN_FrameFormatStandard;
            frame.type   = (uint8_t)kFLEXCAN_FrameTypeData;
            frame.length = (uint8_t)DLC;
#if (defined(USE_CANFD) && USE_CANFD)
            frame.brs = 1U;
            frame.edl = 1U;
#endif
            txXfer.mbIdx = (uint8_t)TX_MESSAGE_BUFFER_NUM;
#if (defined(USE_CANFD) && USE_CANFD)
            txXfer.framefd = &frame;
            (void)FLEXCAN_TransferFDSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#else
            txXfer.frame = &frame;
            (void)FLEXCAN_TransferSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#endif

            while (!txComplete)
            {
            };
            txComplete = false;

            /* Start receive data through Rx Message Buffer. */
            rxXfer.mbIdx = (uint8_t)RX_MESSAGE_BUFFER_NUM;
#if (defined(USE_CANFD) && USE_CANFD)
            rxXfer.framefd = &frame;
            (void)FLEXCAN_TransferFDReceiveNonBlocking(EXAMPLE_CAN, &flexcanHandle, &rxXfer);
#else
            rxXfer.frame = &frame;
            (void)FLEXCAN_TransferReceiveNonBlocking(EXAMPLE_CAN, &flexcanHandle, &rxXfer);
#endif

            /* Wait until Rx MB full. */
            while (!rxComplete)
            {
            };
            rxComplete = false;

            LOG_INFO("Rx MB ID: 0x%3x, Rx MB data: 0x%x, Time stamp: %d\r\n", frame.id >> CAN_ID_STD_SHIFT,
                     frame.dataByte0, frame.timestamp);
            LOG_INFO("Press any key to trigger the next transmission!\r\n\r\n");
            frame.dataByte0++;
            frame.dataByte1 = 0x55;
        }
        else
        {
            /* Before this , should first make node B enter STOP mode after FlexCAN
             * initialized with enableSelfWakeup=true and Rx MB configured, then A
             * sends frame N which wakes up node B. A will continue to send frame N
             * since no acknowledgement, then B received the second frame N(In the
             * application it seems that B received the frame that woke it up which
             * is not expected as stated in the reference manual, but actually the
             * output in the terminal B received is the same second frame N). */
            if (wakenUp)
            {
                LOG_INFO("B has been waken up!\r\n\r\n");
            }

            /* Start receive data through Rx Message Buffer. */
            rxXfer.mbIdx = (uint8_t)RX_MESSAGE_BUFFER_NUM;
#if (defined(USE_CANFD) && USE_CANFD)
            rxXfer.framefd = &frame;
            (void)FLEXCAN_TransferFDReceiveNonBlocking(EXAMPLE_CAN, &flexcanHandle, &rxXfer);
#else
            rxXfer.frame = &frame;
            (void)FLEXCAN_TransferReceiveNonBlocking(EXAMPLE_CAN, &flexcanHandle, &rxXfer);
#endif

            /* Wait until Rx receive full. */
            while (!rxComplete)
            {
            };
            rxComplete = false;

            LOG_INFO("Rx MB ID: 0x%3x, Rx MB data: 0x%x, Time stamp: %d\r\n", frame.id >> CAN_ID_STD_SHIFT,
                     frame.dataByte0, frame.timestamp);

            frame.id     = FLEXCAN_ID_STD(txIdentifier);
            txXfer.mbIdx = (uint8_t)TX_MESSAGE_BUFFER_NUM;
#if (defined(USE_CANFD) && USE_CANFD)
            txXfer.framefd = &frame;
            (void)FLEXCAN_TransferFDSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#else
            txXfer.frame = &frame;
            (void)FLEXCAN_TransferSendNonBlocking(EXAMPLE_CAN, &flexcanHandle, &txXfer);
#endif

            while (!txComplete)
            {
            };
            txComplete = false;
            LOG_INFO("Wait Node A to trigger the next transmission!\r\n\r\n");
        }
    }
}
