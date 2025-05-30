/*
 * Copyright 2017,2020,2022,2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "fsl_lpspi.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"

#include "fsl_common.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define EXAMPLE_LPSPI_MASTER_BASEADDR         LPSPI3
#define LPSPI_MASTER_CLOCK_ROOT               kCLOCK_Root_Lpspi3
#define LPSPI_MASTER_CLOCK_GATE               kCLOCK_Lpspi3
#define LPSPI_MASTER_CLK_FREQ                 (CLOCK_GetIpFreq(LPSPI_MASTER_CLOCK_ROOT))
#define EXAMPLE_LPSPI_MASTER_PCS_FOR_INIT     kLPSPI_Pcs0
#define EXAMPLE_LPSPI_MASTER_PCS_FOR_TRANSFER kLPSPI_MasterPcs0
#define EXAMPLE_LPSPI_MASTER_IRQN             LPSPI3_IRQn
#define EXAMPLE_LPSPI_MASTER_IRQHandler       LPSPI3_IRQHandler

#define EXAMPLE_LPSPI_DEALY_COUNT 0xfffff
#define TRANSFER_SIZE     64U     /*! Transfer dataSize */
#define TRANSFER_BAUDRATE 200000U /*! Transfer baudrate - 200k */

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/* LPSPI user callback */
void LPSPI_MasterUserCallback(LPSPI_Type *base, lpspi_master_handle_t *handle, status_t status, void *userData);

/*******************************************************************************
 * Variables
 ******************************************************************************/
uint8_t masterRxData[TRANSFER_SIZE] = {0U};
uint8_t masterTxData[TRANSFER_SIZE] = {0U};

volatile uint32_t masterTxCount;
volatile uint32_t masterRxCount;
volatile uint8_t g_masterRxWatermark;
volatile uint8_t g_masterFifoSize;

volatile bool isMasterTransferCompleted = false;

/*******************************************************************************
 * Code
 ******************************************************************************/

void EXAMPLE_LPSPI_MASTER_IRQHandler(void)
{
    /* While reading out the RX FIFO as more data may be coming into the RX FIFO. We'll
     * re-enable the interrupts after reading out the FIFO.
     */
    LPSPI_DisableInterrupts(EXAMPLE_LPSPI_MASTER_BASEADDR, kLPSPI_RxInterruptEnable);
    if (masterRxCount < TRANSFER_SIZE)
    {
        while (LPSPI_GetRxFifoCount(EXAMPLE_LPSPI_MASTER_BASEADDR))
        {
            /* Read out the data. */
            masterRxData[masterRxCount] = LPSPI_ReadData(EXAMPLE_LPSPI_MASTER_BASEADDR);
            masterRxCount++;

            if (masterRxCount == TRANSFER_SIZE)
            {
                break;
            }
        }
    }

    /* Update rxWatermark. There isn't RX interrupt for the last datas if the RX count is not greater than rxWatermark.
     */
    if ((TRANSFER_SIZE - masterRxCount) <= g_masterRxWatermark)
    {
        EXAMPLE_LPSPI_MASTER_BASEADDR->FCR =
            (EXAMPLE_LPSPI_MASTER_BASEADDR->FCR & (~LPSPI_FCR_RXWATER_MASK)) |
            LPSPI_FCR_RXWATER(((TRANSFER_SIZE - masterRxCount) > 1U) ? ((TRANSFER_SIZE - masterRxCount) - 1U) : (0U));
    }

    if (masterTxCount < TRANSFER_SIZE)
    {
        while ((LPSPI_GetTxFifoCount(EXAMPLE_LPSPI_MASTER_BASEADDR) < g_masterFifoSize) &&
               (masterTxCount - masterRxCount < g_masterFifoSize))
        {
            /*Write the word to TX register*/
            LPSPI_WriteData(EXAMPLE_LPSPI_MASTER_BASEADDR, masterTxData[masterTxCount]);
            ++masterTxCount;

            if (masterTxCount == TRANSFER_SIZE)
            {
                /* Operation on the TCR register also occupies the tx FIFO,
                   make sure there is still room */
                while ((uint32_t)g_masterFifoSize == LPSPI_GetTxFifoCount(EXAMPLE_LPSPI_MASTER_BASEADDR))
                {
                }
                /* Set the PCS back to uncontinuous to finish the transfer. */
                LPSPI_SetPCSContinous(EXAMPLE_LPSPI_MASTER_BASEADDR, false);
                break;
            }
        }
    }

    /* Check if we're done with this transfer. */
    if ((masterTxCount == TRANSFER_SIZE) && (masterRxCount == TRANSFER_SIZE))
    {
        /* Complete the transfer. */
        isMasterTransferCompleted = true;
    }

    if (masterRxCount < TRANSFER_SIZE)
    {
        LPSPI_EnableInterrupts(EXAMPLE_LPSPI_MASTER_BASEADDR, kLPSPI_RxInterruptEnable);
    }
    SDK_ISR_EXIT_BARRIER;
}

/*!
 * @brief Main function
 */
int main(void)
{
    /* clang-format off */

    const clock_root_config_t lpspiClkCfg = {
        .clockOff = false,
	.mux = 0,
	.div = 1
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

    CLOCK_SetRootClock(LPSPI_MASTER_CLOCK_ROOT, &lpspiClkCfg);
    CLOCK_SetRootClock(BOARD_ADP5585_I2C_CLOCK_ROOT, &lpi2cClkCfg);
    CLOCK_EnableClock(BOARD_ADP5585_I2C_CLOCK_GATE);

    /* Select SPI3 signals */
    adp5585_handle_t handle;
    BOARD_InitADP5585(&handle);
    ADP5585_SetDirection(&handle, (1 << BOARD_ADP5585_EXP_SEL), kADP5585_Output);
    ADP5585_SetPins(&handle, (1 << BOARD_ADP5585_EXP_SEL));

    PRINTF("LPSPI interrupt board to board (b2b) master example.\r\n");
    PRINTF("This example use one board as master and another as slave.\r\n");
    PRINTF("Please make sure you make the correct line connection. Basically, the connection is:\r\n");
    PRINTF("LPSPI_master -- LPSPI_slave\r\n");
    PRINTF("    CLK      --    CLK\r\n");
    PRINTF("    PCS      --    PCS\r\n");
    PRINTF("    SOUT     --    SIN\r\n");
    PRINTF("    SIN      --    SOUT\r\n");
    PRINTF("    GND      --    GND\r\n");
    PRINTF("Please running slave here, then type any key to continue\r\n");
    GETCHAR();

    uint32_t srcClock_Hz;
    uint32_t errorCount;
    uint32_t i;
    lpspi_which_pcs_t whichPcs;
    uint8_t txWatermark;
    lpspi_master_config_t masterConfig;

    /* Master config. */
    LPSPI_MasterGetDefaultConfig(&masterConfig);
    masterConfig.baudRate = TRANSFER_BAUDRATE;
    masterConfig.whichPcs = EXAMPLE_LPSPI_MASTER_PCS_FOR_INIT;
    masterConfig.pcsToSckDelayInNanoSec        = 1000000000U / (masterConfig.baudRate * 2U);
    masterConfig.lastSckToPcsDelayInNanoSec    = 1000000000U / (masterConfig.baudRate * 2U);
    masterConfig.betweenTransferDelayInNanoSec = 1000000000U / (masterConfig.baudRate * 2U);
    
    srcClock_Hz = LPSPI_MASTER_CLK_FREQ;
    LPSPI_MasterInit(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterConfig, srcClock_Hz);

    /******************Set up master transfer******************/
    /* Set up the transfer data. */
    for (i = 0; i < TRANSFER_SIZE; i++)
    {
        masterTxData[i] = i % 256;
        masterRxData[i] = 0;
    }

    isMasterTransferCompleted = false;
    masterTxCount             = 0;
    masterRxCount             = 0;
    whichPcs                  = EXAMPLE_LPSPI_MASTER_PCS_FOR_INIT;

    /* The TX and RX FIFO sizes are always the same. */
    g_masterFifoSize = LPSPI_GetRxFifoSize(EXAMPLE_LPSPI_MASTER_BASEADDR);

    /* Set the RX and TX watermarks to reduce the ISR times. */
    if (g_masterFifoSize > 1)
    {
        txWatermark         = 1;
        g_masterRxWatermark = g_masterFifoSize - 2;
    }
    else
    {
        txWatermark         = 0;
        g_masterRxWatermark = 0;
    }

    LPSPI_SetFifoWatermarks(EXAMPLE_LPSPI_MASTER_BASEADDR, txWatermark, g_masterRxWatermark);

    LPSPI_Enable(EXAMPLE_LPSPI_MASTER_BASEADDR, false);
    EXAMPLE_LPSPI_MASTER_BASEADDR->CFGR1 &= (~LPSPI_CFGR1_NOSTALL_MASK);
    LPSPI_Enable(EXAMPLE_LPSPI_MASTER_BASEADDR, true);

    /* Flush FIFO, clear status, disable all the inerrupts. */
    LPSPI_FlushFifo(EXAMPLE_LPSPI_MASTER_BASEADDR, true, true);
    LPSPI_ClearStatusFlags(EXAMPLE_LPSPI_MASTER_BASEADDR, kLPSPI_AllStatusFlag);
    LPSPI_DisableInterrupts(EXAMPLE_LPSPI_MASTER_BASEADDR, kLPSPI_AllInterruptEnable);

    LPSPI_SelectTransferPCS(EXAMPLE_LPSPI_MASTER_BASEADDR, whichPcs);
    LPSPI_SetPCSContinous(EXAMPLE_LPSPI_MASTER_BASEADDR, true);

    /* Enable the NVIC for LPSPI peripheral. Note that below code is useless if the LPSPI interrupt is in INTMUX,
     * and you should also enable the INTMUX interupt in your application.
     */
    EnableIRQ(EXAMPLE_LPSPI_MASTER_IRQN);

    /* TCR also shares the FIFO, so wait for TCR written. */
    while (LPSPI_GetTxFifoCount(EXAMPLE_LPSPI_MASTER_BASEADDR) != 0)
    {
    }
    /* Fill up the TX data in FIFO. */
    while ((LPSPI_GetTxFifoCount(EXAMPLE_LPSPI_MASTER_BASEADDR) < g_masterFifoSize) &&
           (masterTxCount - masterRxCount < g_masterFifoSize))
    {
        /* Write the word to TX register */
        LPSPI_WriteData(EXAMPLE_LPSPI_MASTER_BASEADDR, masterTxData[masterTxCount]);
        ++masterTxCount;

        if (masterTxCount == TRANSFER_SIZE)
        {
            /* TCR also shares the FIFO, so wait for FIFO has room. */
            while (LPSPI_GetTxFifoCount(EXAMPLE_LPSPI_MASTER_BASEADDR) == g_masterFifoSize)
            {
            }
            /* Set the PCS back to uncontinuous to finish the transfer if all tx data are pushed to FIFO. */
            LPSPI_SetPCSContinous(EXAMPLE_LPSPI_MASTER_BASEADDR, false);
            break;
        }
    }
    LPSPI_EnableInterrupts(EXAMPLE_LPSPI_MASTER_BASEADDR, kLPSPI_RxInterruptEnable);

    /******************Wait for master and slave transfer completed.******************/
    while (!isMasterTransferCompleted)
    {
    }

    errorCount = 0;
    for (i = 0; i < TRANSFER_SIZE; i++)
    {
        if (masterTxData[i] != masterRxData[i])
        {
            errorCount++;
        }
    }
    if (errorCount == 0)
    {
        PRINTF("\r\nLPSPI transfer all data matched!\r\n");
    }
    else
    {
        PRINTF("\r\nError occurred in LPSPI transfer!\r\n");
    }

    /* Print out receive buffer */
    PRINTF("\r\n Master received:");
    for (i = 0U; i < TRANSFER_SIZE; i++)
    {
        /* Print 16 numbers in a line */
        if ((i & 0x0FU) == 0U)
        {
            PRINTF("\r\n");
        }
        PRINTF(" %02X", masterRxData[i]);
    }
    PRINTF("\r\n");

    LPSPI_Deinit(EXAMPLE_LPSPI_MASTER_BASEADDR);

    PRINTF("\r\nEnd of master example!\r\n");

    while (1)
    {
    }
}
