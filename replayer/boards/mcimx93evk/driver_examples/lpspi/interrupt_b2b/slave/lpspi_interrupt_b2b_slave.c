/*
 * Copyright 2017, 2020, 2024 NXP
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
#define EXAMPLE_LPSPI_SLAVE_BASEADDR         LPSPI3
#define EXAMPLE_LPSPI_SLAVE_IRQN             LPSPI3_IRQn
#define EXAMPLE_LPSPI_SLAVE_IRQHandler       LPSPI3_IRQHandler
#define EXAMPLE_LPSPI_SLAVE_PCS_FOR_INIT     kLPSPI_Pcs0
#define EXAMPLE_LPSPI_SLAVE_PCS_FOR_TRANSFER kLPSPI_SlavePcs0

#define EXAMPLE_LPSPI_SLAVE_CLOCK_NAME (LPSPI_SLAVE_CLOCK_ROOT)
#define LPSPI_SLAVE_CLOCK_ROOT         kCLOCK_Root_Lpspi3
#define LPSPI_SLAVE_CLOCK_GATE         kCLOCK_Lpspi3
#define TRANSFER_SIZE 64U /*! Transfer dataSize */

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/* LPSPI user callback */
void LPSPI_SlaveUserCallback(LPSPI_Type *base, lpspi_slave_handle_t *handle, status_t status, void *userData);

/*******************************************************************************
 * Variables
 ******************************************************************************/
uint8_t slaveRxData[TRANSFER_SIZE] = {0U};
uint8_t slaveTxData[TRANSFER_SIZE] = {0U};

volatile uint32_t slaveTxCount;
volatile uint32_t slaveRxCount;
volatile uint8_t g_slaveRxWatermark;
volatile uint8_t g_slaveFifoSize;

volatile bool isSlaveTransferCompleted = false;

/*******************************************************************************
 * Code
 ******************************************************************************/
void EXAMPLE_LPSPI_SLAVE_IRQHandler(void)
{
    if (slaveRxCount < TRANSFER_SIZE)
    {
        /* While reading out the RX FIFO as more data may be coming into the RX FIFO. We'll
         * re-enable the interrupts after reading out the FIFO.
         */
        while (LPSPI_GetRxFifoCount(EXAMPLE_LPSPI_SLAVE_BASEADDR))
        {
            slaveRxData[slaveRxCount] = LPSPI_ReadData(EXAMPLE_LPSPI_SLAVE_BASEADDR);
            slaveRxCount++;

            if (slaveRxCount == TRANSFER_SIZE)
            {
                LPSPI_DisableInterrupts(EXAMPLE_LPSPI_SLAVE_BASEADDR, kLPSPI_RxInterruptEnable);
                break;
            }
        }
    }

    /* Update rxWatermark. There isn't RX interrupt for the last datas if the RX count is not greater than rxWatermark.
     */
    if ((TRANSFER_SIZE - slaveRxCount) <= g_slaveRxWatermark)
    {
        EXAMPLE_LPSPI_SLAVE_BASEADDR->FCR =
            (EXAMPLE_LPSPI_SLAVE_BASEADDR->FCR & (~LPSPI_FCR_RXWATER_MASK)) |
            LPSPI_FCR_RXWATER(((TRANSFER_SIZE - slaveRxCount) > 1U) ? ((TRANSFER_SIZE - slaveRxCount) - 1U) : (0U));
    }

    if (slaveTxCount < TRANSFER_SIZE)
    {
        while (LPSPI_GetTxFifoCount(EXAMPLE_LPSPI_SLAVE_BASEADDR) < g_slaveFifoSize)
        {
            /* Write the word to TX register */
            LPSPI_WriteData(EXAMPLE_LPSPI_SLAVE_BASEADDR, slaveTxData[slaveTxCount]);
            ++slaveTxCount;

            if (slaveTxCount == TRANSFER_SIZE)
            {
                /* Disable interrupt requests */
                LPSPI_DisableInterrupts(EXAMPLE_LPSPI_SLAVE_BASEADDR, kLPSPI_TxInterruptEnable);
                break;
            }
        }
    }

    /* Check if we're done with this transfer.*/
    if ((slaveRxCount == TRANSFER_SIZE) && (slaveTxCount == TRANSFER_SIZE))
    {
        /* Complete the transfer. */
        isSlaveTransferCompleted = true;
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

    CLOCK_SetRootClock(LPSPI_SLAVE_CLOCK_ROOT, &lpspiClkCfg);
    CLOCK_EnableClock(LPSPI_SLAVE_CLOCK_GATE);
    CLOCK_SetRootClock(BOARD_ADP5585_I2C_CLOCK_ROOT, &lpi2cClkCfg);
    CLOCK_EnableClock(BOARD_ADP5585_I2C_CLOCK_GATE);

    /* Select SPI3 signals */
    adp5585_handle_t handle;
    BOARD_InitADP5585(&handle);
    ADP5585_SetDirection(&handle, (1 << BOARD_ADP5585_EXP_SEL), kADP5585_Output);
    ADP5585_SetPins(&handle, (1 << BOARD_ADP5585_EXP_SEL));

    PRINTF("LPSPI interrupt board to board (b2b) slave example.\r\n");
    PRINTF("  Slave start to receive data...\r\n");

    uint32_t errorCount;
    uint32_t i;
    lpspi_slave_config_t slaveConfig;
    lpspi_which_pcs_t whichPcs;
    uint8_t txWatermark;

    /* Slave config */
    LPSPI_SlaveGetDefaultConfig(&slaveConfig);
    slaveConfig.whichPcs = EXAMPLE_LPSPI_SLAVE_PCS_FOR_INIT;

    LPSPI_SlaveInit(EXAMPLE_LPSPI_SLAVE_BASEADDR, &slaveConfig);

    /* Set up the transfer data */
    for (i = 0; i < TRANSFER_SIZE; i++)
    {
        slaveTxData[i] = i % 256;
        slaveRxData[i] = 0;
    }
    /******************Set up slave first ******************/
    isSlaveTransferCompleted = false;
    slaveTxCount             = 0;
    slaveRxCount             = 0;
    whichPcs                 = EXAMPLE_LPSPI_SLAVE_PCS_FOR_INIT;

    /* The TX and RX FIFO sizes are always the same */
    g_slaveFifoSize = LPSPI_GetRxFifoSize(EXAMPLE_LPSPI_SLAVE_BASEADDR);

    /* Set the RX and TX watermarks to reduce the ISR times. */
    if (g_slaveFifoSize > 1)
    {
        txWatermark        = 1;
        g_slaveRxWatermark = g_slaveFifoSize - 2;
    }
    else
    {
        txWatermark        = 0;
        g_slaveRxWatermark = 0;
    }

    LPSPI_SetFifoWatermarks(EXAMPLE_LPSPI_SLAVE_BASEADDR, txWatermark, g_slaveRxWatermark);

    LPSPI_Enable(EXAMPLE_LPSPI_SLAVE_BASEADDR, false);
    EXAMPLE_LPSPI_SLAVE_BASEADDR->CFGR1 &= (~LPSPI_CFGR1_NOSTALL_MASK);
    LPSPI_Enable(EXAMPLE_LPSPI_SLAVE_BASEADDR, true);

    /* Flush FIFO, clear status, disable all the interrupts. */
    LPSPI_FlushFifo(EXAMPLE_LPSPI_SLAVE_BASEADDR, true, true);
    LPSPI_ClearStatusFlags(EXAMPLE_LPSPI_SLAVE_BASEADDR, kLPSPI_AllStatusFlag);
    LPSPI_DisableInterrupts(EXAMPLE_LPSPI_SLAVE_BASEADDR, kLPSPI_AllInterruptEnable);

    LPSPI_SelectTransferPCS(EXAMPLE_LPSPI_SLAVE_BASEADDR, whichPcs);

    /* Enable the NVIC for LPSPI peripheral. Note that below code is useless if the LPSPI interrupt is in INTMUX,
     * and you should also enable the INTMUX interrupt in your application.
     */
    EnableIRQ(EXAMPLE_LPSPI_SLAVE_IRQN);

    /* TCR is also shared the FIFO, so wait for TCR written. */
    while (LPSPI_GetTxFifoCount(EXAMPLE_LPSPI_SLAVE_BASEADDR) != 0)
    {
    }

    /* Fill up the TX data in FIFO */
    while (LPSPI_GetTxFifoCount(EXAMPLE_LPSPI_SLAVE_BASEADDR) < g_slaveFifoSize)
    {
        /* Write the word to TX register */
        LPSPI_WriteData(EXAMPLE_LPSPI_SLAVE_BASEADDR, slaveTxData[slaveTxCount]);
        ++slaveTxCount;

        if (slaveTxCount == TRANSFER_SIZE)
        {
            break;
        }
    }
    if (slaveTxCount == TRANSFER_SIZE)
    {
        /* Only enable rx interrupt if tx data are all pushed to FIFO */
        LPSPI_EnableInterrupts(EXAMPLE_LPSPI_SLAVE_BASEADDR, kLPSPI_RxInterruptEnable);
    }
    else
    {
        LPSPI_EnableInterrupts(EXAMPLE_LPSPI_SLAVE_BASEADDR, kLPSPI_RxInterruptEnable | kLPSPI_TxInterruptEnable);
    }

    /******************Wait for master and slave transfer completed.******************/
    while (!isSlaveTransferCompleted)
    {
    }

    errorCount = 0;
    for (i = 0; i < TRANSFER_SIZE; i++)
    {
        if (slaveTxData[i] != slaveRxData[i])
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
    PRINTF("\r\n Slave received:");
    for (i = 0U; i < TRANSFER_SIZE; i++)
    {
        /* Print 16 numbers in a line */
        if ((i & 0x0FU) == 0U)
        {
            PRINTF("\r\n");
        }
        PRINTF(" %02X", slaveRxData[i]);
    }
    PRINTF("\r\n");

    LPSPI_Deinit(EXAMPLE_LPSPI_SLAVE_BASEADDR);

    PRINTF("\r\nEnd of slave example!\r\n");

    while (1)
    {
    }
}
