#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "pin_mux.h"
#include "board.h"

/* OCRAM 起始地址与长度 */
#define OCRAM_BASE_ADDR 0x20484050U
#define OCRAM_DUMP_LEN  1552U

int main(void)
{
    char ch;

    /* Init board hardware. */
    BOARD_InitBootPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    /* 原有打印 */
    PRINTF("hello world.\r\n");

    /* ------------------------------------------------------------------ */
    /* 读取并打印 OCRAM 中前 1552 字节内容，按 16 字节一行输出地址偏移与数据 */
    {
        volatile uint8_t *p = (uint8_t *)OCRAM_BASE_ADDR;
        PRINTF("OCRAM @ 0x%08X dump %u bytes:\r\n", OCRAM_BASE_ADDR, OCRAM_DUMP_LEN);
        for (uint32_t i = 0; i < OCRAM_DUMP_LEN; i++) {
            /* 每 16 字节打印一次新地址 */
            if ((i & 0x0F) == 0) {
                PRINTF("\r\n%08X: ", (unsigned)(OCRAM_BASE_ADDR + i));
            }
            PRINTF("%02X ", p[i]);
        }
        PRINTF("\r\nEnd of OCRAM dump\r\n");
    }
    /* ------------------------------------------------------------------ */

    while (1)
    {
        ch = GETCHAR();
        PUTCHAR(ch);
    }
}
