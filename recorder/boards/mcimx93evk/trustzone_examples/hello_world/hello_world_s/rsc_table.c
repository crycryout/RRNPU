/* resource_table.c */
#include <stddef.h>
#include <rsc_table.h>

/* 放到 .resource_table 段里，保证 ELF 链到这张表 */
#ifdef __GNUC__
__attribute__((section(".resource_table"), used))
#elif defined(__ICCARM__)
#pragma location = ".resource_table"
#else
#error Compiler not supported!
#endif
const struct resource_table rsc_table = {
    /* 1. 版本号 */
    .version       = 1,
    /* 2. 后面有几个 resource entry（这里只有一个 carveout） */
    .num           = 1,
    .reserved      = { 0, 0 },
    /* 3. 每个 entry 相对于表头的偏移 */
    .offset        = {
        offsetof(struct resource_table, carveout),
    },
    /* 4. carveout 资源：告诉 Linux 把整个固件拷到 0x2001E000，长度 0x1000 */
    .carveout = {
        RSC_CARVEOUT,          /* 类型 */
        0,                     /* 按驱动习惯填 0 */
        0,                     /* 按驱动习惯填 0 */
        /* 下面是真正的目标物理地址和长度 */
        .da   = 0x2001E000,    /* 设备地址 / 物理地址 */
        .pa   = 0x2001E000,    /* 物理地址 */
        .len  = 0x00001000,    /* 长度 */
        .flags= 0,             /* 0 即可 */
        .reserved = {0,0},
        .name = "firmware",    /* 可以随便取个名字 */
    },
};
