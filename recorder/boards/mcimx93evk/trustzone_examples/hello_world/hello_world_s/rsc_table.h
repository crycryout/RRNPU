// rsc_table.h
#ifndef RSC_TABLE_H_
#define RSC_TABLE_H_

#include <stddef.h>
#include <stdint.h>

/* remoteproc resource types */
#define RSC_CARVEOUT    0

/*
 * struct fw_rsc_carveout
 *   type  — 必须设为 RSC_CARVEOUT
 *   da    — 目标设备（NPU）地址
 *   pa    — 物理地址（on Linux side 同 da）
 *   len   — carveout 的长度
 *   flags — 保留，设 0 即可
 *   reserved — 两个保留字段
 *   name  — 一个以 '\0' 结尾的字符串，用来给这块区域起个名字
 *
 * 注意：name 我这儿定了 32 字节足够用，你也可以改大点。
 */
struct fw_rsc_carveout {
    uint32_t type;
    uint32_t da;
    uint32_t pa;
    uint32_t len;
    uint32_t flags;
    uint32_t reserved[2];
    char     name[32];
};

/*
 * struct resource_table
 *   version  — table 版本，总是设为 1
 *   num      — 后面有几个 entry （这里只有一个 carveout）
 *   reserved — 两个保留字段
 *   offset[] — 每个 entry 相对于本结构体起始的偏移量
 *   carveout — 上面定义的第 0 号 entry
 */
struct resource_table {
    uint32_t version;
    uint32_t num;
    uint32_t reserved[2];
    uint32_t offset[1];              /* 这里只有一个 entry */
    struct fw_rsc_carveout carveout; /* 0 号 entry */
};

#endif /* RSC_TABLE_H_ */
