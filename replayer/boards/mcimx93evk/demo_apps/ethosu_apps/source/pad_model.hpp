#ifndef PAD_MODEL
#define PAD_MODEL
#define INPUT_LENGTH 1*2*160*8*2
#define MODEL_LENGTH 1632
unsigned char input_data[1*2*160*8*2] = {0};
unsigned char model_data[1632] = {
    0x24, 0x00, 0x00, 0x00, 0x54, 0x46, 0x4c, 0x33, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x1c, 0x00, 0x18, 0x00,
    0x14, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x12, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00,
    0xe4, 0x05, 0x00, 0x00, 0xcc, 0x02, 0x00, 0x00, 0xf8, 0x05, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xd8, 0xff, 0xff, 0xff, 0x04, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x4f, 0x66, 0x66, 0x6c,
    0x69, 0x6e, 0x65, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x41, 0x6c, 0x6c,
    0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x08, 0x00, 0x0c, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x76, 0x65, 0x6c, 0x61,
    0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x5c, 0x02, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00,
    0x5c, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x36, 0xff, 0xff, 0xff, 0x04, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
    0x66, 0xff, 0xff, 0xff, 0x04, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x33, 0x2e, 0x31, 0x32, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xff, 0xff, 0xff,
    0x04, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x60, 0x01, 0x00, 0x00, 0x43, 0x4f, 0x50, 0x31, 0x01, 0x00, 0x10, 0x00,
    0x08, 0x30, 0x00, 0x10, 0x00, 0x00, 0x06, 0x10, 0x05, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x02, 0x00, 0x50, 0x00,
    0x23, 0x01, 0x00, 0x00, 0x0f, 0x01, 0x01, 0x00, 0x00, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x0c, 0x01, 0x01, 0x00,
    0x0a, 0x01, 0x9f, 0x00, 0x04, 0x01, 0x07, 0x00, 0x06, 0x40, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x05, 0x40, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00,
    0x04, 0x40, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00,
    0x05, 0x01, 0x05, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00,
    0x1f, 0x01, 0x01, 0x00, 0x10, 0x40, 0x00, 0x00, 0x30, 0x14, 0x00, 0x00,
    0x11, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x13, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x1b, 0x01, 0x01, 0x00, 0x1c, 0x01, 0x01, 0x00, 0x1a, 0x01, 0x9f, 0x00,
    0x12, 0x01, 0x01, 0x00, 0x11, 0x01, 0x9f, 0x00, 0x13, 0x01, 0x07, 0x00,
    0x16, 0x40, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x15, 0x40, 0x00, 0x00,
    0x60, 0x0a, 0x00, 0x00, 0x14, 0x40, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x18, 0x01, 0x00, 0x00, 0x14, 0x01, 0x03, 0x81, 0x21, 0x01, 0x00, 0x00,
    0x20, 0x01, 0x00, 0x00, 0x22, 0x01, 0x00, 0x00, 0x25, 0x01, 0x00, 0x00,
    0x26, 0x01, 0x00, 0x80, 0x27, 0x01, 0xff, 0x7f, 0x16, 0x01, 0x01, 0x00,
    0x15, 0x01, 0x03, 0x00, 0x17, 0x01, 0x07, 0x00, 0x0d, 0x01, 0x0a, 0x00,
    0x2d, 0x01, 0x1e, 0x00, 0x24, 0x01, 0x00, 0x00, 0x24, 0x40, 0x1f, 0x00,
    0x01, 0x00, 0x00, 0x80, 0x2f, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00,
    0x0f, 0x01, 0x00, 0x00, 0x0a, 0x01, 0x02, 0x00, 0x05, 0x40, 0x00, 0x00,
    0x30, 0x00, 0x00, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
    0x1a, 0x01, 0x02, 0x00, 0x11, 0x01, 0x02, 0x00, 0x2f, 0x01, 0x03, 0x00,
    0x05, 0x00, 0x01, 0x00, 0x10, 0x40, 0x00, 0x00, 0x30, 0x1e, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00,
    0x18, 0x00, 0x14, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x04, 0x00,
    0x0e, 0x00, 0x00, 0x00, 0xf0, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x74, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
    0x18, 0x00, 0x00, 0x00, 0x14, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x16, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x18, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x28, 0x02, 0x00, 0x00, 0xe8, 0x01, 0x00, 0x00,
    0xb4, 0x01, 0x00, 0x00, 0x70, 0x01, 0x00, 0x00, 0xbc, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x5a, 0xff, 0xff, 0xff, 0x10, 0x00, 0x00, 0x00,
    0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x80, 0x00, 0x00, 0x00,
    0x4c, 0xff, 0xff, 0xff, 0x10, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xa2, 0x1f, 0xaa, 0x3b, 0x01, 0x00, 0x00, 0x00,
    0x4e, 0x1e, 0x2a, 0x43, 0x01, 0x00, 0x00, 0x00, 0x22, 0xb4, 0x6b, 0xc1,
    0x3a, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x61, 0x62,
    0x6c, 0x65, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x5f, 0x31, 0x30, 0x2f,
    0x75, 0x6e, 0x65, 0x74, 0x5f, 0x30, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x5f,
    0x63, 0x6f, 0x6e, 0x76, 0x5f, 0x6c, 0x61, 0x73, 0x74, 0x2f, 0x66, 0x72,
    0x65, 0x71, 0x5f, 0x64, 0x69, 0x6d, 0x5f, 0x70, 0x61, 0x64, 0x2f, 0x50,
    0x61, 0x64, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0xa6, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0e, 0x00, 0x14, 0x00, 0x10, 0x00, 0x0f, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00,
    0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x8c, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x14, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x04, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xa2, 0x1f, 0xaa, 0x3b, 0x01, 0x00, 0x00, 0x00, 0x4e, 0x1e, 0x2a, 0x43,
    0x01, 0x00, 0x00, 0x00, 0x22, 0xb4, 0x6b, 0xc1, 0x3e, 0x00, 0x00, 0x00,
    0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x6d,
    0x6f, 0x64, 0x65, 0x6c, 0x5f, 0x31, 0x30, 0x2f, 0x75, 0x6e, 0x65, 0x74,
    0x5f, 0x30, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x76,
    0x5f, 0x6c, 0x61, 0x73, 0x74, 0x2f, 0x61, 0x63, 0x74, 0x69, 0x76, 0x61,
    0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x4c, 0x65, 0x61, 0x6b, 0x79, 0x52, 0x65,
    0x6c, 0x75, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0xcc, 0xff, 0xff, 0xff, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x20, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x5f, 0x73, 0x70, 0x6c,
    0x69, 0x74, 0x5f, 0x31, 0x5f, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68,
    0x5f, 0x66, 0x61, 0x73, 0x74, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x0b, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x1c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x5f, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x5f, 0x31, 0x5f, 0x73, 0x63, 0x72,
    0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xc0, 0x28, 0x00, 0x00, 0xd0, 0xff, 0xff, 0xff, 0x10, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00,
    0x0e, 0x00, 0x00, 0x00, 0x5f, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x5f, 0x31,
    0x5f, 0x66, 0x6c, 0x61, 0x73, 0x68, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x60, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x14, 0x00, 0x10, 0x00, 0x0f, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, 0x00, 0x00, 0x00,
    0x17, 0x00, 0x00, 0x00, 0x5f, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x5f, 0x31,
    0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x5f, 0x73, 0x74, 0x72,
    0x65, 0x61, 0x6d, 0x00, 0x01, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
    0x56, 0x65, 0x6c, 0x61, 0x20, 0x33, 0x2e, 0x31, 0x32, 0x2e, 0x30, 0x20,
    0x4f, 0x70, 0x74, 0x69, 0x6d, 0x69, 0x73, 0x65, 0x64, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x10, 0x00,
    0x0f, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
    0x07, 0x00, 0x00, 0x00, 0x65, 0x74, 0x68, 0x6f, 0x73, 0x2d, 0x75, 0x00
  };
  unsigned int pad18_vela_tflite_len = 1632;
#endif  