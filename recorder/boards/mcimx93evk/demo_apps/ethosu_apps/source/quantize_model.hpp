#ifndef QUANTIZE_MODEL
#define QUANTIZE_MODEL
#define INPUT_LENGTH 1*2*160*2*2
#define MODEL_LENGTH 704 
unsigned char input_data[1*2*160*2*2] = {0};
unsigned char model_data[] = {
    0x24, 0x00, 0x00, 0x00, 0x54, 0x46, 0x4c, 0x33, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x1c, 0x00, 0x18, 0x00,
    0x14, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x12, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00,
    0x54, 0x02, 0x00, 0x00, 0xdc, 0x00, 0x00, 0x00, 0x68, 0x02, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xd8, 0xff, 0xff, 0xff, 0x04, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x4f, 0x66, 0x66, 0x6c,
    0x69, 0x6e, 0x65, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x41, 0x6c, 0x6c,
    0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x08, 0x00, 0x0c, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x76, 0x65, 0x6c, 0x61,
    0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
    0x5c, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0xd6, 0xff, 0xff, 0xff, 0x04, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x04, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x33, 0x2e, 0x31, 0x32, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0xff, 0xff, 0xff,
    0x88, 0xff, 0xff, 0xff, 0x8c, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x18, 0x00, 0x14, 0x00,
    0x10, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x00, 0x00,
    0x50, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00,
    0x6c, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x1c, 0x00, 0x00, 0x00,
    0x18, 0x00, 0x14, 0x00, 0x0f, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x10, 0x00, 0x16, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x59, 0x18, 0x00, 0x00, 0x00,
    0x18, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x6c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xaa, 0xff, 0xff, 0xff,
    0x14, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x2c, 0x00, 0x00, 0x00, 0x9c, 0xff, 0xff, 0xff,
    0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x20, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00,
    0x18, 0x00, 0x14, 0x00, 0x13, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x04, 0x00,
    0x0e, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x38, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xbf, 0x94, 0x01, 0x3a, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
    0x56, 0x65, 0x6c, 0x61, 0x20, 0x33, 0x2e, 0x31, 0x32, 0x2e, 0x30, 0x20,
    0x4f, 0x70, 0x74, 0x69, 0x6d, 0x69, 0x73, 0x65, 0x64, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72
  };
  unsigned int quantize1_vela_tflite_len = 704;
  #endif