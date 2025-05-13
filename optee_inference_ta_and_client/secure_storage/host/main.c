#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <err.h>
#include <tee_client_api.h>
#include <secure_storage_ta.h>

#define MAX_BUFFER_SIZE 7000       // 最大缓冲区大小，根据实际情况调整
#define FILENAME "model_data.bin"    // 原始文件
#define RETRIEVED_FILENAME "secure_retrieved.bin"  // 读取后生成的文件

// TEE 资源结构体
struct test_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
    TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
    uint32_t origin;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x", res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

TEEC_Result write_secure_object(struct test_ctx *ctx, char *id,
                                char *data, size_t data_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    size_t id_len = strlen(id);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = id_len;
    op.params[1].tmpref.buffer = data;
    op.params[1].tmpref.size = data_len;

    res = TEEC_InvokeCommand(&ctx->sess,
                             TA_SECURE_STORAGE_CMD_WRITE_RAW,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

    return res;
}

TEEC_Result read_secure_object(struct test_ctx *ctx, char *id,
                               char *data, size_t data_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    size_t id_len = strlen(id);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = id_len;
    op.params[1].tmpref.buffer = data;
    op.params[1].tmpref.size = data_len;

    res = TEEC_InvokeCommand(&ctx->sess,
                             TA_SECURE_STORAGE_CMD_READ_RAW,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);

    return res;
}

/*
 * 存储操作：读取文件后，在数据前附加4字节文件大小头，然后存储到安全存储中。
 */
void store_file_data(struct test_ctx *ctx, const char *filename, const char *obj_id)
{
    FILE *file = NULL;
    char *file_buffer = NULL;
    size_t file_size = 0;
    TEEC_Result res;

    file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* 要存储的数据 = 4字节文件大小头 + 文件内容 */
    size_t total_size = sizeof(uint32_t) + file_size;
    if (total_size > MAX_BUFFER_SIZE) {
        fprintf(stderr, "File too large to store (max %d bytes allowed)\n", MAX_BUFFER_SIZE);
        fclose(file);
        return;
    }
    file_buffer = malloc(total_size);
    if (!file_buffer) {
        perror("Failed to allocate memory for file data");
        fclose(file);
        return;
    }

    /* 将文件大小（4字节）写入缓冲区头部 */
    uint32_t file_size_le = (uint32_t)file_size; // 假设小于4GB
    memcpy(file_buffer, &file_size_le, sizeof(uint32_t));

    /* 将文件内容读取到缓冲区后续位置 */
    fread(file_buffer + sizeof(uint32_t), 1, file_size, file);
    fclose(file);

    printf("Prepare session with the TA\n");
    prepare_tee_session(ctx);

    printf("- Write file data to secure storage\n");
    res = write_secure_object(ctx, (char *)obj_id, file_buffer, total_size);
    if (res != TEEC_SUCCESS)
        errx(1, "Failed to store file data in secure storage");

    printf("File data has been securely stored.\n");

    free(file_buffer);
    terminate_tee_session(ctx);
}

/*
 * 读取操作：从安全存储中读取数据，先读取4字节头解析出文件实际大小，
 * 然后将对应大小的文件内容写入到 secure_retrieved.bin 文件中。
 */
void retrieve_file_data(struct test_ctx *ctx, const char *obj_id)
{
    char *read_buffer = malloc(MAX_BUFFER_SIZE);
    if (!read_buffer) {
        perror("Failed to allocate memory for reading file data");
        return;
    }

    printf("Prepare session with the TA\n");
    prepare_tee_session(ctx);

    printf("- Read file data from secure storage\n");
    TEEC_Result res = read_secure_object(ctx, (char *)obj_id, read_buffer, MAX_BUFFER_SIZE);
    if (res != TEEC_SUCCESS)
        errx(1, "Failed to read file data from secure storage");

    /* 从读取数据中解析出文件大小 */
    uint32_t stored_file_size;
    memcpy(&stored_file_size, read_buffer, sizeof(uint32_t));
    if (stored_file_size > MAX_BUFFER_SIZE - sizeof(uint32_t)) {
        fprintf(stderr, "Invalid stored file size\n");
        free(read_buffer);
        terminate_tee_session(ctx);
        return;
    }

    FILE *outfile = fopen(RETRIEVED_FILENAME, "wb");
    if (!outfile) {
        perror("Failed to open output file for writing");
        free(read_buffer);
        terminate_tee_session(ctx);
        return;
    }

    /* 只写入文件内容部分 */
    fwrite(read_buffer + sizeof(uint32_t), 1, stored_file_size, outfile);
    fclose(outfile);

    printf("Retrieved file data has been written to %s (size: %u bytes)\n",
           RETRIEVED_FILENAME, stored_file_size);

    free(read_buffer);
    terminate_tee_session(ctx);
}

int main(int argc, char *argv[])
{
    struct test_ctx ctx;
    const char *obj_id = "model_data_object";

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <store|retrieve>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "store") == 0) {
        store_file_data(&ctx, FILENAME, obj_id);
    } else if (strcmp(argv[1], "retrieve") == 0) {
        retrieve_file_data(&ctx, obj_id);
    } else {
        fprintf(stderr, "Invalid argument: %s. Use 'store' or 'retrieve'.\n", argv[1]);
        return 1;
    }

    return 0;
}
