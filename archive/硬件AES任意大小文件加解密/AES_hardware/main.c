#include <main.h>
#include "bsp.h"
#include "cm32m4xxr_aes.h"
#include "cm32m4xxr_algo_common.h"
#include <string.h>
#include <stdio.h>

// 宏定义
#define CHUNK_SIZE 1024
#define AES_BLOCK_SIZE 16

// 调试级别控制
#define DEBUG_LEVEL 0  // 0=无调试, 1=基本调试, 2=详细调试

#if DEBUG_LEVEL >= 1
#define DBG_PRINT(...) printf(__VA_ARGS__)
#else
#define DBG_PRINT(...)
#endif

#if DEBUG_LEVEL >= 2
#define DBG_VERBOSE(...) printf(__VA_ARGS__)
#else
#define DBG_VERBOSE(...)
#endif

// 操作模式
typedef enum {
    OP_ENCRYPT,
    OP_DECRYPT
} operation_mode_t;

// 会话状态
typedef struct {
    operation_mode_t mode;
    uint8_t iv[16];
    uint32_t total_processed;
    uint32_t total_file_size;
    uint8_t is_first_chunk;
    uint8_t is_last_chunk;
} session_state_t;

USART_InitType USART_InitStructure;

// 全局变量
static uint8_t input_buffer[CHUNK_SIZE + 64];
static uint8_t output_buffer[CHUNK_SIZE + 64];

uint32_t get_current_time(void);
int process_file_chunk_with_key(operation_mode_t mode, uint8_t *input_data, uint32_t input_len,
                      uint8_t *output_data, uint32_t *output_len, session_state_t *session, uint8_t *key);

void RCC_Configuration(void) {
    GPIO_APBxClkCmd(USARTx_GPIO_CLK | RCC_APB2_PERIPH_AFIO, ENABLE);
    USART_APBxClkCmd(USARTx_CLK, ENABLE);
}

void GPIO_Configuration(void) {
    GPIO_InitType GPIO_InitStructure;
    GPIO_ConfigPinRemap(GPIO_RMP3_UART4, ENABLE);

    GPIO_InitStructure.Pin        = USARTx_TxPin;
    GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
    GPIO_InitStructure.GPIO_Mode  = GPIO_Mode_AF_PP;
    GPIO_Init(USARTx_GPIO, &GPIO_InitStructure);

    GPIO_InitStructure.Pin       = USARTx_RxPin;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IN_FLOATING;
    GPIO_Init(USARTx_GPIO, &GPIO_InitStructure);
}

int _put_char(int ch) {
    USART_SendData(USARTx, (uint8_t)ch);
    while (USART_GetFlagStatus(USARTx, USART_FLAG_TXDE) == RESET);
    return ch;
}

int _get_char(void) {
    uint32_t timeout = 5000000;
    while (USART_GetFlagStatus(USARTx, USART_FLAG_RXDNE) == RESET) {
        timeout--;
        if (timeout == 0) return -1;
    }
    int ch = (int)USART_ReceiveData(USARTx);
    return ch;
}

/**
 * @brief 彻底清空接收缓冲区
 */
void clear_receive_buffer(void) {
    DBG_VERBOSE("Clearing receive buffer...\n");
    uint32_t cleared_count = 0;
    while (USART_GetFlagStatus(USARTx, USART_FLAG_RXDNE) != RESET) {
        USART_ReceiveData(USARTx);
        cleared_count++;
    }
    DBG_VERBOSE("Cleared %lu bytes\n", cleared_count);
}

/**
 * @brief 读取精确长度的数据（优化版本）
 */
uint32_t read_exact_data(uint8_t *data, uint32_t exact_len, uint32_t timeout_ms) {
    uint32_t bytes_read = 0;
    uint32_t timeout = timeout_ms * 1000;
    uint32_t last_receive_time = get_current_time();
    uint32_t start_time = get_current_time();

    DBG_VERBOSE("Reading %d bytes\n", exact_len);

    while (bytes_read < exact_len) {
        if (USART_GetFlagStatus(USARTx, USART_FLAG_RXDNE) != RESET) {
            data[bytes_read] = USART_ReceiveData(USARTx);
            bytes_read++;
            last_receive_time = get_current_time();

            // 减少进度输出频率
            if (bytes_read % 100 == 0) {
                DBG_VERBOSE("Received %d/%d\n", bytes_read, exact_len);
            }
        } else {
            uint32_t current_time = get_current_time();
            // 检查无数据超时
            if (current_time - last_receive_time > 500000) { // 500ms无数据
                DBG_PRINT("No data timeout: %d/%d\n", bytes_read, exact_len);
                break;
            }
            // 检查总超时
            if (current_time - start_time > timeout) {
                DBG_PRINT("Overall timeout: %d/%d\n", bytes_read, exact_len);
                break;
            }
        }
    }

    DBG_VERBOSE("Read complete: %d/%d\n", bytes_read, exact_len);
    return bytes_read;
}

// 系统滴答计时器
volatile uint32_t system_tick = 0;

void SysTick_Handler(void) {
    system_tick++;
}

uint32_t get_current_time(void) {
    return system_tick * 1000;
}

void init_systick(void) {
    SysTick_Config(SystemCoreClock / 1000);
}

/**
 * @brief 发送确认信号
 */
void send_ack(void) {
    printf("ACK\n");
}

/**
 * @brief 发送错误信号
 */
void send_error(const char* message) {
    printf("ERROR:%s\n", message);
}

void pkcs7_padding(uint8_t *data, uint32_t *data_len, uint32_t block_size) {
    uint8_t pad_value = block_size - (*data_len % block_size);
    uint32_t original_len = *data_len;

    for(uint32_t i = original_len; i < original_len + pad_value; i++) {
        data[i] = pad_value;
    }
    *data_len = original_len + pad_value;

    DBG_PRINT("PKCS#7: %d -> %d bytes\n", original_len, *data_len);
}

int pkcs7_unpadding(uint8_t *data, uint32_t *data_len) {
    if (*data_len == 0) {
        DBG_PRINT("PKCS#7 Failure: zero length\n");
        return -1;
    }

    uint8_t pad_value = data[*data_len - 1];

    if (pad_value == 0 || pad_value > *data_len) {
        DBG_PRINT("PKCS#7 Failure: invalid padding 0x%02x\n", pad_value);
        return -1;
    }

    for (uint32_t i = *data_len - pad_value; i < *data_len; i++) {
        if (data[i] != pad_value) {
            DBG_PRINT("PKCS#7 Failure: padding mismatch\n");
            return -1;
        }
    }

    *data_len -= pad_value;
    DBG_PRINT("PKCS#7: %d -> %d bytes\n", *data_len + pad_value, *data_len);
    return 0;
}

/**
 * @brief 发送处理后的数据（Base64编码）- 优化版本
 */
void send_encrypted_data_base64(uint8_t *data, uint32_t len) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // 计算Base64编码后的长度
    uint32_t b64_len = 4 * ((len + 2) / 3);

    // 使用静态缓冲区
    static char b64_buffer[1500];

    if (b64_len >= sizeof(b64_buffer)) {
        printf("ERROR: Base64 buffer too small\n");
        return;
    }

    int i, j;
    uint32_t triple;

    // Base64编码
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        triple = (data[i] << 16);
        if (i + 1 < len) triple |= (data[i + 1] << 8);
        if (i + 2 < len) triple |= data[i + 2];

        b64_buffer[j]   = base64_chars[(triple >> 18) & 0x3F];
        b64_buffer[j+1] = base64_chars[(triple >> 12) & 0x3F];
        b64_buffer[j+2] = (i + 1 < len) ? base64_chars[(triple >> 6) & 0x3F] : '=';
        b64_buffer[j+3] = (i + 2 < len) ? base64_chars[triple & 0x3F] : '=';
    }
    b64_buffer[j] = '\0';

    printf("B64:%s\n", b64_buffer);
}

/**
 * @brief 处理文件块加解密 - 硬件AES版本（支持自定义密钥）
 */
int process_file_chunk_with_key(operation_mode_t mode, uint8_t *input_data, uint32_t input_len,
                      uint8_t *output_data, uint32_t *output_len, session_state_t *session, uint8_t *key) {

    AES_PARM AES_Parm = {0};

    DBG_VERBOSE("Processing: mode=%s, len=%d, last=%d\n",
           mode == OP_ENCRYPT ? "encrypt" : "decrypt", input_len, session->is_last_chunk);

    if (mode == OP_ENCRYPT) {
        // 加密模式
        uint32_t padded_len = input_len;
        uint8_t *data_to_encrypt = input_data;

        // 只有最后一个块需要填充
        if (session->is_last_chunk) {
            DBG_VERBOSE("Last chunk, checking padding\n");
            if (input_len % 16 != 0) {
                DBG_PRINT("Need padding, current: %d\n", input_len);
                if (input_len <= CHUNK_SIZE) {
                    memcpy(input_buffer, input_data, input_len);
                    pkcs7_padding(input_buffer, &padded_len, 16);
                    data_to_encrypt = input_buffer;
                } else {
                    DBG_PRINT("ERROR: Input too large\n");
                    return -1;
                }
            }
        }

        DBG_VERBOSE("Encrypting %d bytes\n", padded_len);

        // 设置AES参数
        AES_Parm.in = (uint32_t*)data_to_encrypt;
        AES_Parm.out = (uint32_t*)output_data;
        AES_Parm.key = (uint32_t*)key;
        AES_Parm.iv = (uint32_t*)session->iv;
        AES_Parm.inWordLen = padded_len / 4;
        AES_Parm.keyWordLen = 4;
        AES_Parm.Mode = AES_CBC;
        AES_Parm.En_De = AES_ENC;

        if (AES_Init_OK != AES_Init(&AES_Parm)) {
            DBG_PRINT("ERROR: AES_Init failed\n");
            AES_Close();
            return -1;
        }

        if (AES_Crypto_OK != AES_Crypto(&AES_Parm)) {
            DBG_PRINT("ERROR: AES_Crypto failed\n");
            AES_Close();
            return -1;
        }

        AES_Close();
        *output_len = padded_len;

        // 关键修改：像软件AES一样，使用最后一个密文块更新IV
        memcpy(session->iv, output_data + padded_len - 16, 16);

    } else {
        // 解密模式
        DBG_VERBOSE("Decrypting %d bytes\n", input_len);

        // 设置AES参数
        AES_Parm.in = (uint32_t*)input_data;
        AES_Parm.out = (uint32_t*)output_data;
        AES_Parm.key = (uint32_t*)key;
        AES_Parm.iv = (uint32_t*)session->iv;
        AES_Parm.inWordLen = input_len / 4;
        AES_Parm.keyWordLen = 4;
        AES_Parm.Mode = AES_CBC;
        AES_Parm.En_De = AES_DEC;

        if (AES_Init_OK != AES_Init(&AES_Parm)) {
            DBG_PRINT("ERROR: AES_Init failed\n");
            AES_Close();
            return -1;
        }

        if (AES_Crypto_OK != AES_Crypto(&AES_Parm)) {
            DBG_PRINT("ERROR: AES_Crypto failed\n");
            AES_Close();
            return -1;
        }

        AES_Close();
        *output_len = input_len;

        // 如果是最后一个块，去填充
        if (session->is_last_chunk) {
            DBG_VERBOSE("Last chunk, removing padding\n");

            // 检查是否需要去填充（只有在有填充的情况下）
            uint8_t last_byte = output_data[*output_len - 1];
            if (last_byte <= 16 && last_byte > 0) {
                // 可能是有效的PKCS#7填充，尝试去除
                if (pkcs7_unpadding(output_data, output_len) != 0) {
                    DBG_PRINT("WARNING: PKCS7 unpadding failed, treating as no padding\n");
                    // 如果去填充失败，保持原数据不变
                    // 这样既能处理有填充的数据，也能处理无填充的NIST测试数据
                }
            } else {
                // 没有填充，保持数据不变
                DBG_VERBOSE("No padding detected, keeping data as is\n");
            }
        }

        // 关键修改：像软件AES一样，使用最后一个输入密文块更新IV
        memcpy(session->iv, input_data + input_len - 16, 16);
    }

    session->total_processed += input_len;
    DBG_VERBOSE("Total processed: %lu bytes\n", session->total_processed);
    return 0;
}

/**
 * @brief 新的流式文件处理 - 支持自定义密钥和IV
 */
void new_stream_file_processing(void) {
    printf("NEW_STREAM_MODE\n");

    // 初始化系统计时器
    init_systick();

    // 等待操作选择
    printf("WAIT_OPERATION\n");
    clear_receive_buffer();

    // 读取操作模式
    uint8_t op_byte;
    if (read_exact_data(&op_byte, 1, 1000) != 1) {
        send_error("No operation received");
        return;
    }

    operation_mode_t mode;
    if (op_byte == 'e' || op_byte == 'E') {
        mode = OP_ENCRYPT;
        printf("OPERATION:ENCRYPT\n");
    } else if (op_byte == 'd' || op_byte == 'D') {
        mode = OP_DECRYPT;
        printf("OPERATION:DECRYPT\n");
    } else {
        send_error("Invalid operation");
        return;
    }

    // 发送确认
    send_ack();

    // 接收密钥 (16字节)
    printf("WAIT_KEY\n");
    clear_receive_buffer();

    uint8_t key[16];
    uint32_t key_bytes_received = read_exact_data(key, 16, 5000);
    if (key_bytes_received != 16) {
        // 使用默认密钥
        uint8_t default_key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        memcpy(key, default_key, 16);
        printf("Using default key\n");
    } else {
        printf("Custom key received\n");
    }

    // 发送密钥确认
    send_ack();

    // 接收IV (16字节)
    printf("WAIT_IV\n");
    clear_receive_buffer();

    uint8_t iv[16];
    uint32_t iv_bytes_received = read_exact_data(iv, 16, 5000);
    if (iv_bytes_received != 16) {
        // 使用默认IV
        uint8_t default_iv[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        memcpy(iv, default_iv, 16);
        printf("Using default IV\n");
    } else {
        printf("Custom IV received\n");
    }

    // 发送IV确认
    send_ack();

    // 读取文件大小
    printf("WAIT_SIZE\n");
    clear_receive_buffer();

    uint8_t size_buffer[4];
    uint32_t size_bytes_received = read_exact_data(size_buffer, 4, 5000);

    if (size_bytes_received != 4) {
        DBG_PRINT("File size receive failed: %lu/4\n", size_bytes_received);
        send_error("File size receive failed");
        return;
    }

    // 解析文件大小 (大端序)
    uint32_t file_size = (size_buffer[0] << 24) | (size_buffer[1] << 16) |
                        (size_buffer[2] << 8) | size_buffer[3];

    printf("FILE_SIZE:%lu\n", file_size);

    if (file_size == 0 || file_size > 1000000) {
        send_error("Invalid file size");
        return;
    }

    // 发送确认
    send_ack();

    // 初始化会话
    session_state_t session = {0};
    session.mode = mode;
    session.total_file_size = file_size;
    session.is_last_chunk = 0;
    session.total_processed = 0;

    // 使用接收到的IV
    memcpy(session.iv, iv, 16);

    printf("READY_FOR_DATA\n");

    uint32_t total_received = 0;
    uint32_t chunk_count = 0;

    // 修改process_file_chunk调用，传入密钥
    while (total_received < file_size) {
        chunk_count++;
        uint32_t remaining = file_size - total_received;
        uint32_t chunk_size = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;

        printf("WAIT_CHUNK:%d\n", chunk_size);

        uint32_t received_len = read_exact_data(input_buffer, chunk_size, 10000);

        if (received_len == chunk_size) {
            total_received += received_len;
            printf("CHUNK_RECEIVED:%d\n", received_len);
        } else {
            DBG_PRINT("Chunk receive failed: expected %d, got %d\n", chunk_size, received_len);
            break;
        }

        if (total_received >= file_size) {
            session.is_last_chunk = 1;
            DBG_VERBOSE("This is the last chunk\n");
        }

        uint32_t output_len = 0;

        // 调用修改后的process_file_chunk，传入密钥
        int result = process_file_chunk_with_key(mode, input_buffer, received_len,
                                      output_buffer, &output_len, &session, key);

        if (result != 0) {
            DBG_PRINT("Processing failed: %d\n", result);
            printf("B64:\n");
            printf("CHUNK_PROCESSED:%d->%d\n", received_len, 0);
            break;
        }

        send_encrypted_data_base64(output_buffer, output_len);
        printf("CHUNK_PROCESSED:%d->%d\n", received_len, output_len);

        int progress = (total_received * 100) / file_size;
        printf("PROGRESS:%d%%\n", progress);
    }

    printf("STREAM_COMPLETE\n");
    printf("SUMMARY: received=%lu, processed=%lu, chunks=%lu\n",
           total_received, session.total_processed, chunk_count);

    if (total_received == file_size) {
        printf("SUCCESS: All data processed\n");
    } else {
        printf("WARNING: Incomplete: expected=%lu, received=%lu\n", file_size, total_received);
    }
}

int main(void) {
    RCC_Configuration();
    GPIO_Configuration();

    USART_InitStructure.BaudRate            = 115200;
    USART_InitStructure.WordLength          = USART_WL_8B;
    USART_InitStructure.StopBits            = USART_STPB_1;
    USART_InitStructure.Parity              = USART_PE_NO;
    USART_InitStructure.HardwareFlowControl = USART_HFCTRL_NONE;
    USART_InitStructure.Mode                = USART_MODE_RX | USART_MODE_TX;

    USART_Init(USARTx, &USART_InitStructure);
    USART_Enable(USARTx, ENABLE);

    // 初始化系统计时器
    init_systick();

    while (1) {  // 主循环
        // 初始化
        printf("Initializing...\n");
        clear_receive_buffer();

        printf("MCU Startup Successful!\n");
        printf("READY\n");

        // 读取模式选择
        int choice = _get_char();
        printf("MODE:%c\n", choice);

        switch (choice) {
            case 'n':
            case 'N':
                printf("Starting New Stream Processing...\n");
                new_stream_file_processing();
                break;
            case 'r':
            case 'R':
                printf("Software reset...\n");
                // 可选：执行软件复位
                // NVIC_SystemReset();
                break;
            default:
                printf("Invalid choice\n");
                break;
        }

        printf("Operation completed. Waiting for next command...\n");

        // 清空接收缓冲区，准备接收下一个命令
        clear_receive_buffer();
    }
}
