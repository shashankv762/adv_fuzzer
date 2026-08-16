/**
 * @file demo_vulnerable.c
 * @brief Demo vulnerable target for testing the fuzzer
 * 
 * This is an intentionally vulnerable program for educational purposes.
 * DO NOT use in production. For authorized testing only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Vulnerable structure parser */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t data_size;
    uint8_t data[256];
} demo_packet_t;

#define DEMO_MAGIC 0xDEADBEEF

/**
 * VULNERABILITY 1: Stack buffer overflow
 * Classic unchecked strcpy
 */
static void vulnerable_copy(char *dest, const char *src)
{
    /* BUG: No bounds checking */
    strcpy(dest, src);
}

/**
 * VULNERABILITY 2: Heap buffer overflow
 * Unchecked memcpy to heap buffer
 */
static void process_data(uint8_t *input, size_t input_len)
{
    uint8_t *buffer = malloc(128);
    if (!buffer) return;
    
    /* BUG: No bounds check before copy */
    memcpy(buffer, input, input_len);
    
    /* Process buffer... */
    printf("Processed %zu bytes\n", input_len);
    
    free(buffer);
}

/**
 * VULNERABILITY 3: Integer overflow leading to heap overflow
 */
static void parse_packet(const uint8_t *data, size_t len)
{
    if (len < sizeof(demo_packet_t)) {
        fprintf(stderr, "Packet too small\n");
        return;
    }
    
    const demo_packet_t *pkt = (const demo_packet_t *)data;
    
    if (pkt->magic != DEMO_MAGIC) {
        fprintf(stderr, "Invalid magic number\n");
        return;
    }
    
    /* BUG: Integer overflow - data_size can wrap around */
    uint32_t alloc_size = pkt->data_size + 100;
    if (alloc_size < pkt->data_size) {
        /* Overflow occurred but we don't check! */
    }
    
    uint8_t *heap_buf = malloc(alloc_size);
    if (!heap_buf) return;
    
    /* If overflow occurred, this copies more than allocated */
    memcpy(heap_buf, pkt->data, pkt->data_size);
    
    printf("Parsed packet version %u\n", pkt->version);
    
    free(heap_buf);
}

/**
 * VULNERABILITY 4: Use-after-free
 */
static void use_after_free_demo(const uint8_t *data, size_t len)
{
    if (len == 0) return;
    
    uint8_t *ptr = malloc(len);
    if (!ptr) return;
    
    memcpy(ptr, data, len);
    free(ptr);
    
    /* BUG: Using freed pointer */
    if (len > 0) {
        printf("UAF read: %d\n", ptr[0]);
    }
}

/**
 * VULNERABILITY 5: Double free
 */
static void double_free_demo(int trigger)
{
    uint8_t *ptr = malloc(64);
    if (!ptr) return;
    
    memset(ptr, 0, 64);
    free(ptr);
    
    /* BUG: Double free when trigger is set */
    if (trigger) {
        free(ptr);
    }
}

/**
 * VULNERABILITY 6: Out-of-bounds read
 */
static void oob_read_demo(const char *input, size_t idx)
{
    const char *secret = "SECRET_KEY_12345";
    size_t secret_len = strlen(secret);
    
    /* BUG: No bounds check on idx */
    if (idx < 100) {  /* Wrong check - should be secret_len */
        printf("Character at %zu: %c\n", idx, secret[idx]);
    }
}

/**
 * VULNERABILITY 7: Null pointer dereference
 */
static void null_deref_demo(int trigger)
{
    int *ptr = NULL;
    
    if (trigger) {
        /* BUG: Dereferencing NULL */
        *ptr = 42;
    }
}

/**
 * VULNERABILITY 8: Divide by zero
 */
static void divide_by_zero_demo(int divisor)
{
    int result = 100 / divisor;  /* BUG: No zero check */
    printf("Result: %d\n", result);
}

/**
 * Main entry point - dispatches based on input
 */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        printf("Demo vulnerable target for fuzzing practice.\n");
        printf("\nInput file format:\n");
        printf("  First byte selects vulnerability type:\n");
        printf("    0 = Stack buffer overflow\n");
        printf("    1 = Heap buffer overflow\n");
        printf("    2 = Integer overflow\n");
        printf("    3 = Use-after-free\n");
        printf("    4 = Double free\n");
        printf("    5 = OOB read\n");
        printf("    6 = Null dereference\n");
        printf("    7 = Divide by zero\n");
        return 1;
    }
    
    /* Read input file */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("Failed to open input file");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 1024 * 1024) {
        fprintf(stderr, "Invalid file size\n");
        fclose(f);
        return 1;
    }
    
    uint8_t *input = malloc((size_t)file_size);
    if (!input) {
        fclose(f);
        return 1;
    }
    
    size_t read_size = fread(input, 1, (size_t)file_size, f);
    fclose(f);
    
    if (read_size != (size_t)file_size) {
        free(input);
        return 1;
    }
    
    /* Dispatch based on first byte */
    uint8_t vuln_type = input[0];
    
    switch (vuln_type) {
        case 0:
            /* Stack buffer overflow */
            {
                char small_buffer[32];
                if (read_size > 1) {
                    vulnerable_copy(small_buffer, (char*)input + 1);
                }
            }
            break;
            
        case 1:
            /* Heap buffer overflow */
            if (read_size > 1) {
                process_data(input + 1, read_size - 1);
            }
            break;
            
        case 2:
            /* Integer overflow */
            if (read_size >= sizeof(demo_packet_t)) {
                parse_packet(input + 1, read_size - 1);
            }
            break;
            
        case 3:
            /* Use-after-free */
            if (read_size > 1) {
                use_after_free_demo(input + 1, read_size - 1);
            }
            break;
            
        case 4:
            /* Double free */
            if (read_size > 1 && input[1]) {
                double_free_demo(1);
            }
            break;
            
        case 5:
            /* OOB read */
            if (read_size >= 2) {
                oob_read_demo("test_string", input[1]);
            }
            break;
            
        case 6:
            /* Null dereference */
            if (read_size > 1 && input[1]) {
                null_deref_demo(1);
            }
            break;
            
        case 7:
            /* Divide by zero */
            if (read_size >= 2) {
                divide_by_zero_demo(input[1]);
            }
            break;
            
        default:
            printf("Unknown vulnerability type: %d\n", vuln_type);
            break;
    }
    
    free(input);
    return 0;
}
