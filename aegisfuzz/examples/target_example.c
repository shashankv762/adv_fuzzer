/*
 * AegisFuzz Enterprise - Example Target with Intentional Vulnerability
 * 
 * This example demonstrates how to use the AegisFuzz harness to fuzz
 * a simple parser function. It contains an intentional buffer overflow
 * vulnerability for testing purposes.
 *
 * DO NOT USE THIS CODE IN PRODUCTION - IT CONTAINS DELIBERATE VULNERABILITIES
 * FOR TESTING THE FUZZER'S CRASH DETECTION CAPABILITIES.
 *
 * Copyright (c) 2024 AegisFuzz Project. All rights reserved.
 * Licensed under the Apache License 2.0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../src/core/aegis_types.h"

/* ============================================================================
 * VULNERABLE TARGET CODE
 * This simulates a real-world parser with a buffer overflow bug.
 * ============================================================================ */

#define HEADER_SIZE 8
#define MAX_DATA_SIZE 256

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t data_length;
} packet_header_t;

#define PACKET_MAGIC 0x41454749  /* "AEGI" */

/* 
 * VULNERABLE FUNCTION: Buffer overflow when data_length > buffer size
 * This is intentionally left vulnerable to demonstrate crash detection.
 */
static int parse_packet(const uint8_t *input, size_t input_size)
{
    if (input_size < HEADER_SIZE) {
        return -1; /* Input too small */
    }

    /* Parse header */
    packet_header_t header;
    header.magic = *(uint32_t*)(input);
    header.version = *(uint16_t*)(input + 4);
    header.flags = *(uint16_t*)(input + 6);
    
    if (input_size >= HEADER_SIZE + 4) {
        header.data_length = *(uint32_t*)(input + 8);
    } else {
        header.data_length = 0;
    }

    /* Check magic number */
    if (header.magic != PACKET_MAGIC) {
        return -2; /* Invalid magic */
    }

    /* 
     * VULNERABILITY: No proper bounds checking on data_length
     * If data_length is very large, this will cause heap overflow
     */
    uint8_t local_buffer[64];
    
    /* Simulate processing data - THIS IS INTENTIONALLY VULNERABLE */
    if (header.data_length > 0 && header.data_length < 10000) {
        /* Bug: copies data_length bytes without checking against local_buffer size */
        size_t copy_size = header.data_length;
        if (HEADER_SIZE + copy_size <= input_size) {
            /* Intentionally unsafe copy for demonstration */
            memcpy(local_buffer, input + HEADER_SIZE, copy_size > 64 ? 64 : copy_size);
            
            /* Additional bug: if data_length is huge but we only copy 64, 
             * we might still have logic errors */
            if (copy_size > 64) {
                /* This path triggers on oversized inputs */
                volatile uint8_t sink = local_buffer[copy_size % 64];
                (void)sink;
            }
        }
    }

    /* Another vulnerability: integer overflow in size calculation */
    if (header.flags & 0x01) {
        uint32_t alloc_size = header.data_length * 2;
        if (alloc_size < header.data_length) {
            /* Integer overflow detected - trigger abort */
            abort();
        }
        
        /* Safe allocation for demo, but the overflow check above can trigger */
        if (alloc_size > 0 && alloc_size < 1000000) {
            void *ptr = malloc(alloc_size);
            if (ptr) {
                memset(ptr, 0, alloc_size);
                free(ptr);
            }
        }
    }

    return 0;
}

/* ============================================================================
 * FUZZ HARNESS INTEGRATION
 * Connects the target to AegisFuzz framework.
 * ============================================================================ */

static int fuzz_target_init(void *ctx)
{
    (void)ctx;
    printf("[Target] Initializing packet parser\n");
    return 0;
}

static int fuzz_target_process(const uint8_t *data, size_t size, void *ctx)
{
    (void)ctx;
    
    /* Minimum size check */
    if (size < HEADER_SIZE) {
        return 0;
    }

    /* Call the vulnerable parser */
    int result = parse_packet(data, size);
    
    /* Return non-zero for interesting inputs (LibFuzzer convention) */
    return (result == 0) ? 1 : 0;
}

static void fuzz_target_cleanup(void *ctx)
{
    (void)ctx;
    printf("[Target] Cleaning up\n");
}

static void fuzz_crash_handler(const aegis_crash_report_t *report, void *ctx)
{
    (void)ctx;
    fprintf(stderr, "[CRASH CALLBACK] Detected crash: %s\n", report->id);
}

/* ============================================================================
 * MAIN ENTRY POINT
 * Can be run standalone, with AFL++, or with LibFuzzer.
 * ============================================================================ */

int main(int argc, char **argv)
{
    printf("=== AegisFuzz Example Target ===\n");
    printf("Target: Packet Parser with Intentional Vulnerabilities\n");
    printf("==============================\n\n");

    /* Initialize harness */
    aegis_config_t config = {0};
    config.target_name = "packet_parser";
    config.max_input_size = 1024;
    config.verbose_logging = true;

    aegis_harness_t *harness = aegis_get_default_harness();
    
    if (aegis_harness_init(harness, &config) != AEGIS_OK) {
        fprintf(stderr, "Failed to initialize harness\n");
        return 1;
    }

    /* Register callbacks */
    aegis_register_callbacks(
        harness,
        fuzz_target_init,
        fuzz_target_process,
        fuzz_target_cleanup,
        fuzz_crash_handler,
        NULL
    );

    /* Handle command line arguments */
    if (argc > 1) {
        /* Standalone mode: replay files */
        printf("Running in standalone replay mode...\n");
        for (int i = 1; i < argc; i++) {
            printf("\nProcessing: %s\n", argv[i]);
            aegis_status_t status = aegis_run_standalone(harness, argv[i]);
            if (status != AEGIS_OK) {
                printf("Error processing %s: %d\n", argv[i], status);
            }
        }
    } else {
        /* Fuzzer mode: wait for LLVMFuzzerTestOneInput calls */
        printf("Ready for fuzzing.\n");
        printf("Usage modes:\n");
        printf("  Standalone: %s <input_file>\n", argv[0]);
        printf("  AFL++:      AFL_PRELOAD=./libaegis_core.so afl-fuzz -i corpus -o output -- ./target\n");
        printf("  LibFuzzer:  ./target corpus/\n");
        
        /* In LibFuzzer mode, LLVMFuzzerTestOneInput will be called automatically */
        /* For standalone without args, just show help */
        #ifdef __AFL_FUZZ_TEST_CASE_LEN
        /* AFL++ persistent mode would go here */
        #endif
    }

    aegis_harness_cleanup(harness);
    return 0;
}
