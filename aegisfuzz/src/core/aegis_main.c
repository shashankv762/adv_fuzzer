/*
 * AegisFuzz Enterprise - Main Harness Implementation
 * 
 * This is the core entry point that unifies AFL++ and LibFuzzer modes.
 * It manages harness lifecycle, input processing, and coordinates
 * between signal handlers, coverage instrumentation, and target code.
 *
 * Copyright (c) 2024 AegisFuzz Project. All rights reserved.
 * Licensed under the Apache License 2.0.
 */

#include "aegis_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/* Global harness instance for signal handler access */
static aegis_harness_t g_default_harness;

/* Forward declarations */
static aegis_status_t aegis_input_init_internal(aegis_input_t *input, size_t capacity);
static void aegis_input_free_internal(aegis_input_t *input);
static aegis_mode_t aegis_detect_mode_internal(void);

/**
 * Initialize the fuzzing harness.
 * Sets up coverage mapping, signal handlers, and input buffers.
 */
aegis_status_t aegis_harness_init(aegis_harness_t *harness, const aegis_config_t *config)
{
    if (!harness) {
        return AEGIS_ERR_INVALID_ARG;
    }

    memset(harness, 0, sizeof(*harness));

    /* Copy configuration with defaults */
    harness->config.mode = config ? config->mode : AEGIS_MODE_UNKNOWN;
    harness->config.target_name = config ? config->target_name : "unknown_target";
    harness->config.max_input_size = config ? config->max_input_size : AEGIS_MAX_INPUT_SIZE;
    harness->config.timeout_us = config ? config->timeout_us : AEGIS_DEFAULT_TIMEOUT_US;
    harness->config.enable_sanitizers = config ? config->enable_sanitizers : true;
    harness->config.verbose_logging = config ? config->verbose_logging : false;
    harness->config.output_dir = config ? config->output_dir : "output";

    /* Auto-detect mode if not specified */
    if (harness->config.mode == AEGIS_MODE_UNKNOWN) {
        harness->config.mode = aegis_detect_mode_internal();
    }

    AEGIS_LOG("Initializing AegisFuzz Harness");
    AEGIS_LOG("  Mode: %d", harness->config.mode);
    AEGIS_LOG("  Target: %s", harness->config.target_name);
    AEGIS_LOG("  Max Input Size: %zu", harness->config.max_input_size);

    /* Initialize input buffer */
    aegis_status_t status = aegis_input_init_internal(&harness->input, harness->config.max_input_size);
    if (status != AEGIS_OK) {
        AEGIS_LOG("Failed to initialize input buffer");
        return status;
    }

    /* Initialize coverage mapping */
    status = aegis_coverage_init(harness);
    if (status != AEGIS_OK) {
        AEGIS_LOG("Warning: Coverage initialization failed (non-fatal)");
        /* Continue without coverage if AFL++ not present */
    }

    /* Initialize signal handlers */
    status = aegis_signal_setup(harness);
    if (status != AEGIS_OK) {
        AEGIS_LOG("Failed to setup signal handlers");
        aegis_input_free_internal(&harness->input);
        return status;
    }

    /* Initialize statistics */
    harness->stats.start_time = (uint64_t)time(NULL);
    harness->stats.last_update = harness->stats.start_time;

    harness->initialized = true;
    AEGIS_LOG("Harness initialized successfully");

    return AEGIS_OK;
}

/**
 * Cleanup harness resources.
 */
aegis_status_t aegis_harness_cleanup(aegis_harness_t *harness)
{
    if (!harness || !harness->initialized) {
        return AEGIS_ERR_INVALID_ARG;
    }

    AEGIS_LOG("Cleaning up harness");

    /* Restore signal handlers */
    aegis_signal_restore();

    /* Free input buffer */
    aegis_input_free_internal(&harness->input);

    /* Dump final coverage stats */
    if (harness->coverage_map) {
        aegis_coverage_dump(harness);
    }

    harness->initialized = false;
    return AEGIS_OK;
}

/**
 * Initialize input buffer structure.
 */
static aegis_status_t aegis_input_init_internal(aegis_input_t *input, size_t capacity)
{
    if (!input || capacity == 0) {
        return AEGIS_ERR_INVALID_ARG;
    }

    input->data = (uint8_t *)malloc(capacity);
    if (!input->data) {
        return AEGIS_ERR_NO_MEMORY;
    }

    input->size = 0;
    input->capacity = capacity;
    input->is_shared = false;

    memset(input->data, 0, capacity);
    return AEGIS_OK;
}

/**
 * Set input data from external buffer.
 */
aegis_status_t aegis_input_set(aegis_input_t *input, const uint8_t *data, size_t size)
{
    if (!input || !input->data) {
        return AEGIS_ERR_INVALID_ARG;
    }

    if (size > input->capacity) {
        AEGIS_LOG("Input size %zu exceeds capacity %zu", size, input->capacity);
        size = input->capacity;
    }

    memcpy(input->data, data, size);
    input->size = size;
    input->is_shared = false;

    return AEGIS_OK;
}

/**
 * Free input buffer.
 */
static void aegis_input_free_internal(aegis_input_t *input)
{
    if (!input) {
        return;
    }

    if (input->data && !input->is_shared) {
        free(input->data);
    }

    input->data = NULL;
    input->size = 0;
    input->capacity = 0;
}

/**
 * Public wrapper for input free.
 */
void aegis_input_free(aegis_input_t *input)
{
    aegis_input_free_internal(input);
}

/**
 * Detect operating mode based on environment variables.
 */
static aegis_mode_t aegis_detect_mode_internal(void)
{
    const char *mode_env = getenv(AEGIS_ENV_MODE);
    
    if (mode_env) {
        if (strcmp(mode_env, "afl") == 0) {
            return AEGIS_MODE_AFL;
        } else if (strcmp(mode_env, "libfuzzer") == 0) {
            return AEGIS_MODE_LIBFUZZER;
        } else if (strcmp(mode_env, "standalone") == 0) {
            return AEGIS_MODE_STANDALONE;
        }
    }

    /* Check for AFL++ shared memory */
    if (getenv(AEGIS_ENV_SHM_ID)) {
        return AEGIS_MODE_AFL;
    }

    /* Check for LibFuzzer by looking at argv[0] or other indicators */
    /* This is a heuristic - LibFuzzer usually calls LLVMFuzzerTestOneInput directly */
    
    return AEGIS_MODE_STANDALONE;
}

/**
 * Public mode detection function.
 */
aegis_mode_t aegis_detect_mode(void)
{
    return aegis_detect_mode_internal();
}

/* ============================================================================
 * AFL++ Integration: LLVMFuzzerTestOneInput wrapper
 * When compiled with AFL++, this function is called for each test case.
 * ============================================================================ */

#ifdef __AFL_FUZZ_INIT
__AFL_FUZZ_INIT();
#endif

/**
 * Main fuzzing entry point compatible with both AFL++ and LibFuzzer.
 * The fuzzer calls this function with each generated input.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    aegis_harness_t *harness = &g_default_harness;

    if (!harness->initialized) {
        /* Lazy initialization if not done explicitly */
        aegis_config_t config = {0};
        config.target_name = "auto_target";
        if (aegis_harness_init(harness, &config) != AEGIS_OK) {
            return 0;
        }
    }

    harness->stats.total_execs++;

    /* Set current input */
    if (aegis_input_set(&harness->input, data, size) != AEGIS_OK) {
        return 0;
    }

    /* Mark that we're executing target code */
    harness->in_target = true;

    /* Call user-provided fuzz callback if registered */
    if (harness->fuzz_fn) {
        int result = harness->fuzz_fn(data, size, harness->user_ctx);
        
        /* Non-zero return indicates interesting input (for LibFuzzer) */
        harness->in_target = false;
        return result;
    }

    harness->in_target = false;
    return 0;
}

/**
 * Initialize harness with custom callbacks.
 * Called by user code to register target-specific logic.
 */
aegis_status_t aegis_register_callbacks(
    aegis_harness_t *harness,
    aegis_init_cb init_fn,
    aegis_fuzz_cb fuzz_fn,
    aegis_cleanup_cb cleanup_fn,
    aegis_crash_cb crash_fn,
    void *user_ctx
) {
    if (!harness) {
        return AEGIS_ERR_INVALID_ARG;
    }

    harness->init_fn = init_fn;
    harness->fuzz_fn = fuzz_fn;
    harness->cleanup_fn = cleanup_fn;
    harness->crash_fn = crash_fn;
    harness->user_ctx = user_ctx;

    /* Call init callback if provided */
    if (init_fn && harness->initialized) {
        int result = init_fn(user_ctx);
        if (result != 0) {
            AEGIS_LOG("Init callback returned error: %d", result);
        }
    }

    return AEGIS_OK;
}

/**
 * Get the default harness instance.
 * Useful for direct manipulation in standalone mode.
 */
aegis_harness_t* aegis_get_default_harness(void)
{
    return &g_default_harness;
}

/**
 * Standalone mode runner - executes harness with file inputs.
 * Useful for reproducing crashes or testing specific inputs.
 */
aegis_status_t aegis_run_standalone(aegis_harness_t *harness, const char *input_file)
{
    if (!harness || !input_file || !harness->fuzz_fn) {
        return AEGIS_ERR_INVALID_ARG;
    }

    /* Read input file */
    int fd = open(input_file, O_RDONLY);
    if (fd < 0) {
        AEGIS_LOG("Failed to open input file: %s", input_file);
        return AEGIS_ERR_IO;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return AEGIS_ERR_IO;
    }

    if (st.st_size > (off_t)harness->config.max_input_size) {
        AEGIS_LOG("Input file too large: %ld bytes", (long)st.st_size);
        close(fd);
        return AEGIS_ERR_INVALID_ARG;
    }

    uint8_t *buffer = (uint8_t *)malloc(st.st_size);
    if (!buffer) {
        close(fd);
        return AEGIS_ERR_NO_MEMORY;
    }

    ssize_t bytes_read = read(fd, buffer, st.st_size);
    close(fd);

    if (bytes_read < 0 || (size_t)bytes_read != (size_t)st.st_size) {
        free(buffer);
        return AEGIS_ERR_IO;
    }

    AEGIS_LOG("Running standalone test with file: %s (%zu bytes)", input_file, (size_t)bytes_read);

    /* Execute fuzz callback */
    harness->stats.total_execs++;
    int result = harness->fuzz_fn(buffer, bytes_read, harness->user_ctx);

    free(buffer);

    if (result != 0) {
        AEGIS_LOG("Test returned interesting status: %d", result);
    }

    return AEGIS_OK;
}

/* ============================================================================
 * Main Entry Point (for standalone execution)
 * ============================================================================ */

#ifndef AEGIS_NO_MAIN
int main(int argc, char **argv)
{
    aegis_config_t config = {0};
    config.target_name = "standalone_target";
    config.verbose_logging = true;

    aegis_harness_t *harness = aegis_get_default_harness();
    
    if (aegis_harness_init(harness, &config) != AEGIS_OK) {
        fprintf(stderr, "Failed to initialize harness\n");
        return 1;
    }

    if (argc > 1) {
        /* Run in file replay mode */
        for (int i = 1; i < argc; i++) {
            aegis_run_standalone(harness, argv[i]);
        }
    } else {
        printf("AegisFuzz Enterprise v%s\n", AEGIS_VERSION_STRING);
        printf("Usage: %s <input_file> [input_file...]\n", argv[0]);
        printf("Run with AFL++: AFL_PRELOAD=./libaegis_core.so afl-fuzz -i corpus -o output -- ./target\n");
        printf("Run with LibFuzzer: ./target -dict=dict.file corpus/\n");
    }

    aegis_harness_cleanup(harness);
    return 0;
}
#endif
