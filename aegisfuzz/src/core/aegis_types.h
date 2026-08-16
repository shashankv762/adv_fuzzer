/*
 * AegisFuzz Enterprise - Core Type Definitions
 * 
 * This header defines the fundamental types, constants, and structures
 * used throughout the AegisFuzz core engine. It ensures type safety
 * and provides a unified interface for both AFL++ and LibFuzzer modes.
 *
 * Copyright (c) 2024 AegisFuzz Project. All rights reserved.
 * Licensed under the Apache License 2.0.
 */

#ifndef AEGIS_TYPES_H
#define AEGIS_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <signal.h>

/* ============================================================================
 * VERSIONING
 * ============================================================================ */
#define AEGIS_VERSION_MAJOR 1
#define AEGIS_VERSION_MINOR 0
#define AEGIS_VERSION_PATCH 0
#define AEGIS_VERSION_STRING "1.0.0"

/* ============================================================================
 * CONFIGURATION CONSTANTS
 * ============================================================================ */

/* Maximum input size supported by the harness (default: 1MB) */
#define AEGIS_MAX_INPUT_SIZE (1024 * 1024)

/* Default timeout for target execution in microseconds */
#define AEGIS_DEFAULT_TIMEOUT_US 500000

/* Shared memory map size for AFL++ coverage feedback */
#define AEGIS_MAP_SIZE (1 << 16)

/* Maximum number of signal handlers to register */
#define AEGIS_MAX_SIGNAL_HANDLERS 8

/* Path configuration */
#define AEGIS_ENV_SHM_ID "__AFL_SHM_ID"
#define AEGIS_ENV_DEBUG "AEGIS_DEBUG"
#define AEGIS_ENV_MODE "AEGIS_MODE" /* Values: "afl", "libfuzzer", "standalone" */

/* Crash reporting paths */
#define AEGIS_DIR_CRASHES "output/crashes"
#define AEGIS_DIR_HANGS "output/hangs"
#define AEGIS_DIR_CORPUS "output/corpus"
#define AEGIS_DIR_LOGS "output/logs"

/* ============================================================================
 * TYPE DEFINITIONS
 * ============================================================================ */

/* Status codes for harness operations */
typedef enum {
    AEGIS_OK = 0,
    AEGIS_ERR_INVALID_ARG = -1,
    AEGIS_ERR_NO_MEMORY = -2,
    AEGIS_ERR_SHM_FAILED = -3,
    AEGIS_ERR_TIMEOUT = -4,
    AEGIS_ERR_CRASH = -5,
    AEGIS_ERR_HANG = -6,
    AEGIS_ERR_IO = -7,
    AEGIS_ERR_UNSUPPORTED = -8
} aegis_status_t;

/* Fuzzer operating mode */
typedef enum {
    AEGIS_MODE_UNKNOWN = 0,
    AEGIS_MODE_AFL,       /* Running under AFL++ */
    AEGIS_MODE_LIBFUZZER, /* Running under LibFuzzer */
    AEGIS_MODE_STANDALONE /* Standalone testing mode */
} aegis_mode_t;

/* Crash severity levels */
typedef enum {
    AEGIS_SEV_INFO = 0,
    AEGIS_SEV_LOW,
    AEGIS_SEV_MEDIUM,
    AEGIS_SEV_HIGH,
    AEGIS_SEV_CRITICAL
} aegis_severity_t;

/* Signal context structure for crash reporting */
typedef struct {
    int signum;              /* Signal number */
    void *addr;              /* Faulting address (if applicable) */
    void *ip;                /* Instruction pointer at crash */
    void *sp;                /* Stack pointer at crash */
    void *bp;                /* Base pointer at crash */
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t flags;          /* EFLAGS/RFLAGS */
    uint64_t cr2;            /* Page fault linear address (x86) */
} aegis_crash_context_t;

/* Crash report structure */
typedef struct {
    char id[64];             /* Unique crash identifier (hash) */
    aegis_severity_t severity;
    aegis_crash_context_t context;
    char stack_trace[4096];  /* Symbolicated stack trace */
    char input_path[1024];   /* Path to the crashing input file */
    uint64_t input_size;     /* Size of the crashing input */
    uint64_t exec_time_us;   /* Execution time when crash occurred */
    uint64_t timestamp;      /* Unix timestamp of crash */
    char target_name[256];   /* Name of the fuzzed target */
    char sanitizer_info[512];/* ASan/UBSan output if available */
} aegis_crash_report_t;

/* Coverage statistics */
typedef struct {
    uint64_t total_execs;    /* Total executions */
    uint64_t unique_edges;   /* Unique edges covered */
    uint64_t unique_pcs;     /* Unique PCs covered */
    uint64_t crashes;        /* Total crashes found */
    uint64_t hangs;          /* Total hangs detected */
    uint64_t start_time;     /* Start timestamp */
    uint64_t last_update;    /* Last statistics update */
} aegis_stats_t;

/* Harness configuration */
typedef struct {
    aegis_mode_t mode;
    const char *target_name;
    size_t max_input_size;
    uint64_t timeout_us;
    bool enable_sanitizers;
    bool verbose_logging;
    const char *output_dir;
} aegis_config_t;

/* Input buffer structure */
typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
    bool is_shared;        /* True if backed by shared memory */
} aegis_input_t;

/* Callback function types */
typedef int (*aegis_init_cb)(void *ctx);
typedef int (*aegis_fuzz_cb)(const uint8_t *data, size_t size, void *ctx);
typedef void (*aegis_cleanup_cb)(void *ctx);
typedef void (*aegis_crash_cb)(const aegis_crash_report_t *report, void *ctx);

/* Main harness context */
typedef struct {
    aegis_config_t config;
    aegis_input_t input;
    aegis_stats_t stats;
    uint8_t *coverage_map; /* Pointer to AFL++ shared memory */
    void *user_ctx;        /* User-defined context pointer */
    
    /* Callbacks */
    aegis_init_cb init_fn;
    aegis_fuzz_cb fuzz_fn;
    aegis_cleanup_cb cleanup_fn;
    aegis_crash_cb crash_fn;
    
    /* Internal state */
    bool initialized;
    bool in_target;        /* True while executing target code */
    pid_t target_pid;      /* PID of the target process (if forked) */
} aegis_harness_t;

/* ============================================================================
 * MACRO UTILITIES
 * ============================================================================ */

/* Align to 8-byte boundary */
#define AEGIS_ALIGN8(x) (((x) + 7) & ~7)

/* Min/Max helpers */
#define AEGIS_MIN(a, b) ((a) < (b) ? (a) : (b))
#define AEGIS_MAX(a, b) ((a) > (b) ? (a) : (b))

/* Array size helper */
#define AEGIS_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Debug logging macro (enabled in debug builds) */
#ifdef AEGIS_DEBUG
    #include <stdio.h>
    #define AEGIS_LOG(fmt, ...) \
        fprintf(stderr, "[AEGIS:%d] " fmt "\n", __LINE__, ##__VA_ARGS__)
    #define AEGIS_LOG_HEX(buf, len) \
        do { \
            fprintf(stderr, "[HEX] "); \
            for (size_t _i = 0; _i < (len) && _i < 64; _i++) \
                fprintf(stderr, "%02x ", (buf)[_i]); \
            fprintf(stderr, "\n"); \
        } while (0)
#else
    #define AEGIS_LOG(fmt, ...) ((void)0)
    #define AEGIS_LOG_HEX(buf, len) ((void)0)
#endif

/* Error checking helper */
#define AEGIS_CHECK(cond, err_code) \
    do { \
        if (!(cond)) return (err_code); \
    } while (0)

/* ============================================================================
 * FUNCTION DECLARATIONS (Implemented in subsequent modules)
 * ============================================================================ */

/* Initialization */
aegis_status_t aegis_harness_init(aegis_harness_t *harness, const aegis_config_t *config);
aegis_status_t aegis_harness_cleanup(aegis_harness_t *harness);

/* Input handling */
aegis_status_t aegis_input_init(aegis_input_t *input, size_t capacity);
aegis_status_t aegis_input_set(aegis_input_t *input, const uint8_t *data, size_t size);
void aegis_input_free(aegis_input_t *input);

/* Signal handling */
aegis_status_t aegis_signal_setup(aegis_harness_t *harness);
void aegis_signal_restore(void);

/* Coverage instrumentation */
aegis_status_t aegis_coverage_init(aegis_harness_t *harness);
void aegis_coverage_dump(const aegis_harness_t *harness);

/* Crash reporting */
aegis_status_t aegis_crash_generate_id(const aegis_crash_context_t *ctx, char *id_out, size_t id_len);
aegis_status_t aegis_crash_report_save(const aegis_crash_report_t *report);

/* Mode detection */
aegis_mode_t aegis_detect_mode(void);

#endif /* AEGIS_TYPES_H */
