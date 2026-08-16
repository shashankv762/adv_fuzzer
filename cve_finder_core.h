/**
 * CVE-FINDER: Advanced Fuzzing Framework for Vulnerability Discovery
 * 
 * This is a production-grade, modular fuzzing harness designed for:
 * 1. Integration with AFL++ and LibFuzzer
 * 2. Real-time crash triage and logging
 * 3. Coverage-guided exploration
 * 4. CI/CD pipeline integration
 * 5. Cloud-ready deployment (AWS/Azure/GCP)
 * 
 * DISCLAIMER: For authorized security research and bug bounty programs only.
 * No automated exploit generation is included; focus is on vulnerability detection.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#ifndef CVE_FINDER_CORE_H
#define CVE_FINDER_CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <execinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>

/* ============================================================================
 * CONFIGURATION & CONSTANTS
 * ============================================================================ */

#define CVE_FINDER_VERSION "1.0.0-PRO"
#define MAX_INPUT_SIZE (1024 * 1024) /* 1MB default max input */
#define MAX_CRASH_LOG_LEN 4096
#define MAX_BACKTRACE_DEPTH 64
#define SHARED_MEM_MAP_SIZE (1 << 16) /* 64KB coverage map */

/* Mode Flags */
#define MODE_AFL 0x01
#define MODE_LIBFUZZER 0x02
#define MODE_STANDALONE 0x04

/* Severity Levels */
typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} severity_level_t;

/* Crash Types */
typedef enum {
    CRASH_NONE = 0,
    CRASH_SEGFAULT,
    CRASH_ABRT,
    CRASH_FPE,
    CRASH_BUS,
    CRASH_TIMEOUT,
    CRASH_UNKNOWN
} crash_type_t;

/* ============================================================================
 * CORE DATA STRUCTURES
 * ============================================================================ */

/**
 * @brief Global configuration context for the fuzzer
 */
typedef struct {
    uint8_t mode;                   /* Operating mode (AFL/LibFuzzer/Standalone) */
    char *target_name;              /* Name of the target library/function */
    char *output_dir;               /* Directory for crash logs and stats */
    char *input_dir;                /* Directory for seed inputs */
    uint32_t max_input_size;        /* Maximum input size to process */
    uint32_t timeout_sec;           /* Execution timeout in seconds */
    int verbose;                    /* Verbosity level (0-3) */
    int ci_mode;                    /* CI/CD pipeline mode (exit on crash) */
} cve_finder_config_t;

/**
 * @brief Crash information structure for triage
 */
typedef struct {
    crash_type_t type;              /* Type of crash */
    severity_level_t severity;      /* Estimated severity */
    pid_t pid;                      /* Process ID where crash occurred */
    time_t timestamp;               /* Time of crash */
    char signal_str[32];            /* Human readable signal */
    void *backtrace[MAX_BACKTRACE_DEPTH]; /* Stack trace addresses */
    int backtrace_size;             /* Number of frames in backtrace */
    char log_file_path[512];        /* Path to saved crash log */
    uint8_t input_sample[64];       /* First 64 bytes of crashing input */
    size_t input_sample_len;        /* Length of sample */
} crash_info_t;

/**
 * @brief Statistics tracking for real-time reporting
 */
typedef struct {
    uint64_t total_execs;           /* Total executions */
    uint64_t crashes_found;         /* Total unique crashes */
    uint64_t hangs_found;           /* Total timeouts/hangs */
    uint64_t start_time;            /* Start timestamp */
    uint64_t last_crash_time;       /* Timestamp of last crash */
    uint32_t paths_found;           /* Unique paths discovered (coverage) */
    uint8_t *coverage_map;          /* Pointer to shared coverage map */
} fuzzer_stats_t;

/* ============================================================================
 * GLOBAL STATE (Managed by Fuzzer Engine)
 * ============================================================================ */

extern cve_finder_config_t g_config;
extern fuzzer_stats_t g_stats;
extern volatile sig_atomic_t g_stop_requested;

/* AFL++ Shared Memory for Coverage */
extern uint8_t *afl_coverage_map;

/* ============================================================================
 * CORE API FUNCTIONS
 * ============================================================================ */

/**
 * @brief Initialize the CVE-Finder framework
 * 
 * Parses environment variables, sets up signal handlers, and initializes
 * shared memory for coverage tracking.
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, -1 on failure
 */
int cve_finder_init(int argc, char **argv);

/**
 * @brief Shutdown the framework gracefully
 * 
 * Flushes logs, generates final reports, and cleans up resources.
 */
void cve_finder_shutdown(void);

/**
 * @brief Main entry point for user-defined fuzz targets
 * 
 * Users must implement this function in their specific target harness.
 * 
 * @param data Pointer to input data
 * @param size Size of input data
 * @return 0 on success, non-zero on error/crash
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/**
 * @brief Report a crash to the framework
 * 
 * Called internally by signal handlers or explicitly by sanitizers.
 * 
 * @param info Pointer to populated crash_info_t structure
 */
void cve_finder_report_crash(crash_info_t *info);

/**
 * @brief Log a message with severity level
 * 
 * @param level Severity level
 * @param format Printf-style format string
 * @param ... Arguments
 */
void cve_log(severity_level_t level, const char *format, ...);

/**
 * @brief Update coverage map (Called by instrumentation)
 * 
 * @param pc Program counter
 * @param edge Edge identifier
 */
void cve_finder_update_coverage(uint32_t pc, uint32_t edge);

/* ============================================================================
 * SIGNAL HANDLING & CRASH TRIAGE
 * ============================================================================ */

/**
 * @brief Install custom signal handlers for crash detection
 */
void install_signal_handlers(void);

/**
 * @brief Generate a stack trace
 * 
 * @param buffer Buffer to store addresses
 * @param max_frames Maximum number of frames
 * @return Number of frames captured
 */
int generate_backtrace(void **buffer, int max_frames);

/**
 * @brief Save crash details to disk
 * 
 * @param info Crash information structure
 * @return 0 on success, -1 on failure
 */
int save_crash_log(crash_info_t *info);

/* ============================================================================
 * INTEGRATION HOOKS
 * ============================================================================ */

/**
 * @brief Check if running under AFL++
 * 
 * @return 1 if yes, 0 if no
 */
int is_afl_mode(void);

/**
 * @brief Check if running under LibFuzzer
 * 
 * @return 1 if yes, 0 if no
 */
int is_libfuzzer_mode(void);

/**
 * @brief Get coverage map pointer
 * 
 * @return Pointer to coverage map or NULL
 */
uint8_t* get_coverage_map(void);

/* ============================================================================
 * MACROS FOR EASE OF USE
 * ============================================================================ */

#define CVE_LOG_INFO(fmt, ...) cve_log(SEV_INFO, fmt, ##__VA_ARGS__)
#define CVE_LOG_WARN(fmt, ...) cve_log(SEV_LOW, fmt, ##__VA_ARGS__)
#define CVE_LOG_ERROR(fmt, ...) cve_log(SEV_MEDIUM, fmt, ##__VA_ARGS__)
#define CVE_LOG_CRIT(fmt, ...) cve_log(SEV_HIGH, fmt, ##__VA_ARGS__)

#endif /* CVE_FINDER_CORE_H */
