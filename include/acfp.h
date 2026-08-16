/**
 * @file acfp.h
 * @brief Main header file for Advanced C Fuzzing Platform
 * 
 * This header defines core structures, constants, and function prototypes
 * for the fuzzing platform. Designed for C11/C17 compliance.
 */

#ifndef ACFP_H
#define ACFP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/* Version information */
#define ACFP_VERSION_MAJOR 1
#define ACFP_VERSION_MINOR 0
#define ACFP_VERSION_PATCH 0
#define ACFP_VERSION_STRING "1.0.0"

/* Platform limits */
#define ACFP_MAX_INPUT_SIZE (1024 * 1024)       /* 1MB max input */
#define ACFP_MAX_CORPUS_SIZE (100 * 1024 * 1024) /* 100MB corpus limit */
#define ACFP_MAX_PATH_LEN 4096
#define ACFP_MAX_CRASH_HASH_LEN 64
#define ACFP_MAX_STACK_TRACE_LEN 8192
#define ACFP_MAX_SANITIZER_OUTPUT_LEN 16384
#define ACFP_MAX_MUTATORS 32
#define ACFP_MAX_DICTIONARY_ENTRIES 1024
#define ACFP_MAX_DICT_ENTRY_LEN 256

/* Crash severity levels */
typedef enum {
    ACFP_SEVERITY_UNKNOWN = 0,
    ACFP_SEVERITY_INFO,
    ACFP_SEVERITY_LOW,
    ACFP_SEVERITY_MEDIUM,
    ACFP_SEVERITY_HIGH,
    ACFP_SEVERITY_CRITICAL
} acfp_severity_t;

/* Exploitability assessment */
typedef enum {
    ACFP_EXPLOIT_UNKNOWN = 0,
    ACFP_EXPLOIT_NOT_EXPLOITABLE,
    ACFP_EXPLOIT_PROBABLY_NOT_EXPLOITABLE,
    ACFP_EXPLOIT_PROBABLY_EXPLOITABLE,
    ACFP_EXPLOIT_EXPLOITABLE,
    ACFP_EXPLOIT_DOS_ONLY
} acfp_exploitability_t;

/* Crash types */
typedef enum {
    ACFP_CRASH_UNKNOWN = 0,
    ACFP_CRASH_HEAP_OVERFLOW,
    ACFP_CRASH_STACK_OVERFLOW,
    ACFP_CRASH_USE_AFTER_FREE,
    ACFP_CRASH_DOUBLE_FREE,
    ACFP_CRASH_OOB_READ,
    ACFP_CRASH_OOB_WRITE,
    ACFP_CRASH_NULL_DEREF,
    ACFP_CRASH_INTEGER_OVERFLOW,
    ACFP_CRASH_UNINITIALIZED_MEM,
    ACFP_CRASH_DIVIDE_BY_ZERO,
    ACFP_CRASH_ASSERTION_FAILURE,
    ACFP_CRASH_TIMEOUT,
    ACFP_CRASH_HANG,
    ACFP_CRASH_LEAK,
    ACFP_CRASH_UNDEFINED_BEHAVIOR
} acfp_crash_type_t;

/* Lifecycle states */
typedef enum {
    ACFP_STATE_NEW = 0,
    ACFP_STATE_TRIAGED,
    ACFP_STATE_CONFIRMED,
    ACFP_STATE_EXPLOITABILITY_ASSESSED,
    ACFP_STATE_PATCH_PROPOSED,
    ACFP_STATE_PATCH_VERIFIED,
    ACFP_STATE_DISCLOSED,
    ACFP_STATE_REJECTED,
    ACFP_STATE_ARCHIVED
} acfp_lifecycle_state_t;

/* User roles */
typedef enum {
    ACFP_ROLE_VIEWER = 0,
    ACFP_ROLE_RESEARCHER,
    ACFP_ROLE_ADMIN,
    ACFP_ROLE_OWNER
} acfp_role_t;

/* Fuzzer backend types */
typedef enum {
    ACFP_BACKEND_NATIVE = 0,
    ACFP_BACKEND_AFLPP,
    ACFP_BACKEND_LIBFUZZER
} acfp_backend_t;

/* Mutation types */
typedef enum {
    ACFP_MUT_BITFLIP = 0,
    ACFP_MUT_BYTEFLIP,
    ACFP_MUT_ARITHMETIC,
    ACFP_MUT_INTERESTING_VALUE,
    ACFP_MUT_BLOCK_DUPLICATION,
    ACFP_MUT_BLOCK_DELETION,
    ACFP_MUT_BLOCK_INSERTION,
    ACFP_MUT_SPLICING,
    ACFP_MUT_SHUFFLE,
    ACFP_MUT_DICTIONARY,
    ACFP_MUT_HAVOC,
    ACFP_MUT_COUNT
} acfp_mutation_t;

/* Dictionary entry */
typedef struct {
    uint8_t data[ACFP_MAX_DICT_ENTRY_LEN];
    size_t len;
    uint32_t hit_count;
} acfp_dict_entry_t;

/* Dictionary */
typedef struct {
    acfp_dict_entry_t entries[ACFP_MAX_DICTIONARY_ENTRIES];
    size_t count;
} acfp_dictionary_t;

/* Coverage map */
#define ACFP_COVERAGE_MAP_SIZE 65536
typedef struct {
    uint8_t map[ACFP_COVERAGE_MAP_SIZE];
    uint32_t checksum;
    size_t covered_edges;
} acfp_coverage_t;

/* Input buffer */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
} acfp_input_t;

/* Corpus entry */
typedef struct {
    char path[ACFP_MAX_PATH_LEN];
    uint8_t *data;
    size_t len;
    uint64_t execs;
    uint32_t hash;
    time_t discovered;
    bool minimized;
} acfp_corpus_entry_t;

/* Corpus manager */
#define ACFP_MAX_CORPUS_ENTRIES 10000
typedef struct {
    acfp_corpus_entry_t *entries[ACFP_MAX_CORPUS_ENTRIES];
    size_t count;
    size_t total_size;
    char base_path[ACFP_MAX_PATH_LEN];
} acfp_corpus_t;

/* Crash information */
typedef struct {
    char id[ACFP_MAX_CRASH_HASH_LEN];
    char crash_hash[ACFP_MAX_CRASH_HASH_LEN];
    acfp_crash_type_t type;
    acfp_severity_t severity;
    acfp_exploitability_t exploitability;
    char sanitizer_output[ACFP_MAX_SANITIZER_OUTPUT_LEN];
    char stack_trace[ACFP_MAX_STACK_TRACE_LEN];
    char input_path[ACFP_MAX_PATH_LEN];
    char minimized_path[ACFP_MAX_PATH_LEN];
    uint64_t exec_count;
    time_t first_seen;
    time_t last_seen;
    uint32_t occurrence_count;
    char target_name[256];
    char harness_name[256];
    acfp_backend_t backend;
    int signal_number;
    void *fault_address;
    void *pc_address;
    acfp_lifecycle_state_t state;
    char cwe_candidate[32];
    float cvss_score;
    char notes[4096];
} acfp_crash_info_t;

/* Fuzzer statistics */
typedef struct {
    uint64_t total_execs;
    uint64_t unique_inputs;
    uint64_t unique_crashes;
    uint64_t unique_hangs;
    uint64_t unique_timeouts;
    double execs_per_sec;
    double coverage_percent;
    size_t corpus_size;
    size_t current_input_size;
    time_t start_time;
    time_t last_update;
    char current_target[256];
    char current_harness[256];
    acfp_backend_t backend;
    bool running;
} acfp_stats_t;

/* Triage result */
typedef struct {
    bool is_crash;
    bool is_hang;
    bool is_timeout;
    acfp_crash_type_t crash_type;
    acfp_severity_t severity;
    acfp_exploitability_t exploitability;
    char crash_hash[ACFP_MAX_CRASH_HASH_LEN];
    char sanitizer_report[ACFP_MAX_SANITIZER_OUTPUT_LEN];
    char stack_trace[ACFP_MAX_STACK_TRACE_LEN];
    int signal_number;
    void *fault_address;
    void *pc_address;
    char cwe_candidate[32];
    float cvss_score;
    char exploitability_summary[1024];
    char remediation_recommendation[2048];
} acfp_triage_result_t;

/* Target information */
typedef struct {
    char name[256];
    char description[1024];
    char version[64];
    char git_commit[64];
    char build_config[512];
    char binary_path[ACFP_MAX_PATH_LEN];
    char harness_path[ACFP_MAX_PATH_LEN];
    char seed_corpus_path[ACFP_MAX_PATH_LEN];
    char dictionary_path[ACFP_MAX_PATH_LEN];
    acfp_backend_t backend;
    bool uses_sanitizers;
    bool persistent_mode;
    bool fork_server;
    int timeout_ms;
    char dangerous_functions[1024]; /* Detected dangerous functions */
    char attack_surface[4096];      /* Attack surface report */
} acfp_target_t;

/* Job configuration */
typedef struct {
    char id[64];
    char name[256];
    acfp_target_t target;
    acfp_backend_t backend;
    int parallel_jobs;
    int timeout_ms;
    int memory_limit_mb;
    bool use_asan;
    bool use_ubsan;
    bool use_lsan;
    bool minimize_crashes;
    bool deterministic_first;
    int havoc_cycles;
    time_t created;
    time_t started;
    time_t finished;
    acfp_lifecycle_state_t state;
} acfp_job_t;

/* CWE mapping */
typedef struct {
    const char *cwe_id;
    const char *name;
    const char *description;
    acfp_crash_type_t crash_type;
} acfp_cwe_mapping_t;

/* CVSS estimation data */
typedef struct {
    float attack_vector;
    float attack_complexity;
    float privileges_required;
    float user_interaction;
    float scope;
    float confidentiality;
    float integrity;
    float availability;
    float base_score;
} acfp_cvss_data_t;

/* Function prototypes - Core fuzzer */
int acfp_init(void);
void acfp_cleanup(void);
int acfp_fuzz_iteration(acfp_input_t *input, acfp_triage_result_t *result);
int acfp_mutate_input(acfp_input_t *input, acfp_mutation_t mutation);
uint32_t acfp_compute_coverage_checksum(acfp_coverage_t *coverage);
int acfp_compare_coverage(acfp_coverage_t *old, acfp_coverage_t *new);

/* Function prototypes - Corpus management */
int acfp_corpus_init(acfp_corpus_t *corpus, const char *base_path);
int acfp_corpus_add(acfp_corpus_t *corpus, const uint8_t *data, size_t len);
int acfp_corpus_minimize(acfp_corpus_t *corpus);
acfp_corpus_entry_t *acfp_corpus_select(acfp_corpus_t *corpus);
void acfp_corpus_cleanup(acfp_corpus_t *corpus);

/* Function prototypes - Crash handling */
int acfp_crash_save(const acfp_crash_info_t *crash, const char *output_dir);
int acfp_crash_load(acfp_crash_info_t *crash, const char *crash_file);
char *acfp_crash_compute_hash(const acfp_crash_info_t *crash);
bool acfp_crash_is_duplicate(const acfp_crash_info_t *existing, 
                             const acfp_crash_info_t *new_crash);

/* Function prototypes - Triage */
int acfp_triage_crash(const char *crash_input_path, 
                      const char *binary_path,
                      acfp_triage_result_t *result);
acfp_exploitability_t acfp_assess_exploitability(acfp_crash_type_t type,
                                                  const char *sanitizer_output);
const char *acfp_crash_type_to_string(acfp_crash_type_t type);
const char *acfp_severity_to_string(acfp_severity_t severity);
const char *acfp_exploitability_to_string(acfp_exploitability_t expl);

/* Function prototypes - Dictionary */
int acfp_dictionary_load(acfp_dictionary_t *dict, const char *path);
int acfp_dictionary_add(acfp_dictionary_t *dict, const uint8_t *data, size_t len);
const acfp_dict_entry_t *acfp_dictionary_select(acfp_dictionary_t *dict);

/* Function prototypes - Statistics */
void acfp_stats_init(acfp_stats_t *stats);
void acfp_stats_update_exec(acfp_stats_t *stats);
void acfp_stats_update_crash(acfp_stats_t *stats);
void acfp_stats_update_hang(acfp_stats_t *stats);

/* Function prototypes - Storage/Database */
int acfp_db_init(const char *db_path);
int acfp_db_save_crash(const acfp_crash_info_t *crash);
int acfp_db_save_job(const acfp_job_t *job);
int acfp_db_update_lifecycle(const char *crash_id, acfp_lifecycle_state_t state);
int acfp_db_close(void);

/* Function prototypes - Report generation */
int acfp_report_generate_cve_ready(const acfp_crash_info_t *crash,
                                   const acfp_target_t *target,
                                   const char *output_path);
int acfp_report_generate_markdown(const acfp_crash_info_t *crash,
                                  const char *output_path);
int acfp_report_generate_json(const acfp_crash_info_t *crash,
                              const char *output_path);

/* Utility functions */
uint64_t acfp_get_time_ms(void);
uint32_t acfp_hash_buffer(const uint8_t *data, size_t len);
int acfp_read_file(const char *path, uint8_t **data, size_t *len);
int acfp_write_file(const char *path, const uint8_t *data, size_t len);
char *acfp_strdup(const char *str);
void acfp_safe_strcpy(char *dest, const char *src, size_t dest_size);

#endif /* ACFP_H */
