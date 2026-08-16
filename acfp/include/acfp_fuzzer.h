/*
 * ACFP - Advanced C Fuzzing Platform
 * Core Fuzzing Engine Header
 * 
 * Copyright (c) 2024 ACFP Project
 * Licensed under Apache License 2.0
 */

#ifndef ACFP_FUZZER_H
#define ACFP_FUZZER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version information */
#define ACFP_VERSION_MAJOR 1
#define ACFP_VERSION_MINOR 0
#define ACFP_VERSION_PATCH 0
#define ACFP_VERSION_STRING "1.0.0"

/* Configuration constants */
#define ACFP_MAX_INPUT_SIZE (1024 * 1024)  /* 1 MB max input */
#define ACFP_DEFAULT_INPUT_SIZE 256
#define ACFP_MAX_CORPUS_SIZE 10000
#define ACFP_MAX_DICT_ENTRIES 1000
#define ACFP_MAX_DICT_ENTRY_SIZE 256
#define ACFP_HASH_SIZE 32
#define ACFP_CRASH_HASH_SIZE 16

/* Mutation strategies */
typedef enum {
    MUT_BIT_FLIP = 0,
    MUT_BYTE_FLIP,
    MUT_ARITHMETIC,
    MUT_INTERESTING_VALUE,
    MUT_BLOCK_DUPLICATION,
    MUT_BLOCK_DELETION,
    MUT_BLOCK_INSERTION,
    MUT_BLOCK_OVERWRITE,
    MUT_DICTIONARY_INSERT,
    MUT_DICTIONARY_OVERWRITE,
    MUT_RANDOM,
    MUT_SPLICE,
    MUT_LAST
} acfp_mutation_t;

/* Crash types detected by sanitizers */
typedef enum {
    CRASH_UNKNOWN = 0,
    CRASH_HEAP_OVERFLOW,
    CRASH_HEAP_UNDERFLOW,
    CRASH_STACK_OVERFLOW,
    CRASH_USE_AFTER_FREE,
    CRASH_DOUBLE_FREE,
    CRASH_OUT_OF_BOUNDS_READ,
    CRASH_OUT_OF_BOUNDS_WRITE,
    CRASH_NULL_DEREFERENCE,
    CRASH_INTEGER_OVERFLOW,
    CRASH_DIVIDE_BY_ZERO,
    CRASH_ASSERTION_FAILURE,
    CRASH_UNINITIALIZED_MEMORY,
    CRASH_MEMORY_LEAK,
    CRASH_TIMEOUT,
    CRASH_LAST
} acfp_crash_type_t;

/* Exploitability assessment */
typedef enum {
    EXPLOIT_NONE = 0,
    EXPLOIT_EXPLOITABLE,
    EXPLOIT_PROBABLY_EXPLOITABLE,
    EXPLOIT_UNKNOWN,
    EXPLOIT_PROBABLY_NOT,
    EXPLOIT_DOS_ONLY,
    EXPLOIT_LAST
} acfp_exploitability_t;

/* Crash lifecycle states */
typedef enum {
    STATE_NEW = 0,
    STATE_TRIAGED,
    STATE_CONFIRMED,
    STATE_EXPLOITABILITY_ASSESSED,
    STATE_PATCH_PROPOSED,
    STATE_PATCH_VERIFIED,
    STATE_DISCLOSED,
    STATE_REJECTED,
    STATE_ARCHIVED,
    STATE_LAST
} acfp_lifecycle_state_t;

/* Severity levels */
typedef enum {
    SEVERITY_INFO = 0,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
    SEVERITY_LAST
} acfp_severity_t;

/* Input buffer structure */
typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
    char *filename;
    uint64_t exec_count;
    bool interesting;
} acfp_input_t;

/* Corpus management */
typedef struct {
    acfp_input_t **inputs;
    size_t count;
    size_t capacity;
    uint64_t total_execs;
    size_t current_interesting;
} acfp_corpus_t;

/* Dictionary entry for grammar-aware fuzzing */
typedef struct {
    uint8_t *data;
    size_t size;
    uint64_t hit_count;
    bool active;
} acfp_dict_entry_t;

/* Dictionary for structure-aware fuzzing */
typedef struct {
    acfp_dict_entry_t **entries;
    size_t count;
    size_t capacity;
} acfp_dictionary_t;

/* Coverage bitmap for coverage-guided fuzzing */
typedef struct {
    uint8_t *bitmap;
    size_t size;
    uint64_t total_bits;
    uint64_t set_bits;
} acfp_coverage_t;

/* Crash information structure */
typedef struct {
    char id[64];
    char crash_hash[ACFP_CRASH_HASH_SIZE * 2 + 1];
    acfp_crash_type_t type;
    acfp_severity_t severity;
    acfp_exploitability_t exploitability;
    char target_name[256];
    char harness_name[256];
    char sanitizer_output[8192];
    char stack_trace[4096];
    char affected_function[256];
    char affected_file[512];
    int affected_line;
    char cwe_candidate[32];
    float cvss_score;
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t occurrence_count;
    acfp_lifecycle_state_t state;
    char reproducer_path[512];
    char minimized_path[512];
    char notes[1024];
} acfp_crash_info_t;

/* Fuzzer statistics */
typedef struct {
    uint64_t start_time;
    uint64_t last_update;
    uint64_t total_execs;
    uint64_t unique_crashes;
    uint64_t unique_hangs;
    uint64_t unique_timeouts;
    uint64_t corpus_size;
    uint64_t interesting_inputs;
    double execs_per_sec;
    double coverage_percent;
    uint32_t current_seed;
    char backend[64];
    char target[256];
} acfp_stats_t;

/* Fuzzer configuration */
typedef struct {
    char target_path[512];
    char corpus_dir[512];
    char output_dir[512];
    char dict_file[512];
    size_t max_input_size;
    size_t timeout_ms;
    size_t max_iterations;
    bool use_afl;
    bool use_libfuzzer;
    bool use_sanitizers;
    bool persistent_mode;
    bool fork_server;
    int parallel_instances;
    bool minimize_corpus;
    bool save_all_inputs;
    char seed_strategy[64];
} acfp_config_t;

/* Mutation context */
typedef struct {
    acfp_mutation_t strategy;
    int param1;
    int param2;
    void *extra_data;
    size_t extra_size;
} acfp_mutation_ctx_t;

/* Interesting values for mutation */
extern const int8_t acfp_interesting_8[];
extern const int16_t acfp_interesting_16[];
extern const int32_t acfp_interesting_32[];
extern const size_t acfp_interesting_8_len;
extern const size_t acfp_interesting_16_len;
extern const size_t acfp_interesting_32_len;

/* Function prototypes - Core fuzzer */
int acfp_init(const acfp_config_t *config);
void acfp_cleanup(void);
int acfp_fuzz_loop(uint64_t iterations);
int acfp_fuzz_one(acfp_input_t *input);

/* Function prototypes - Corpus management */
acfp_corpus_t *acfp_corpus_create(size_t initial_capacity);
void acfp_corpus_destroy(acfp_corpus_t *corpus);
int acfp_corpus_load(acfp_corpus_t *corpus, const char *dir);
int acfp_corpus_save(acfp_corpus_t *corpus, const char *dir);
int acfp_corpus_add(acfp_corpus_t *corpus, acfp_input_t *input);
int acfp_corpus_minimize(acfp_corpus_t *corpus);
acfp_input_t *acfp_corpus_select(acfp_corpus_t *corpus);

/* Function prototypes - Input manipulation */
acfp_input_t *acfp_input_create(size_t size);
void acfp_input_destroy(acfp_input_t *input);
int acfp_input_load(acfp_input_t *input, const char *path);
int acfp_input_save(acfp_input_t *input, const char *path);
acfp_input_t *acfp_input_clone(acfp_input_t *src);

/* Function prototypes - Mutations */
int acfp_mutate(acfp_input_t *src, acfp_input_t *dst, acfp_mutation_ctx_t *ctx);
int acfp_mutate_bit_flip(acfp_input_t *input);
int acfp_mutate_byte_flip(acfp_input_t *input);
int acfp_mutate_arithmetic(acfp_input_t *input);
int acfp_mutate_interesting(acfp_input_t *input);
int acfp_mutate_block_dup(acfp_input_t *input);
int acfp_mutate_block_del(acfp_input_t *input);
int acfp_mutate_block_insert(acfp_input_t *input);
int acfp_mutate_splice(acfp_input_t *input1, acfp_input_t *input2, acfp_input_t *dst);
int acfp_mutate_dictionary(acfp_input_t *input, acfp_dictionary_t *dict);

/* Function prototypes - Dictionary */
acfp_dictionary_t *acfp_dict_create(void);
void acfp_dict_destroy(acfp_dictionary_t *dict);
int acfp_dict_load(acfp_dictionary_t *dict, const char *path);
int acfp_dict_add(acfp_dictionary_t *dict, const uint8_t *data, size_t size);

/* Function prototypes - Coverage */
acfp_coverage_t *acfp_coverage_create(size_t size);
void acfp_coverage_destroy(acfp_coverage_t *cov);
int acfp_coverage_update(acfp_coverage_t *cov, const uint8_t *trace, size_t trace_size);
bool acfp_coverage_has_new(acfp_coverage_t *cov, const uint8_t *trace, size_t trace_size);
double acfp_coverage_percent(acfp_coverage_t *cov);

/* Function prototypes - Crash handling */
int acfp_crash_detect(int exit_code, const char *stderr_output);
acfp_crash_type_t acfp_crash_classify(const char *sanitizer_output);
acfp_severity_t acfp_crash_severity(acfp_crash_type_t type);
acfp_exploitability_t acfp_crash_exploitability(acfp_crash_info_t *crash);
int acfp_crash_hash(acfp_crash_info_t *crash, const char *stack_trace);
int acfp_crash_save(acfp_crash_info_t *crash, acfp_input_t *input);
int acfp_crash_minimize(acfp_crash_info_t *crash);
const char *acfp_crash_type_str(acfp_crash_type_t type);
const char *acfp_severity_str(acfp_severity_t sev);
const char *acfp_exploitability_str(acfp_exploitability_t exp);
const char *acfp_state_str(acfp_lifecycle_state_t state);

/* Function prototypes - CWE mapping */
const char *acfp_cwe_map(acfp_crash_type_t type);

/* Function prototypes - CVSS estimation */
float acfp_cvss_estimate(acfp_crash_info_t *crash);

/* Function prototypes - Statistics */
acfp_stats_t *acfp_stats_get(void);
void acfp_stats_update(void);

/* Function prototypes - AFL++ integration */
int acfp_afl_check(void);
int acfp_afl_build_target(const char *src, const char *out, const char *compiler);
int acfp_afl_fuzz(const char *target, const char *input_dir, const char *output_dir);
int acfp_afl_parse_stats(const char *stats_file, acfp_stats_t *stats);
int acfp_afl_import_corpus(const char *afl_dir, acfp_corpus_t *corpus);
int acfp_afl_export_corpus(acfp_corpus_t *corpus, const char *afl_dir);

/* Function prototypes - LibFuzzer integration */
int acfp_libfuzzer_check(void);
int acfp_libfuzzer_build_target(const char *src, const char *out, const char *sanitizers);
int acfp_libfuzzer_generate_harness(const char *api_sig, const char *out_file);
int acfp_libfuzzer_parse_crash(const char *crash_log, acfp_crash_info_t *crash);

/* Function prototypes - Report generation */
int acfp_report_generate_md(acfp_crash_info_t *crash, const char *out_path);
int acfp_report_generate_json(acfp_crash_info_t *crash, const char *out_path);
int acfp_report_generate_sarif(acfp_crash_info_t *crash, const char *out_path);
int acfp_report_generate_cve_draft(acfp_crash_info_t *crash, const char *out_path);

/* Utility functions */
uint64_t acfp_timestamp(void);
void acfp_hash_buffer(const uint8_t *data, size_t size, char *hash_out);
char *acfp_strdup(const char *str);
int acfp_mkdir_p(const char *path);
bool acfp_file_exists(const char *path);
size_t acfp_file_size(const char *path);
int acfp_read_file(const char *path, uint8_t **buf, size_t *size);
int acfp_write_file(const char *path, const uint8_t *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* ACFP_FUZZER_H */
