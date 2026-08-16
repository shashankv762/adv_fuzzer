/**
 * @file core.c
 * @brief Core fuzzing engine implementation
 * 
 * This implements the main coverage-guided fuzzing loop with
 * mutation operators, crash detection, and corpus management.
 */

#include "acfp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <limits.h>

/* MIN macro */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* Global state */
acfp_coverage_t g_coverage;
acfp_dictionary_t g_dictionary;
static bool g_initialized = false;

/* Interesting values for mutations */
static const int32_t g_interesting_values[] = {
    0, 1, -1, 100, 1000, INT8_MIN, INT8_MAX,
    INT16_MIN, INT16_MAX, INT32_MIN, INT32_MAX,
    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF
};
#define NUM_INTERESTING_VALUES (sizeof(g_interesting_values) / sizeof(g_interesting_values[0]))

/* Random number generator state */
static uint32_t g_rand_state;

/**
 * @brief Initialize the random number generator
 */
static void init_rng(uint32_t seed)
{
    g_rand_state = seed ? seed : (uint32_t)time(NULL);
}

/**
 * @brief Generate a pseudo-random number
 */
static uint32_t rand_uint32(void)
{
    /* xorshift32 */
    g_rand_state ^= g_rand_state << 13;
    g_rand_state ^= g_rand_state >> 17;
    g_rand_state ^= g_rand_state << 5;
    return g_rand_state;
}

/**
 * @brief Get random number in range [0, max)
 */
uint32_t acfp_rand_range(uint32_t max)
{
    if (max == 0) return 0;
    return rand_uint32() % max;
}

static uint32_t rand_range(uint32_t max)
{
    return acfp_rand_range(max);
}

/**
 * @brief Get current time in milliseconds
 */
uint64_t acfp_get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

/**
 * @brief Hash a buffer using DJB2 algorithm
 */
uint32_t acfp_hash_buffer(const uint8_t *data, size_t len)
{
    uint32_t hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

/**
 * @brief Duplicate a string safely
 */
char *acfp_strdup(const char *str)
{
    if (!str) return NULL;
    size_t len = strlen(str) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, str, len);
    }
    return dup;
}

/**
 * @brief Safe string copy
 */
void acfp_safe_strcpy(char *dest, const char *src, size_t dest_size)
{
    if (!dest || !src || dest_size == 0) return;
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

/**
 * @brief Read file contents into buffer
 */
int acfp_read_file(const char *path, uint8_t **data, size_t *len)
{
    if (!path || !data || !len) return -1;
    
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size < 0 || size > ACFP_MAX_INPUT_SIZE) {
        fclose(f);
        return -1;
    }
    
    *data = malloc((size_t)size);
    if (!*data) {
        fclose(f);
        return -1;
    }
    
    size_t read_size = fread(*data, 1, (size_t)size, f);
    fclose(f);
    
    if (read_size != (size_t)size) {
        free(*data);
        *data = NULL;
        return -1;
    }
    
    *len = (size_t)size;
    return 0;
}

/**
 * @brief Write buffer to file
 */
int acfp_write_file(const char *path, const uint8_t *data, size_t len)
{
    if (!path || !data) return -1;
    
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    
    return (written == len) ? 0 : -1;
}

/**
 * @brief Initialize the fuzzing engine
 */
int acfp_init(void)
{
    if (g_initialized) {
        return 0;
    }
    
    /* Initialize RNG */
    init_rng(0);
    
    /* Clear coverage map */
    memset(&g_coverage, 0, sizeof(g_coverage));
    
    /* Initialize dictionary */
    memset(&g_dictionary, 0, sizeof(g_dictionary));
    
    g_initialized = true;
    return 0;
}

/**
 * @brief Cleanup the fuzzing engine
 */
void acfp_cleanup(void)
{
    if (!g_initialized) return;
    
    /* Clean up dictionary entries if needed */
    memset(&g_dictionary, 0, sizeof(g_dictionary));
    memset(&g_coverage, 0, sizeof(g_coverage));
    
    g_initialized = false;
}

/**
 * @brief Compute checksum of coverage map
 */
uint32_t acfp_compute_coverage_checksum(acfp_coverage_t *coverage)
{
    if (!coverage) return 0;
    
    uint32_t checksum = 0;
    for (size_t i = 0; i < ACFP_COVERAGE_MAP_SIZE; i++) {
        if (coverage->map[i]) {
            checksum ^= (uint32_t)(i * coverage->map[i]);
        }
    }
    coverage->checksum = checksum;
    return checksum;
}

/**
 * @brief Compare two coverage maps
 * @return 1 if new coverage found, 0 otherwise
 */
int acfp_compare_coverage(acfp_coverage_t *old, acfp_coverage_t *new_cov)
{
    if (!old || !new_cov) return 0;
    
    int new_coverage = 0;
    for (size_t i = 0; i < ACFP_COVERAGE_MAP_SIZE; i++) {
        if (new_cov->map[i] && !old->map[i]) {
            new_coverage = 1;
            old->map[i] = new_cov->map[i];
        }
    }
    
    if (new_coverage) {
        acfp_compute_coverage_checksum(old);
    }
    
    return new_coverage;
}

/**
 * @brief Bitflip mutation
 */
static int mutate_bitflip(acfp_input_t *input)
{
    if (!input || input->len == 0) return -1;
    
    size_t pos = rand_range(input->len);
    uint8_t bit = 1 << rand_range(8);
    input->data[pos] ^= bit;
    return 0;
}

/**
 * @brief Byte flip mutation
 */
static int mutate_byteflip(acfp_input_t *input)
{
    if (!input || input->len == 0) return -1;
    
    size_t pos = rand_range(input->len);
    input->data[pos] = rand_range(256);
    return 0;
}

/**
 * @brief Arithmetic mutation
 */
static int mutate_arithmetic(acfp_input_t *input)
{
    if (!input || input->len < 2) return -1;
    
    size_t pos = rand_range(input->len - 1);
    int delta = (int)rand_range(71) - 35; /* -35 to +35 */
    
    if (rand_range(2)) {
        /* 16-bit arithmetic */
        if (pos + 1 < input->len) {
            int16_t val = (int16_t)(input->data[pos] | (input->data[pos + 1] << 8));
            val += (int16_t)delta;
            input->data[pos] = (uint8_t)(val & 0xFF);
            input->data[pos + 1] = (uint8_t)((val >> 8) & 0xFF);
        }
    } else {
        /* 8-bit arithmetic */
        int8_t val = (int8_t)input->data[pos];
        val += (int8_t)delta;
        input->data[pos] = (uint8_t)val;
    }
    
    return 0;
}

/**
 * @brief Insert interesting value
 */
static int mutate_interesting(acfp_input_t *input)
{
    if (!input || input->len < 4) return -1;
    
    size_t pos = rand_range(input->len - 3);
    int32_t val = g_interesting_values[rand_range(NUM_INTERESTING_VALUES)];
    
    /* Choose size: 1, 2, or 4 bytes */
    int size_choice = rand_range(3);
    if (size_choice == 0 && pos < input->len) {
        input->data[pos] = (uint8_t)(val & 0xFF);
    } else if (size_choice == 1 && pos + 1 < input->len) {
        input->data[pos] = (uint8_t)(val & 0xFF);
        input->data[pos + 1] = (uint8_t)((val >> 8) & 0xFF);
    } else if (pos + 3 < input->len) {
        input->data[pos] = (uint8_t)(val & 0xFF);
        input->data[pos + 1] = (uint8_t)((val >> 8) & 0xFF);
        input->data[pos + 2] = (uint8_t)((val >> 16) & 0xFF);
        input->data[pos + 3] = (uint8_t)((val >> 24) & 0xFF);
    }
    
    return 0;
}

/**
 * @brief Block duplication mutation
 */
static int mutate_block_dup(acfp_input_t *input)
{
    if (!input || input->len < 2 || input->len >= ACFP_MAX_INPUT_SIZE / 2) return -1;
    
    size_t from = rand_range(input->len);
    size_t len = rand_range(MIN(input->len - from, MIN(128, ACFP_MAX_INPUT_SIZE - input->len)));
    if (len == 0) len = 1;
    
    size_t to = rand_range(input->len + 1);
    
    /* Make room */
    if (input->len + len > input->capacity) {
        size_t new_cap = input->capacity * 2;
        uint8_t *new_data = realloc(input->data, new_cap);
        if (!new_data) return -1;
        input->data = new_data;
        input->capacity = new_cap;
    }
    
    /* Move data and insert duplicate */
    memmove(input->data + to + len, input->data + to, input->len - to);
    memcpy(input->data + to, input->data + from, len);
    input->len += len;
    
    return 0;
}

/**
 * @brief Block deletion mutation
 */
static int mutate_block_del(acfp_input_t *input)
{
    if (!input || input->len <= 1) return -1;
    
    size_t from = rand_range(input->len);
    size_t len = rand_range(MIN(input->len - from, 128));
    if (len == 0) len = 1;
    
    memmove(input->data + from, input->data + from + len, input->len - from - len);
    input->len -= len;
    
    return 0;
}

/**
 * @brief Splicing mutation (combines two inputs)
 */
static int mutate_splice(acfp_input_t *input, acfp_corpus_t *corpus)
{
    if (!input || !corpus || corpus->count == 0) return -1;
    
    /* Select another corpus entry */
    acfp_corpus_entry_t *other = acfp_corpus_select(corpus);
    if (!other || other->len == 0) return -1;
    
    size_t cut1 = rand_range(input->len);
    size_t cut2 = rand_range(other->len);
    
    size_t new_len = cut1 + (other->len - cut2);
    if (new_len > input->capacity || new_len > ACFP_MAX_INPUT_SIZE) return -1;
    
    memcpy(input->data + cut1, other->data + cut2, other->len - cut2);
    input->len = cut1 + (other->len - cut2);
    
    return 0;
}

/**
 * @brief Dictionary-based mutation
 */
static int mutate_dictionary(acfp_input_t *input, acfp_dictionary_t *dict)
{
    if (!input || !dict || dict->count == 0) return -1;
    
    const acfp_dict_entry_t *entry = acfp_dictionary_select(dict);
    if (!entry || entry->len == 0) return -1;
    
    size_t pos = rand_range(input->len + 1);
    size_t remaining = input->len - pos;
    
    /* Make room if needed */
    if (input->len + entry->len > input->capacity) {
        size_t new_cap = input->capacity * 2;
        if (new_cap < input->len + entry->len) {
            new_cap = input->len + entry->len + 1024;
        }
        uint8_t *new_data = realloc(input->data, new_cap);
        if (!new_data) return -1;
        input->data = new_data;
        input->capacity = new_cap;
    }
    
    /* Insert dictionary entry */
    if (remaining >= entry->len) {
        /* Overwrite */
        memcpy(input->data + pos, entry->data, entry->len);
    } else {
        /* Insert */
        memmove(input->data + pos + entry->len, input->data + pos, remaining);
        memcpy(input->data + pos, entry->data, entry->len);
        input->len += entry->len;
    }
    
    return 0;
}

/**
 * @brief Havoc mutation (multiple random mutations)
 */
static int mutate_havoc(acfp_input_t *input, acfp_dictionary_t *dict, acfp_corpus_t *corpus)
{
    if (!input) return -1;
    
    int num_mutations = (int)rand_range(6) + 1; /* 1-6 mutations */
    
    for (int i = 0; i < num_mutations; i++) {
        acfp_mutation_t mut = rand_range(ACFP_MUT_COUNT);
        switch (mut) {
            case ACFP_MUT_BITFLIP:
                mutate_bitflip(input);
                break;
            case ACFP_MUT_BYTEFLIP:
                mutate_byteflip(input);
                break;
            case ACFP_MUT_ARITHMETIC:
                mutate_arithmetic(input);
                break;
            case ACFP_MUT_INTERESTING_VALUE:
                mutate_interesting(input);
                break;
            case ACFP_MUT_BLOCK_DUPLICATION:
                mutate_block_dup(input);
                break;
            case ACFP_MUT_BLOCK_DELETION:
                mutate_block_del(input);
                break;
            case ACFP_MUT_SPLICING:
                mutate_splice(input, corpus);
                break;
            case ACFP_MUT_DICTIONARY:
                mutate_dictionary(input, dict);
                break;
            default:
                mutate_bitflip(input);
                break;
        }
    }
    
    return 0;
}

/**
 * @brief Apply a mutation to input
 */
int acfp_mutate_input(acfp_input_t *input, acfp_mutation_t mutation)
{
    if (!input) return -1;
    
    switch (mutation) {
        case ACFP_MUT_BITFLIP:
            return mutate_bitflip(input);
        case ACFP_MUT_BYTEFLIP:
            return mutate_byteflip(input);
        case ACFP_MUT_ARITHMETIC:
            return mutate_arithmetic(input);
        case ACFP_MUT_INTERESTING_VALUE:
            return mutate_interesting(input);
        case ACFP_MUT_BLOCK_DUPLICATION:
            return mutate_block_dup(input);
        case ACFP_MUT_BLOCK_DELETION:
            return mutate_block_del(input);
        case ACFP_MUT_SPLICING:
            return mutate_splice(input, NULL);
        case ACFP_MUT_DICTIONARY:
            return mutate_dictionary(input, &g_dictionary);
        case ACFP_MUT_HAVOC:
            return mutate_havoc(input, &g_dictionary, NULL);
        default:
            return mutate_bitflip(input);
    }
}

/**
 * @brief Run target with input and detect crashes
 * @return 0 on normal exit, signal number on crash, -1 on error
 */
static int run_target(const char *binary_path, const uint8_t *input, size_t input_len,
                      int timeout_ms, int memory_limit_mb)
{
    if (!binary_path || !input) return -1;
    
    /* Create temporary input file */
    char tmpfile[] = "/tmp/acfp_input_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return -1;
    
    ssize_t written = write(fd, input, input_len);
    close(fd);
    
    if (written != (ssize_t)input_len) {
        unlink(tmpfile);
        return -1;
    }
    
    /* Fork and execute */
    pid_t pid = fork();
    if (pid < 0) {
        unlink(tmpfile);
        return -1;
    }
    
    if (pid == 0) {
        /* Child process */
        
        /* Set resource limits */
        if (memory_limit_mb > 0) {
            struct rlimit rl;
            rl.rlim_cur = (rlim_t)(memory_limit_mb * 1024 * 1024);
            rl.rlim_max = rl.rlim_cur;
            setrlimit(RLIMIT_AS, &rl);
        }
        
        /* Redirect stdin from temp file */
        freopen(tmpfile, "r", stdin);
        
        /* Execute target */
        execl(binary_path, binary_path, tmpfile, NULL);
        _exit(127);
    }
    
    /* Parent waits for child */
    int status = 0;
    struct timeval start, now;
    gettimeofday(&start, NULL);
    
    while (1) {
        pid_t result = waitpid(pid, &status, WNOHANG);
        
        if (result == pid) {
            /* Child finished */
            break;
        } else if (result < 0) {
            /* Error */
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            unlink(tmpfile);
            return -1;
        }
        
        /* Check timeout */
        gettimeofday(&now, NULL);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + 
                          (now.tv_usec - start.tv_usec) / 1000;
        
        if (timeout_ms > 0 && elapsed_ms > timeout_ms) {
            /* Timeout - kill child */
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            unlink(tmpfile);
            return -2; /* Timeout indicator */
        }
        
        usleep(1000); /* 1ms poll */
    }
    
    unlink(tmpfile);
    
    if (WIFEXITED(status)) {
        return 0; /* Normal exit */
    } else if (WIFSIGNALED(status)) {
        return WTERMSIG(status); /* Crash signal */
    }
    
    return -1;
}

/**
 * @brief Perform one fuzzing iteration
 */
int acfp_fuzz_iteration(acfp_input_t *input, acfp_triage_result_t *result)
{
    if (!input || !result || !g_initialized) return -1;
    
    /* Clear result */
    memset(result, 0, sizeof(*result));
    
    /* Run target */
    /* Note: binary_path should be configured externally */
    /* For now, this is a placeholder */
    
    return 0;
}

/* String conversion functions */
const char *acfp_crash_type_to_string(acfp_crash_type_t type)
{
    switch (type) {
        case ACFP_CRASH_HEAP_OVERFLOW: return "heap_overflow";
        case ACFP_CRASH_STACK_OVERFLOW: return "stack_overflow";
        case ACFP_CRASH_USE_AFTER_FREE: return "use_after_free";
        case ACFP_CRASH_DOUBLE_FREE: return "double_free";
        case ACFP_CRASH_OOB_READ: return "out_of_bounds_read";
        case ACFP_CRASH_OOB_WRITE: return "out_of_bounds_write";
        case ACFP_CRASH_NULL_DEREF: return "null_dereference";
        case ACFP_CRASH_INTEGER_OVERFLOW: return "integer_overflow";
        case ACFP_CRASH_UNINITIALIZED_MEM: return "uninitialized_memory";
        case ACFP_CRASH_DIVIDE_BY_ZERO: return "divide_by_zero";
        case ACFP_CRASH_ASSERTION_FAILURE: return "assertion_failure";
        case ACFP_CRASH_TIMEOUT: return "timeout";
        case ACFP_CRASH_HANG: return "hang";
        case ACFP_CRASH_LEAK: return "memory_leak";
        case ACFP_CRASH_UNDEFINED_BEHAVIOR: return "undefined_behavior";
        default: return "unknown";
    }
}

const char *acfp_severity_to_string(acfp_severity_t severity)
{
    switch (severity) {
        case ACFP_SEVERITY_INFO: return "info";
        case ACFP_SEVERITY_LOW: return "low";
        case ACFP_SEVERITY_MEDIUM: return "medium";
        case ACFP_SEVERITY_HIGH: return "high";
        case ACFP_SEVERITY_CRITICAL: return "critical";
        default: return "unknown";
    }
}

const char *acfp_exploitability_to_string(acfp_exploitability_t expl)
{
    switch (expl) {
        case ACFP_EXPLOIT_NOT_EXPLOITABLE: return "not_exploitable";
        case ACFP_EXPLOIT_PROBABLY_NOT_EXPLOITABLE: return "probably_not_exploitable";
        case ACFP_EXPLOIT_PROBABLY_EXPLOITABLE: return "probably_exploitable";
        case ACFP_EXPLOIT_EXPLOITABLE: return "exploitable";
        case ACFP_EXPLOIT_DOS_ONLY: return "dos_only";
        default: return "unknown";
    }
}
