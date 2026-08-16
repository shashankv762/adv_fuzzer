/*
 * ACFP - Advanced C Fuzzing Platform
 * Core Fuzzing Engine Implementation
 * 
 * Copyright (c) 2024 ACFP Project
 * Licensed under Apache License 2.0
 */

#include "acfp_fuzzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <libgen.h>
#include <signal.h>

/* Global state */
static acfp_config_t g_config;
static acfp_corpus_t *g_corpus = NULL;
static acfp_dictionary_t *g_dict = NULL;
static acfp_coverage_t *g_coverage = NULL;
static acfp_stats_t g_stats;
static bool g_initialized = false;

/* Interesting values for mutation strategies */
const int8_t acfp_interesting_8[] = {
    -128, -1, 0, 1, 16, 32, 64, 100, 127
};
const int16_t acfp_interesting_16[] = {
    -32768, -129, -1, 0, 1, 16, 32, 64, 100, 127, 128, 255, 256, 512, 1000, 1024, 4096, 32767
};
const int32_t acfp_interesting_32[] = {
    -2147483648, -1006301535, -536870912, -2147483647, -1000000000,
    -100000000, -10000000, -1000000, -100000, -10000, -1000, -100, -10,
    -2147483647, -32769, -129, -1, 0, 1, 16, 32, 64, 100, 127, 128,
    255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535, 65536,
    100000, 1000000, 10000000, 100000000, 1000000000, 2147483647
};
const size_t acfp_interesting_8_len = sizeof(acfp_interesting_8) / sizeof(acfp_interesting_8[0]);
const size_t acfp_interesting_16_len = sizeof(acfp_interesting_16) / sizeof(acfp_interesting_16[0]);
const size_t acfp_interesting_32_len = sizeof(acfp_interesting_32) / sizeof(acfp_interesting_32[0]);

/* Static function declarations */
static int acfp_execute_target(acfp_input_t *input, int *exit_code, char *stderr_buf, size_t stderr_size);
static bool acfp_is_crash(int exit_code, const char *stderr_output);
static void acfp_update_stats(void);

/* Initialize the fuzzer with configuration */
int acfp_init(const acfp_config_t *config) {
    if (!config) {
        fprintf(stderr, "Error: NULL configuration\n");
        return -1;
    }

    if (g_initialized) {
        fprintf(stderr, "Warning: Fuzzer already initialized, cleaning up\n");
        acfp_cleanup();
    }

    /* Copy configuration */
    memcpy(&g_config, config, sizeof(acfp_config_t));

    /* Create output directory */
    if (acfp_mkdir_p(g_config.output_dir) != 0) {
        fprintf(stderr, "Error: Failed to create output directory: %s\n", g_config.output_dir);
        return -1;
    }

    /* Initialize corpus */
    g_corpus = acfp_corpus_create(100);
    if (!g_corpus) {
        fprintf(stderr, "Error: Failed to create corpus\n");
        return -1;
    }

    /* Load seed corpus */
    if (acfp_corpus_load(g_corpus, g_config.corpus_dir) != 0) {
        fprintf(stderr, "Warning: Failed to load corpus from %s\n", g_config.corpus_dir);
        /* Continue with empty corpus - will generate random inputs */
    }

    /* Load dictionary if specified */
    if (g_config.dict_file[0] != '\0') {
        g_dict = acfp_dict_create();
        if (g_dict && acfp_dict_load(g_dict, g_config.dict_file) != 0) {
            fprintf(stderr, "Warning: Failed to load dictionary from %s\n", g_config.dict_file);
        }
    }

    /* Initialize coverage bitmap */
    g_coverage = acfp_coverage_create(65536);  /* 64KB coverage bitmap */
    if (!g_coverage) {
        fprintf(stderr, "Warning: Failed to create coverage bitmap\n");
    }

    /* Initialize statistics */
    memset(&g_stats, 0, sizeof(acfp_stats_t));
    g_stats.start_time = acfp_timestamp();
    g_stats.last_update = g_stats.start_time;
    snprintf(g_stats.backend, sizeof(g_stats.backend), "%s", 
             config->use_afl ? "AFL++" : (config->use_libfuzzer ? "LibFuzzer" : "native"));
    snprintf(g_stats.target, sizeof(g_stats.target), "%s", config->target_path);

    g_initialized = true;
    printf("[*] ACFP Fuzzer initialized\n");
    printf("[*] Target: %s\n", g_config.target_path);
    printf("[*] Corpus: %zu inputs loaded\n", g_corpus->count);
    printf("[*] Backend: %s\n", g_stats.backend);

    return 0;
}

/* Cleanup fuzzer resources */
void acfp_cleanup(void) {
    if (!g_initialized) {
        return;
    }

    if (g_corpus) {
        acfp_corpus_destroy(g_corpus);
        g_corpus = NULL;
    }

    if (g_dict) {
        acfp_dict_destroy(g_dict);
        g_dict = NULL;
    }

    if (g_coverage) {
        acfp_coverage_destroy(g_coverage);
        g_coverage = NULL;
    }

    g_initialized = false;
    printf("[*] Fuzzer cleanup complete\n");
}

/* Main fuzzing loop */
int acfp_fuzz_loop(uint64_t iterations) {
    if (!g_initialized) {
        fprintf(stderr, "Error: Fuzzer not initialized\n");
        return -1;
    }

    printf("[*] Starting fuzzing loop: %lu iterations\n", iterations);

    uint64_t crashes_found = 0;
    uint64_t interesting_found = 0;

    for (uint64_t i = 0; i < iterations; i++) {
        /* Select input from corpus */
        acfp_input_t *selected = acfp_corpus_select(g_corpus);
        if (!selected) {
            /* Create random input if corpus is empty */
            selected = acfp_input_create(ACFP_DEFAULT_INPUT_SIZE);
            if (!selected) {
                continue;
            }
            /* Fill with random data */
            for (size_t j = 0; j < selected->size; j++) {
                selected->data[j] = rand() % 256;
            }
        }

        /* Clone input for mutation */
        acfp_input_t *mutated = acfp_input_clone(selected);
        if (!mutated) {
            if (selected->filename == NULL) {
                acfp_input_destroy(selected);
            }
            continue;
        }

        /* Apply mutations */
        acfp_mutation_ctx_t ctx = {0};
        ctx.strategy = (acfp_mutation_t)(rand() % MUT_LAST);
        
        if (acfp_mutate(mutated, mutated, &ctx) != 0) {
            acfp_input_destroy(mutated);
            if (selected->filename == NULL) {
                acfp_input_destroy(selected);
            }
            continue;
        }

        /* Execute target with mutated input */
        int exit_code = 0;
        char stderr_buf[4096] = {0};
        
        if (acfp_execute_target(mutated, &exit_code, stderr_buf, sizeof(stderr_buf)) == 0) {
            g_stats.total_execs++;

            /* Check for crash */
            if (acfp_is_crash(exit_code, stderr_buf)) {
                crashes_found++;
                g_stats.unique_crashes++;

                /* Create crash info */
                acfp_crash_info_t crash = {0};
                snprintf(crash.target_name, sizeof(crash.target_name), "%s", g_config.target_path);
                snprintf(crash.sanitizer_output, sizeof(crash.sanitizer_output), "%s", stderr_buf);
                crash.type = acfp_crash_classify(stderr_buf);
                crash.severity = acfp_crash_severity(crash.type);
                crash.first_seen = acfp_timestamp();
                crash.last_seen = crash.first_seen;
                crash.occurrence_count = 1;
                crash.state = STATE_NEW;

                /* Generate crash hash for deduplication */
                acfp_crash_hash(&crash, stderr_buf);

                /* Save crash artifacts */
                acfp_crash_save(&crash, mutated);

                printf("\n[!] CRASH DETECTED: Type=%s, Hash=%s\n", 
                       acfp_crash_type_str(crash.type), crash.crash_hash);

                /* Generate report */
                char report_path[512];
                snprintf(report_path, sizeof(report_path), "%s/reports/crash_%s.md", 
                         g_config.output_dir, crash.crash_hash);
                acfp_report_generate_md(&crash, report_path);
            }

            /* Check if input is interesting (new coverage) */
            if (g_coverage && acfp_coverage_has_new(g_coverage, mutated->data, mutated->size)) {
                interesting_found++;
                mutated->interesting = true;
                
                /* Add to corpus if space available */
                if (g_corpus->count < ACFP_MAX_CORPUS_SIZE) {
                    acfp_corpus_add(g_corpus, mutated);
                    mutated = NULL;  /* Ownership transferred */
                }
            }
        }

        /* Cleanup */
        if (mutated) {
            acfp_input_destroy(mutated);
        }
        if (selected->filename == NULL) {
            acfp_input_destroy(selected);
        }

        /* Update stats periodically */
        if (i % 1000 == 0) {
            acfp_update_stats();
            printf("[*] Progress: %lu/%lu execs, %lu crashes, %lu interesting\n",
                   g_stats.total_execs, iterations, crashes_found, interesting_found);
        }
    }

    acfp_update_stats();
    printf("[*] Fuzzing loop complete: %lu total execs, %lu crashes found\n",
           g_stats.total_execs, crashes_found);

    return (int)crashes_found;
}

/* Execute single fuzzing iteration */
int acfp_fuzz_one(acfp_input_t *input) {
    if (!g_initialized || !input) {
        return -1;
    }

    int exit_code = 0;
    char stderr_buf[4096] = {0};

    if (acfp_execute_target(input, &exit_code, stderr_buf, sizeof(stderr_buf)) != 0) {
        return -1;
    }

    g_stats.total_execs++;

    if (acfp_is_crash(exit_code, stderr_buf)) {
        return 1;  /* Crash detected */
    }

    return 0;  /* No crash */
}

/* Execute target with input */
static int acfp_execute_target(acfp_input_t *input, int *exit_code, char *stderr_buf, size_t stderr_size) {
    if (!input || !exit_code || !stderr_buf) {
        return -1;
    }

    /* Create temporary file for input */
    char temp_path[] = "/tmp/acfp_fuzz_XXXXXX";
    int fd = mkstemp(temp_path);
    if (fd == -1) {
        perror("mkstemp");
        return -1;
    }

    /* Write input to temp file */
    if (write(fd, input->data, input->size) != (ssize_t)input->size) {
        perror("write");
        close(fd);
        unlink(temp_path);
        return -1;
    }
    close(fd);

    /* Setup pipes for stderr capture */
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        unlink(temp_path);
        return -1;
    }

    /* Fork and execute target */
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        unlink(temp_path);
        return -1;
    }

    if (pid == 0) {
        /* Child process */
        close(pipefd[0]);  /* Close read end */
        dup2(pipefd[1], STDERR_FILENO);  /* Redirect stderr */
        close(pipefd[1]);

        /* Execute target with input file as argument */
        execl(g_config.target_path, g_config.target_path, temp_path, NULL);
        _exit(127);  /* execl failed */
    }

    /* Parent process */
    close(pipefd[1]);  /* Close write end */

    /* Read stderr with timeout */
    fd_set readfds;
    struct timeval tv;
    tv.tv_sec = g_config.timeout_ms / 1000;
    tv.tv_usec = (g_config.timeout_ms % 1000) * 1000;

    FD_ZERO(&readfds);
    FD_SET(pipefd[0], &readfds);

    size_t stderr_offset = 0;
    int select_ret = select(pipefd[0] + 1, &readfds, NULL, NULL, &tv);

    if (select_ret > 0 && FD_ISSET(pipefd[0], &readfds)) {
        ssize_t n = read(pipefd[0], stderr_buf, stderr_size - 1);
        if (n > 0) {
            stderr_offset = (size_t)n;
            stderr_buf[stderr_offset] = '\0';
        }
    }

    close(pipefd[0]);

    /* Wait for child with timeout */
    int status;
    int wait_ret = waitpid(pid, &status, WNOHANG);
    
    if (wait_ret == 0) {
        /* Timeout - kill child */
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        *exit_code = -1;  /* Timeout indicator */
        snprintf(stderr_buf + stderr_offset, stderr_size - stderr_offset, 
                 "\nTimeout after %zu ms", g_config.timeout_ms);
    } else if (wait_ret > 0) {
        if (WIFEXITED(status)) {
            *exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            *exit_code = 128 + WTERMSIG(status);
        } else {
            *exit_code = -1;
        }
    } else {
        *exit_code = -1;
    }

    /* Cleanup temp file */
    unlink(temp_path);

    return 0;
}

/* Check if execution resulted in a crash */
static bool acfp_is_crash(int exit_code, const char *stderr_output) {
    /* Non-zero exit code indicates potential crash */
    if (exit_code != 0) {
        return true;
    }

    /* Check stderr for sanitizer output */
    if (stderr_output && strlen(stderr_output) > 0) {
        if (strstr(stderr_output, "ERROR:") != NULL ||
            strstr(stderr_output, "ASAN") != NULL ||
            strstr(stderr_output, "UBSAN") != NULL ||
            strstr(stderr_output, "MSAN") != NULL ||
            strstr(stderr_output, "LSAN") != NULL ||
            strstr(stderr_output, "runtime error") != NULL) {
            return true;
        }
    }

    return false;
}

/* Update statistics */
static void acfp_update_stats(void) {
    uint64_t now = acfp_timestamp();
    uint64_t elapsed = now - g_stats.start_time;

    g_stats.last_update = now;
    g_stats.corpus_size = g_corpus ? g_corpus->count : 0;
    g_stats.interesting_inputs = g_corpus ? g_corpus->current_interesting : 0;

    if (elapsed > 0) {
        g_stats.execs_per_sec = (double)g_stats.total_execs / elapsed;
    }

    if (g_coverage) {
        g_stats.coverage_percent = acfp_coverage_percent(g_coverage);
    }
}

/* Get current statistics */
acfp_stats_t *acfp_stats_get(void) {
    acfp_update_stats();
    return &g_stats;
}

/* Update statistics (public wrapper) */
void acfp_stats_update(void) {
    acfp_update_stats();
}

/* Get current timestamp in seconds since epoch */
uint64_t acfp_timestamp(void) {
    return (uint64_t)time(NULL);
}

/* Compute SHA256-like hash of buffer (simplified implementation) */
void acfp_hash_buffer(const uint8_t *data, size_t size, char *hash_out) {
    /* Simple DJB2 hash for demonstration - replace with proper SHA256 in production */
    uint32_t hash = 5381;
    
    for (size_t i = 0; i < size; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }

    /* Convert to hex string */
    for (int i = 0; i < 8; i++) {
        sprintf(hash_out + (i * 2), "%02x", (hash >> (i * 4)) & 0xFF);
    }
    hash_out[16] = '\0';
}

/* Duplicate string safely */
char *acfp_strdup(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, str, len);
    }
    return dup;
}

/* Create directory path recursively */
int acfp_mkdir_p(const char *path) {
    if (!path || path[0] == '\0') {
        return -1;
    }

    char *path_copy = acfp_strdup(path);
    if (!path_copy) {
        return -1;
    }

    char *p = path_copy;
    
    /* Skip leading slash */
    if (*p == '/') p++;

    while (*p) {
        while (*p && *p != '/') p++;
        
        if (*p == '/') {
            *p = '\0';
            
            if (mkdir(path_copy, 0755) != 0 && errno != EEXIST) {
                free(path_copy);
                return -1;
            }
            
            *p = '/';
            p++;
        }
    }

    /* Create final component */
    if (mkdir(path_copy, 0755) != 0 && errno != EEXIST) {
        free(path_copy);
        return -1;
    }

    free(path_copy);
    return 0;
}

/* Check if file exists */
bool acfp_file_exists(const char *path) {
    if (!path) return false;
    
    struct stat st;
    return stat(path, &st) == 0;
}

/* Get file size */
size_t acfp_file_size(const char *path) {
    if (!path) return 0;
    
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return st.st_size;
}

/* Read entire file into buffer */
int acfp_read_file(const char *path, uint8_t **buf, size_t *size) {
    if (!path || !buf || !size) {
        return -1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0) {
        fclose(f);
        return -1;
    }

    *buf = malloc(fsize);
    if (!*buf) {
        fclose(f);
        return -1;
    }

    size_t read_size = fread(*buf, 1, fsize, f);
    fclose(f);

    *size = read_size;
    return 0;
}

/* Write buffer to file */
int acfp_write_file(const char *path, const uint8_t *buf, size_t size) {
    if (!path || !buf) {
        return -1;
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }

    size_t written = fwrite(buf, 1, size, f);
    fclose(f);

    return (written == size) ? 0 : -1;
}
