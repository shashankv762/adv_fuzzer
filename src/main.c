/**
 * @file main.c
 * @brief Main entry point for ACFP fuzzer
 * 
 * Command-line interface for running fuzzing campaigns.
 */

#include "acfp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

/* Global dictionary - declared extern in header, defined here */
extern acfp_dictionary_t g_dictionary;

/* External function from core.c */
extern uint32_t acfp_rand_range(uint32_t max);
#define rand_range(x) acfp_rand_range(x)

/* Global state */
static volatile int g_running = 1;
static acfp_stats_t g_stats;
static acfp_corpus_t g_corpus;

/* Signal handler */
static void signal_handler(int sig)
{
    (void)sig;
    printf("\nReceived signal, shutting down...\n");
    g_running = 0;
}

/* Print usage */
static void print_usage(const char *prog)
{
    printf("Advanced C Fuzzing Platform (ACFP) v%s\n", ACFP_VERSION_STRING);
    printf("\nUsage: %s [options] <target_binary>\n", prog);
    printf("\nOptions:\n");
    printf("  -i, --input <dir>     Input corpus directory\n");
    printf("  -o, --output <dir>    Output directory for crashes/corpus\n");
    printf("  -d, --dict <file>     Dictionary file\n");
    printf("  -t, --timeout <ms>    Timeout in milliseconds (default: 1000)\n");
    printf("  -m, --memory <MB>     Memory limit in MB (default: 256)\n");
    printf("  -j, --jobs <n>        Parallel jobs (default: 1)\n");
    printf("  -T, --time <sec>      Total fuzzing time in seconds\n");
    printf("  -B, --backend <name>  Backend: native, aflpp, libfuzzer (default: native)\n");
    printf("  -S, --sanitizers      Enable sanitizers (ASAN, UBSAN)\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Show this help\n");
    printf("\nExample:\n");
    printf("  %s -i corpus/seeds -o output -t 500 ./target_binary\n", prog);
}

int main(int argc, char *argv[])
{
    /* Default options */
    const char *input_dir = NULL;
    const char *output_dir = "./output";
    const char *dict_file = NULL;
    const char *target_binary = NULL;
    int timeout_ms = 1000;
    int memory_limit_mb = 256;
    int parallel_jobs = 1;
    int total_time_sec = 0;
    int verbose = 0;
    acfp_backend_t backend = ACFP_BACKEND_NATIVE;
    bool use_sanitizers = false;
    
    /* Parse options */
    static struct option long_options[] = {
        {"input",    required_argument, 0, 'i'},
        {"output",   required_argument, 0, 'o'},
        {"dict",     required_argument, 0, 'd'},
        {"timeout",  required_argument, 0, 't'},
        {"memory",   required_argument, 0, 'm'},
        {"jobs",     required_argument, 0, 'j'},
        {"time",     required_argument, 0, 'T'},
        {"backend",  required_argument, 0, 'B'},
        {"sanitizers", no_argument,     0, 'S'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:d:t:m:j:T:B:Svh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                input_dir = optarg;
                break;
            case 'o':
                output_dir = optarg;
                break;
            case 'd':
                dict_file = optarg;
                break;
            case 't':
                timeout_ms = atoi(optarg);
                break;
            case 'm':
                memory_limit_mb = atoi(optarg);
                break;
            case 'j':
                parallel_jobs = atoi(optarg);
                break;
            case 'T':
                total_time_sec = atoi(optarg);
                break;
            case 'B':
                if (strcmp(optarg, "aflpp") == 0) {
                    backend = ACFP_BACKEND_AFLPP;
                } else if (strcmp(optarg, "libfuzzer") == 0) {
                    backend = ACFP_BACKEND_LIBFUZZER;
                } else {
                    backend = ACFP_BACKEND_NATIVE;
                }
                break;
            case 'S':
                use_sanitizers = true;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    /* Get target binary */
    if (optind >= argc) {
        fprintf(stderr, "Error: No target binary specified\n");
        print_usage(argv[0]);
        return 1;
    }
    target_binary = argv[optind];
    
    /* Validate input directory */
    if (!input_dir) {
        fprintf(stderr, "Error: Input corpus directory required (-i)\n");
        print_usage(argv[0]);
        return 1;
    }
    
    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("ACFP Fuzzer v%s starting...\n", ACFP_VERSION_STRING);
    printf("Target: %s\n", target_binary);
    printf("Input: %s\n", input_dir);
    printf("Output: %s\n", output_dir);
    printf("Timeout: %dms, Memory: %dMB, Jobs: %d\n", 
           timeout_ms, memory_limit_mb, parallel_jobs);
    printf("Backend: %s\n", 
           backend == ACFP_BACKEND_AFLPP ? "AFL++" :
           backend == ACFP_BACKEND_LIBFUZZER ? "LibFuzzer" : "Native");
    if (use_sanitizers) {
        printf("Sanitizers: ENABLED\n");
    }
    printf("\n");
    
    /* Initialize engine */
    if (acfp_init() != 0) {
        fprintf(stderr, "Failed to initialize fuzzer\n");
        return 1;
    }
    
    /* Initialize corpus */
    if (acfp_corpus_init(&g_corpus, output_dir) != 0) {
        fprintf(stderr, "Failed to initialize corpus\n");
        acfp_cleanup();
        return 1;
    }
    
    /* Load dictionary if provided */
    if (dict_file) {
        if (acfp_dictionary_load(&g_dictionary, dict_file) != 0) {
            fprintf(stderr, "Warning: Failed to load dictionary from %s\n", dict_file);
        } else {
            printf("Loaded dictionary with %zu entries\n", g_dictionary.count);
        }
    }
    
    /* Initialize statistics */
    acfp_stats_init(&g_stats);
    g_stats.running = true;
    acfp_safe_strcpy(g_stats.current_target, target_binary, sizeof(g_stats.current_target));
    g_stats.backend = backend;
    
    printf("Fuzzer initialized. Press Ctrl+C to stop.\n\n");
    
    uint64_t start_time = acfp_get_time_ms();
    uint64_t last_stats_print = start_time;
    
    /* Main fuzzing loop */
    while (g_running) {
        /* Check time limit */
        if (total_time_sec > 0) {
            uint64_t elapsed = (acfp_get_time_ms() - start_time) / 1000;
            if (elapsed >= (uint64_t)total_time_sec) {
                printf("Time limit reached (%d seconds)\n", total_time_sec);
                break;
            }
        }
        
        /* Select input from corpus */
        acfp_corpus_entry_t *entry = acfp_corpus_select(&g_corpus);
        if (!entry) {
            /* No corpus yet, create initial input */
            uint8_t initial_data[256];
            for (int i = 0; i < 256; i++) {
                initial_data[i] = (uint8_t)i;
            }
            acfp_corpus_add(&g_corpus, initial_data, sizeof(initial_data));
            continue;
        }
        
        /* Create working copy */
        acfp_input_t input;
        input.data = malloc(entry->len + 1024);
        if (!input.data) {
            fprintf(stderr, "Memory allocation failed\n");
            break;
        }
        memcpy(input.data, entry->data, entry->len);
        input.len = entry->len;
        input.capacity = entry->len + 1024;
        
        /* Apply mutations */
        acfp_mutation_t mutation = rand_range(ACFP_MUT_COUNT);
        acfp_mutate_input(&input, mutation);
        
        /* Execute target (simplified - real implementation would run target) */
        /* For now, just update stats */
        acfp_stats_update_exec(&g_stats);
        
        /* Print periodic stats */
        uint64_t now = acfp_get_time_ms();
        if (now - last_stats_print >= 5000 && verbose) {
            printf("[Stats] Execs: %lu, Corpus: %zu, Crashes: %lu, Exec/s: %.1f\n",
                   (unsigned long)g_stats.total_execs,
                   g_corpus.count,
                   (unsigned long)g_stats.unique_crashes,
                   g_stats.execs_per_sec);
            last_stats_print = now;
        }
        
        free(input.data);
    }
    
    /* Final stats */
    printf("\n=== Fuzzing Complete ===\n");
    printf("Total executions: %lu\n", (unsigned long)g_stats.total_execs);
    printf("Unique inputs: %lu\n", (unsigned long)g_stats.unique_inputs);
    printf("Unique crashes: %lu\n", (unsigned long)g_stats.unique_crashes);
    printf("Corpus size: %zu\n", g_corpus.count);
    
    /* Cleanup */
    g_stats.running = false;
    acfp_corpus_cleanup(&g_corpus);
    acfp_cleanup();
    
    printf("Cleanup complete.\n");
    return 0;
}
