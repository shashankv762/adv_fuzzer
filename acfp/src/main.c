/*
 * ACFP - Advanced C Fuzzing Platform
 * Main Entry Point
 * 
 * Copyright (c) 2024 ACFP Project
 * Licensed under Apache License 2.0
 */

#include "acfp_fuzzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

static volatile int g_interrupted = 0;

void signal_handler(int sig) {
    (void)sig;
    g_interrupted = 1;
    printf("\n[*] Received interrupt signal, cleaning up...\n");
}

void print_usage(const char *prog) {
    printf("ACFP - Advanced C Fuzzing Platform v%s\n", ACFP_VERSION_STRING);
    printf("\nUsage: %s [options] <target> <corpus_dir>\n", prog);
    printf("\nOptions:\n");
    printf("  -o, --output DIR      Output directory for crashes and reports\n");
    printf("  -d, --dict FILE       Dictionary file for grammar-aware fuzzing\n");
    printf("  -t, --timeout MS      Timeout per execution in milliseconds (default: 1000)\n");
    printf("  -n, --iterations N    Number of iterations to run (default: 10000)\n");
    printf("  -s, --seed N          Random seed (default: time-based)\n");
    printf("  -m, --max-size N      Maximum input size in bytes (default: 65536)\n");
    printf("  -a, --afl             Use AFL++ backend\n");
    printf("  -l, --libfuzzer       Use LibFuzzer backend\n");
    printf("  -S, --sanitizers      Enable sanitizer support\n");
    printf("  -p, --parallel N      Number of parallel instances (default: 1)\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s ./target ./seeds\n", prog);
    printf("  %s -o ./output -n 100000 ./target ./seeds\n", prog);
    printf("  %s -a -o ./afl_output ./afl_target ./afl_seeds\n", prog);
    printf("\nFor authorized security research only.\n");
}

int main(int argc, char *argv[]) {
    acfp_config_t config = {0};
    int verbose = 0;
    
    /* Default configuration */
    config.timeout_ms = 1000;
    config.max_iterations = 10000;
    config.max_input_size = 65536;
    config.parallel_instances = 1;
    snprintf(config.output_dir, sizeof(config.output_dir), "./acfp_output");
    snprintf(config.seed_strategy, sizeof(config.seed_strategy), "random");

    /* Parse command line options */
    static struct option long_options[] = {
        {"output",     required_argument, 0, 'o'},
        {"dict",       required_argument, 0, 'd'},
        {"timeout",    required_argument, 0, 't'},
        {"iterations", required_argument, 0, 'n'},
        {"seed",       required_argument, 0, 's'},
        {"max-size",   required_argument, 0, 'm'},
        {"afl",        no_argument,       0, 'a'},
        {"libfuzzer",  no_argument,       0, 'l'},
        {"sanitizers", no_argument,       0, 'S'},
        {"parallel",   required_argument, 0, 'p'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "o:d:t:n:s:m:alSp:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'o':
                snprintf(config.output_dir, sizeof(config.output_dir), "%s", optarg);
                break;
            case 'd':
                snprintf(config.dict_file, sizeof(config.dict_file), "%s", optarg);
                break;
            case 't':
                config.timeout_ms = atoi(optarg);
                break;
            case 'n':
                config.max_iterations = strtoull(optarg, NULL, 10);
                break;
            case 's':
                srand(atoi(optarg));
                break;
            case 'm':
                config.max_input_size = atoi(optarg);
                break;
            case 'a':
                config.use_afl = true;
                break;
            case 'l':
                config.use_libfuzzer = true;
                break;
            case 'S':
                config.use_sanitizers = true;
                break;
            case 'p':
                config.parallel_instances = atoi(optarg);
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

    /* Check required arguments */
    if (optind >= argc) {
        fprintf(stderr, "Error: Target program not specified\n");
        print_usage(argv[0]);
        return 1;
    }

    if (optind + 1 >= argc) {
        fprintf(stderr, "Error: Corpus directory not specified\n");
        print_usage(argv[0]);
        return 1;
    }

    snprintf(config.target_path, sizeof(config.target_path), "%s", argv[optind]);
    snprintf(config.corpus_dir, sizeof(config.corpus_dir), "%s", argv[optind + 1]);

    /* Verify target exists */
    if (!acfp_file_exists(config.target_path)) {
        fprintf(stderr, "Error: Target program '%s' does not exist or is not accessible\n", 
                config.target_path);
        return 1;
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Print banner */
    printf("\n");
    printf("=================================================\n");
    printf("  ACFP - Advanced C Fuzzing Platform v%s\n", ACFP_VERSION_STRING);
    printf("  For authorized security research only\n");
    printf("=================================================\n\n");

    /* Initialize fuzzer */
    if (acfp_init(&config) != 0) {
        fprintf(stderr, "Error: Failed to initialize fuzzer\n");
        return 1;
    }

    if (verbose) {
        printf("[*] Configuration:\n");
        printf("    Target: %s\n", config.target_path);
        printf("    Corpus: %s\n", config.corpus_dir);
        printf("    Output: %s\n", config.output_dir);
        printf("    Timeout: %u ms\n", config.timeout_ms);
        printf("    Iterations: %lu\n", config.max_iterations);
        printf("    Max Input Size: %zu\n", config.max_input_size);
        if (config.use_afl) printf("    Backend: AFL++\n");
        if (config.use_libfuzzer) printf("    Backend: LibFuzzer\n");
        if (config.use_sanitizers) printf("    Sanitizers: Enabled\n");
        printf("\n");
    }

    /* Run fuzzing loop */
    int crashes_found = acfp_fuzz_loop(config.max_iterations);

    /* Cleanup */
    acfp_cleanup();

    /* Summary */
    printf("\n");
    printf("=================================================\n");
    printf("  FUZZING COMPLETE\n");
    printf("=================================================\n");
    
    acfp_stats_t *stats = acfp_stats_get();
    printf("Total Executions: %lu\n", stats->total_execs);
    printf("Unique Crashes: %lu\n", stats->unique_crashes);
    printf("Corpus Size: %lu\n", stats->corpus_size);
    printf("Executions/sec: %.2f\n", stats->execs_per_sec);
    printf("Coverage: %.2f%%\n", stats->coverage_percent);
    printf("\n");

    if (crashes_found > 0) {
        printf("[!] %d crash(es) found! Check %s/reports/ for details.\n", 
               crashes_found, config.output_dir);
    }

    return crashes_found > 0 ? 0 : 0;  /* Always return 0 unless internal error */
}
