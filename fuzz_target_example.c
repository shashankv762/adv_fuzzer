/**
 * CVE-FINDER: Example Fuzz Target Harness
 * 
 * This file demonstrates how to wrap a target library function
 * for fuzzing with CVE-Finder, AFL++, or LibFuzzer.
 * 
 * Replace the `target_function` implementation with your actual target.
 */

#include "cve_finder_core.h"
#include <string.h>

/* ============================================================================
 * TARGET FUNCTION SIMULATION
 * Replace this with the actual function you want to fuzz.
 * Example: A vulnerable parser, image decoder, network handler, etc.
 * ============================================================================ */

/**
 * @brief Example vulnerable function (DO NOT USE IN PRODUCTION)
 * 
 * This simulates a function that might have a buffer overflow or null deref.
 * In a real scenario, this would be your library code.
 */
int target_function(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    /* Simulate parsing logic */
    if (data[0] == 'F') {
        if (size > 5 && memcmp(data, "FUZZ", 4) == 0) {
            /* Potential bug trigger condition */
            if (size > 10 && data[5] == 0xFF) {
                /* Simulate a crash for demonstration */
                int *ptr = NULL;
                *ptr = 42; /* Null pointer dereference */
            }
        }
    }

    /* Simulate normal processing */
    volatile uint32_t sum = 0;
    for (size_t i = 0; i < size; i++) {
        sum += data[i];
    }

    return (int)(sum % 256);
}

/* ============================================================================
 * FUZZER ENTRY POINTS
 * ============================================================================ */

/**
 * @brief LibFuzzer Entry Point
 * 
 * When compiled with -fsanitize=fuzzer, this is the main entry.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Initialize framework if not already done (for standalone runs) */
    static int initialized = 0;
    if (!initialized) {
        /* In LibFuzzer mode, we often skip full init to avoid arg parsing conflicts */
        /* But we can set up basic logging if needed */
        initialized = 1;
    }

    /* Call the target function */
    target_function(data, size);

    return 0;
}

/**
 * @brief Standalone / AFL++ Main Entry
 * 
 * When compiled as a standalone binary or for AFL++ (without libfuzzer flag),
 * this reads from stdin or file and calls the harness.
 */
#ifndef __AFL_FUZZ_TEST_CASE_LEN
/* Standard main for non-persistent AFL modes or standalone testing */
int main(int argc, char **argv) {
    /* Initialize CVE-Finder Framework */
    if (cve_finder_init(argc, argv) != 0) {
        return 1;
    }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    /* Enable persistent mode for AFL++ */
    __AFL_INIT();
#endif

    uint8_t buf[MAX_INPUT_SIZE];
    size_t n;

    /* Read input */
#ifdef __AFL_FUZZ_TEST_CASE_BUF
    /* Persistent mode buffer */
    buf = __AFL_FUZZ_TEST_CASE_BUF;
    while (__AFL_LOOP(10000)) {
        n = __AFL_FUZZ_TEST_CASE_LEN;
        if (n > MAX_INPUT_SIZE) n = MAX_INPUT_SIZE;
        
        g_stats.total_execs++;
        LLVMFuzzerTestOneInput(buf, n);
    }
#else
    /* Stdin mode for standalone or simple AFL */
    while (1) {
        /* Simple read for demo - real impl should handle partial reads */
        n = fread(buf, 1, sizeof(buf), stdin);
        if (n == 0) break;

        g_stats.total_execs++;
        LLVMFuzzerTestOneInput(buf, n);
        
        /* In standalone mode, one input per run usually */
        break; 
    }
#endif

    cve_finder_shutdown();
    return 0;
}
#endif /* __AFL_FUZZ_TEST_CASE_LEN */
