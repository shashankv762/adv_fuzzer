/*
 * AegisFuzz Enterprise - Coverage Instrumentation Hooks
 * 
 * This module interfaces with LLVM Sanitizers (ASan, UBSan, MSan)
 * and provides coverage feedback mechanisms compatible with AFL++
 * and LibFuzzer. It implements the __sanitizer_cov_* callbacks.
 *
 * Copyright (c) 2024 AegisFuzz Project. All rights reserved.
 * Licensed under the Apache License 2.0.
 */

#define _GNU_SOURCE  /* Required for shmat on Linux */

#include "aegis_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>

/* Global coverage map pointer */
static uint8_t *g_coverage_map = NULL;
static uint32_t g_coverage_map_size = AEGIS_MAP_SIZE;

/* Position-specific randomness for edge coverage */
static uint32_t g_prev_location = 0;

/* Sanitizer callback prototypes */
void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2);
void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2);
void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2);
void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2);
void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases);
void __sanitizer_cov_trace_div4(uint32_t Val);
void __sanitizer_cov_trace_div8(uint64_t Val);
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
void __sanitizer_cov_trace_pc_guard(uint32_t *guard);
void __sanitizer_cov_8bit_counters_init(char *start, char *stop);
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg, const uintptr_t *pcs_end);

/**
 * Initialize coverage mapping using AFL++ shared memory.
 * Reads __AFL_SHM_ID environment variable to attach to existing segment.
 */
aegis_status_t aegis_coverage_init(aegis_harness_t *harness)
{
    if (!harness) {
        return AEGIS_ERR_INVALID_ARG;
    }

    const char *shm_id_str = getenv(AEGIS_ENV_SHM_ID);
    
    if (shm_id_str) {
        /* Running under AFL++ - attach to existing shared memory */
        int shm_id = atoi(shm_id_str);
        
        g_coverage_map = (uint8_t *)shmat(shm_id, NULL, 0);
        if (g_coverage_map == (void *)-1) {
            AEGIS_LOG("Failed to attach to AFL++ shared memory (ID: %d)", shm_id);
            g_coverage_map = NULL;
            return AEGIS_ERR_SHM_FAILED;
        }
        
        harness->coverage_map = g_coverage_map;
        AEGIS_LOG("Attached to AFL++ shared memory (ID: %d, Map: %p)", shm_id, (void*)g_coverage_map);
    } else {
        /* Standalone mode - allocate private coverage map */
        g_coverage_map = (uint8_t *)mmap(NULL, g_coverage_map_size,
                                          PROT_READ | PROT_WRITE,
                                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (g_coverage_map == MAP_FAILED) {
            AEGIS_LOG("Failed to allocate coverage map");
            g_coverage_map = NULL;
            return AEGIS_ERR_NO_MEMORY;
        }
        
        harness->coverage_map = g_coverage_map;
        AEGIS_LOG("Allocated private coverage map (%p)", (void*)g_coverage_map);
    }

    /* Initialize map to zero */
    memset(g_coverage_map, 0, g_coverage_map_size);
    
    return AEGIS_OK;
}

/**
 * Dump coverage statistics (for standalone mode debugging).
 */
void aegis_coverage_dump(const aegis_harness_t *harness)
{
    (void)harness; /* Suppress unused warning in release builds */
    
    if (!g_coverage_map) {
        return;
    }

    uint64_t unique_edges = 0;
    for (size_t i = 0; i < g_coverage_map_size; i++) {
        if (g_coverage_map[i] != 0) {
            unique_edges++;
        }
    }

    AEGIS_LOG("Coverage Summary:");
    AEGIS_LOG("  Total Executions: %lu", harness ? harness->stats.total_execs : 0);
    AEGIS_LOG("  Unique Edges: %lu", unique_edges);
    AEGIS_LOG("  Coverage Map Size: %u", g_coverage_map_size);
}

/* ============================================================================
 * LLVM Sanitizer Coverage Callbacks
 * These functions are called by instrumented code during execution.
 * ============================================================================ */

/**
 * Initialize PC guards - called once at program startup.
 * Assigns random IDs to each guard to prevent optimization removal.
 */
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
{
    static uint32_t rand_state = 0x12345678;
    
    if (start == stop || *start) {
        return; /* Already initialized or empty range */
    }

    AEGIS_LOG("Initializing %zu PC guards", stop - start);

    for (uint32_t *x = start; x < stop; x++) {
        /* Simple LCG random number generator */
        rand_state = rand_state * 1664525 + 1013904223;
        *x = rand_state % (g_coverage_map_size - 1) + 1;
    }
}

/**
 * Trace PC guard - called on every edge transition.
 * Updates the coverage map with edge frequency.
 */
void __sanitizer_cov_trace_pc_guard(uint32_t *guard)
{
    if (!*guard || !g_coverage_map) {
        return;
    }

    /* Increment coverage counter (saturating at 255) */
    uint32_t idx = *guard % g_coverage_map_size;
    if (g_coverage_map[idx] < 255) {
        g_coverage_map[idx]++;
    }
}

/**
 * Alternative coverage initialization using 8-bit counters.
 */
void __sanitizer_cov_8bit_counters_init(char *start, char *stop)
{
    AEGIS_LOG("8-bit counters initialized: %p to %p", start, stop);
    /* In a full implementation, we would map these to our coverage array */
}

/**
 * Initialize PCS (Program Counter Set) for function-level coverage.
 */
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg, const uintptr_t *pcs_end)
{
    AEGIS_LOG("PCS initialized: %zu entries", (pcs_end - pcs_beg));
    /* Store PC information for more detailed coverage analysis */
}

/* ============================================================================
 * Comparison Tracing (for value profiling)
 * These help fuzzers understand comparison operations for smarter mutations.
 * ============================================================================ */

static inline void update_coverage_for_cmp(uint64_t val)
{
    if (!g_coverage_map) return;
    
    /* Use lower bits of value to index into coverage map */
    uint32_t idx = (uint32_t)(val ^ (val >> 32)) % g_coverage_map_size;
    if (g_coverage_map[idx] < 255) {
        g_coverage_map[idx]++;
    }
}

void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2)
{
    if (Arg1 != Arg2) {
        update_coverage_for_cmp(Arg1 | ((uint64_t)Arg2 << 8));
    }
}

void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2)
{
    if (Arg1 != Arg2) {
        update_coverage_for_cmp(Arg1 | ((uint64_t)Arg2 << 16));
    }
}

void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2)
{
    if (Arg1 != Arg2) {
        update_coverage_for_cmp(Arg1 | ((uint64_t)Arg2 << 32));
    }
}

void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2)
{
    if (Arg1 != Arg2) {
        update_coverage_for_cmp(Arg1 ^ Arg2);
    }
}

void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases)
{
    /* Cases format: [NumCases][Case0Value][Case1Value]... */
    if (!Cases) return;
    
    uint64_t num_cases = Cases[0];
    update_coverage_for_cmp(Val ^ num_cases);
    
    for (uint64_t i = 0; i < num_cases && i < 8; i++) {
        update_coverage_for_cmp(Val ^ Cases[i + 1]);
    }
}

void __sanitizer_cov_trace_div4(uint32_t Val)
{
    update_coverage_for_cmp(Val);
}

void __sanitizer_cov_trace_div8(uint64_t Val)
{
    update_coverage_for_cmp(Val);
}

/* ============================================================================
 * AFL++ Style Edge Coverage
 * Compatible with AFL's classic edge tracing mechanism.
 * ============================================================================ */

/**
 * Classic AFL edge trace function.
 * Can be called directly from instrumented code.
 */
void __afl_trace(uint32_t edge_id)
{
    if (!g_coverage_map) return;
    
    /* XOR with previous location for edge coverage */
    uint32_t loc = edge_id ^ g_prev_location;
    g_prev_location = edge_id >> 1;
    
    if (loc < g_coverage_map_size) {
        g_coverage_map[loc]++;
    }
}

/**
 * Set coverage map pointer externally.
 * Useful when integrating with existing AFL++ setups.
 */
void aegis_set_coverage_map(uint8_t *map, uint32_t size)
{
    g_coverage_map = map;
    if (size > 0 && size < AEGIS_MAP_SIZE) {
        g_coverage_map_size = size;
    }
}

/**
 * Get current coverage map pointer.
 */
uint8_t* aegis_get_coverage_map(void)
{
    return g_coverage_map;
}

/**
 * Reset coverage map (for forkserver mode between executions).
 */
void aegis_coverage_reset(void)
{
    if (g_coverage_map) {
        memset(g_coverage_map, 0, g_coverage_map_size);
    }
    g_prev_location = 0;
}
