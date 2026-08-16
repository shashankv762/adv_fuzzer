/*
 * ACFP - Advanced C Fuzzing Platform
 * Coverage Tracking Implementation
 */

#include "acfp_fuzzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Create coverage bitmap */
acfp_coverage_t *acfp_coverage_create(size_t size) {
    acfp_coverage_t *cov = calloc(1, sizeof(acfp_coverage_t));
    if (!cov) return NULL;

    cov->size = size > 0 ? size : 65536;
    cov->bitmap = calloc(1, cov->size);
    if (!cov->bitmap) {
        free(cov);
        return NULL;
    }

    cov->total_bits = cov->size * 8;
    cov->set_bits = 0;

    return cov;
}

/* Destroy coverage bitmap */
void acfp_coverage_destroy(acfp_coverage_t *cov) {
    if (!cov) return;

    free(cov->bitmap);
    free(cov);
}

/* Update coverage with new trace */
int acfp_coverage_update(acfp_coverage_t *cov, const uint8_t *trace, size_t trace_size) {
    if (!cov || !trace || trace_size == 0) return -1;

    bool new_coverage = false;

    for (size_t i = 0; i < trace_size && i < cov->size; i++) {
        if (trace[i] != 0 && cov->bitmap[i] == 0) {
            cov->bitmap[i] = trace[i];
            new_coverage = true;
        }
    }

    /* Recalculate set bits */
    cov->set_bits = 0;
    for (size_t i = 0; i < cov->size; i++) {
        if (cov->bitmap[i] != 0) {
            cov->set_bits++;
        }
    }

    return new_coverage ? 1 : 0;
}

/* Check if trace has new coverage */
bool acfp_coverage_has_new(acfp_coverage_t *cov, const uint8_t *trace, size_t trace_size) {
    if (!cov || !trace || trace_size == 0) return false;

    /* Simple hash-based edge coverage check */
    uint32_t hash = 5381;
    for (size_t i = 0; i < trace_size; i++) {
        hash = ((hash << 5) + hash) + trace[i];
    }

    size_t idx = hash % cov->size;
    
    if (cov->bitmap[idx] == 0) {
        cov->bitmap[idx] = 1;
        cov->set_bits++;
        return true;
    }

    return false;
}

/* Get coverage percentage */
double acfp_coverage_percent(acfp_coverage_t *cov) {
    if (!cov || cov->total_bits == 0) return 0.0;

    return (double)cov->set_bits / (double)cov->total_bits * 100.0;
}
