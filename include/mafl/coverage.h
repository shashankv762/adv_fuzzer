#ifndef MAFL_COVERAGE_H
#define MAFL_COVERAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Default map size - matches AFL/AFL++ default */
#define MAFL_MAP_SIZE 65536

typedef struct mafl_coverage_map {
    uint8_t bins[MAFL_MAP_SIZE];
    uint8_t virgin[MAFL_MAP_SIZE];
    uint32_t guard_count;
    bool attached;
    char shm_name[64];
    int shm_fd;
} mafl_coverage_map_t;

/* SanitizerCoverage callbacks - implemented by runtime */
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
void __sanitizer_cov_trace_pc_guard(uint32_t *guard);

/* Coverage API */
void mafl_coverage_init(mafl_coverage_map_t *map);
bool mafl_coverage_has_new(mafl_coverage_map_t *map);
void mafl_coverage_update_virgin(mafl_coverage_map_t *map);
void mafl_coverage_clear(mafl_coverage_map_t *map);
void mafl_coverage_stats(mafl_coverage_map_t *map, uint32_t *total_edges, uint32_t *hit_edges);

#endif /* MAFL_COVERAGE_H */
