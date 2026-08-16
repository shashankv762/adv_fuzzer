/*
 * ACFP - Advanced C Fuzzing Platform
 * Crash Handling and Triage Implementation
 */

#include "acfp_fuzzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Detect if exit indicates a crash */
int acfp_crash_detect(int exit_code, const char *stderr_output) {
    if (exit_code != 0 && exit_code != -1) {
        return 1;  /* Non-zero exit (not timeout) */
    }
    
    if (stderr_output && strlen(stderr_output) > 0) {
        const char *crash_indicators[] = {
            "ERROR:", "ASAN", "UBSAN", "MSAN", "LSAN",
            "runtime error", "segmentation fault", "abort",
            "Assertion", "AddressSanitizer", "UndefinedBehaviorSanitizer",
            NULL
        };
        
        for (int i = 0; crash_indicators[i]; i++) {
            if (strstr(stderr_output, crash_indicators[i])) {
                return 1;
            }
        }
    }
    
    return 0;
}

/* Classify crash type from sanitizer output */
acfp_crash_type_t acfp_crash_classify(const char *sanitizer_output) {
    if (!sanitizer_output || strlen(sanitizer_output) == 0) {
        return CRASH_UNKNOWN;
    }

    /* Check for specific crash types */
    if (strstr(sanitizer_output, "heap-buffer-overflow")) {
        return strstr(sanitizer_output, "WRITE") ? CRASH_HEAP_OVERFLOW : CRASH_OUT_OF_BOUNDS_READ;
    }
    if (strstr(sanitizer_output, "heap-use-after-free")) {
        return CRASH_USE_AFTER_FREE;
    }
    if (strstr(sanitizer_output, "double-free")) {
        return CRASH_DOUBLE_FREE;
    }
    if (strstr(sanitizer_output, "stack-buffer-overflow")) {
        return CRASH_STACK_OVERFLOW;
    }
    if (strstr(sanitizer_output, "global-buffer-overflow")) {
        return CRASH_OUT_OF_BOUNDS_READ;
    }
    if (strstr(sanitizer_output, "null-pointer-deref")) {
        return CRASH_NULL_DEREFERENCE;
    }
    if (strstr(sanitizer_output, "integer-overflow") || 
        strstr(sanitizer_output, "signed-integer-overflow")) {
        return CRASH_INTEGER_OVERFLOW;
    }
    if (strstr(sanitizer_output, "divide-by-zero") || 
        strstr(sanitizer_output, "division by zero")) {
        return CRASH_DIVIDE_BY_ZERO;
    }
    if (strstr(sanitizer_output, "assertion") || 
        strstr(sanitizer_output, "ASSERT")) {
        return CRASH_ASSERTION_FAILURE;
    }
    if (strstr(sanitizer_output, "uninitialized-memory")) {
        return CRASH_UNINITIALIZED_MEMORY;
    }
    if (strstr(sanitizer_output, "memory-leak") ||
        strstr(sanitizer_output, "LeakSanitizer")) {
        return CRASH_MEMORY_LEAK;
    }
    if (strstr(sanitizer_output, "Timeout") ||
        strstr(sanitizer_output, "timeout")) {
        return CRASH_TIMEOUT;
    }

    /* Generic classification */
    if (strstr(sanitizer_output, "overflow")) {
        return CRASH_HEAP_OVERFLOW;
    }
    if (strstr(sanitizer_output, "underflow")) {
        return CRASH_HEAP_UNDERFLOW;
    }

    return CRASH_UNKNOWN;
}

/* Determine severity based on crash type */
acfp_severity_t acfp_crash_severity(acfp_crash_type_t type) {
    switch (type) {
        case CRASH_HEAP_OVERFLOW:
        case CRASH_STACK_OVERFLOW:
        case CRASH_USE_AFTER_FREE:
        case CRASH_DOUBLE_FREE:
        case CRASH_OUT_OF_BOUNDS_WRITE:
            return SEVERITY_CRITICAL;
            
        case CRASH_OUT_OF_BOUNDS_READ:
        case CRASH_NULL_DEREFERENCE:
        case CRASH_INTEGER_OVERFLOW:
            return SEVERITY_HIGH;
            
        case CRASH_UNINITIALIZED_MEMORY:
        case CRASH_DIVIDE_BY_ZERO:
            return SEVERITY_MEDIUM;
            
        case CRASH_ASSERTION_FAILURE:
        case CRASH_MEMORY_LEAK:
            return SEVERITY_LOW;
            
        case CRASH_TIMEOUT:
            return SEVERITY_INFO;
            
        default:
            return SEVERITY_MEDIUM;
    }
}

/* Estimate exploitability using conservative heuristics */
acfp_exploitability_t acfp_crash_exploitability(acfp_crash_info_t *crash) {
    if (!crash) return EXPLOIT_UNKNOWN;

    /* Conservative assessment for defensive research */
    switch (crash->type) {
        case CRASH_HEAP_OVERFLOW:
        case CRASH_STACK_OVERFLOW:
            /* Write overflows are potentially exploitable */
            return EXPLOIT_PROBABLY_EXPLOITABLE;
            
        case CRASH_USE_AFTER_FREE:
            /* UAF can be exploitable but context-dependent */
            return EXPLOIT_PROBABLY_EXPLOITABLE;
            
        case CRASH_DOUBLE_FREE:
            /* Often leads to heap corruption */
            return EXPLOIT_PROBABLY_EXPLOITABLE;
            
        case CRASH_OUT_OF_BOUNDS_READ:
        case CRASH_NULL_DEREFERENCE:
            /* Read bugs typically DoS only */
            return EXPLOIT_DOS_ONLY;
            
        case CRASH_INTEGER_OVERFLOW:
            /* Can lead to memory corruption if used in allocation */
            return EXPLOIT_UNKNOWN;
            
        case CRASH_DIVIDE_BY_ZERO:
        case CRASH_ASSERTION_FAILURE:
        case CRASH_TIMEOUT:
            /* DoS only */
            return EXPLOIT_DOS_ONLY;
            
        case CRASH_MEMORY_LEAK:
            /* Not directly exploitable */
            return EXPLOIT_PROBABLY_NOT;
            
        default:
            return EXPLOIT_UNKNOWN;
    }
}

/* Generate crash hash for deduplication */
int acfp_crash_hash(acfp_crash_info_t *crash, const char *stack_trace) {
    if (!crash) return -1;

    /* Extract key frames from stack trace for hashing */
    char normalized[2048] = {0};
    size_t norm_idx = 0;

    if (stack_trace && strlen(stack_trace) > 0) {
        /* Simple normalization: extract function names or addresses */
        const char *p = stack_trace;
        int frame_count = 0;
        
        while (*p && frame_count < 5 && norm_idx < sizeof(normalized) - 10) {
            if (strstr(p, "#") == p) {
                /* Found frame marker */
                const char *frame_start = strchr(p, ' ');
                if (frame_start) {
                    /* Copy next 30 chars as frame signature */
                    for (int i = 0; i < 30 && frame_start[i] && frame_start[i] != '\n'; i++) {
                        normalized[norm_idx++] = frame_start[i];
                    }
                    normalized[norm_idx++] = '|';
                    frame_count++;
                }
            }
            p++;
        }
    }

    /* If no stack trace, use crash type and target */
    if (norm_idx == 0) {
        snprintf(normalized, sizeof(normalized), "%s|%s", 
                 acfp_crash_type_str(crash->type), crash->target_name);
    }

    /* Hash the normalized signature */
    acfp_hash_buffer((uint8_t *)normalized, strlen(normalized), crash->crash_hash);
    
    return 0;
}

/* Save crash artifacts */
int acfp_crash_save(acfp_crash_info_t *crash, acfp_input_t *input) {
    if (!crash) return -1;

    /* Create crash directory */
    char crash_dir[512];
    snprintf(crash_dir, sizeof(crash_dir), "/workspace/acfp/reports/crashes/%s", 
             crash->crash_hash);
    
    if (acfp_mkdir_p(crash_dir) != 0) {
        return -1;
    }

    /* Generate unique ID */
    snprintf(crash->id, sizeof(crash->id), "CRASH-%s-%lu", 
             crash->crash_hash, acfp_timestamp());

    /* Save reproducer input */
    if (input && input->data) {
        snprintf(crash->reproducer_path, sizeof(crash->reproducer_path),
                 "%s/reproducer.bin", crash_dir);
        acfp_input_save(input, crash->reproducer_path);
    }

    /* Save metadata */
    char meta_path[512];
    snprintf(meta_path, sizeof(meta_path), "%s/metadata.json", crash_dir);
    
    FILE *f = fopen(meta_path, "w");
    if (f) {
        fprintf(f, "{\n");
        fprintf(f, "  \"id\": \"%s\",\n", crash->id);
        fprintf(f, "  \"hash\": \"%s\",\n", crash->crash_hash);
        fprintf(f, "  \"type\": \"%s\",\n", acfp_crash_type_str(crash->type));
        fprintf(f, "  \"severity\": \"%s\",\n", acfp_severity_str(crash->severity));
        fprintf(f, "  \"target\": \"%s\",\n", crash->target_name);
        fprintf(f, "  \"first_seen\": %lu,\n", crash->first_seen);
        fprintf(f, "  \"state\": %d\n", crash->state);
        fprintf(f, "}\n");
        fclose(f);
    }

    return 0;
}

/* Minimize crash reproducer */
int acfp_crash_minimize(acfp_crash_info_t *crash) {
    /* Placeholder for minimization algorithm */
    /* In production, implement delta debugging or similar */
    if (!crash || !crash->reproducer_path[0]) return -1;

    /* For now, just copy reproducer as minimized */
    snprintf(crash->minimized_path, sizeof(crash->minimized_path),
             "%s", crash->reproducer_path);

    return 0;
}

/* Get string representation of crash type */
const char *acfp_crash_type_str(acfp_crash_type_t type) {
    static const char *types[] = {
        "Unknown",
        "Heap Overflow",
        "Heap Underflow",
        "Stack Overflow",
        "Use After Free",
        "Double Free",
        "Out-of-bounds Read",
        "Out-of-bounds Write",
        "Null Dereference",
        "Integer Overflow",
        "Divide by Zero",
        "Assertion Failure",
        "Uninitialized Memory",
        "Memory Leak",
        "Timeout"
    };
    
    if (type >= 0 && type < CRASH_LAST) {
        return types[type];
    }
    return "Unknown";
}

/* Get string representation of severity */
const char *acfp_severity_str(acfp_severity_t sev) {
    static const char *severities[] = {
        "Informational",
        "Low",
        "Medium",
        "High",
        "Critical"
    };
    
    if (sev >= 0 && sev < SEVERITY_LAST) {
        return severities[sev];
    }
    return "Unknown";
}

/* Get string representation of exploitability */
const char *acfp_exploitability_str(acfp_exploitability_t exp) {
    static const char *exploitability[] = {
        "None",
        "Exploitable",
        "Probably Exploitable",
        "Unknown",
        "Probably Not Exploitable",
        "DoS Only"
    };
    
    if (exp >= 0 && exp < EXPLOIT_LAST) {
        return exploitability[exp];
    }
    return "Unknown";
}

/* Get string representation of lifecycle state */
const char *acfp_state_str(acfp_lifecycle_state_t state) {
    static const char *states[] = {
        "New",
        "Triaged",
        "Confirmed",
        "Exploitability Assessed",
        "Patch Proposed",
        "Patch Verified",
        "Disclosed",
        "Rejected",
        "Archived"
    };
    
    if (state >= 0 && state < STATE_LAST) {
        return states[state];
    }
    return "Unknown";
}

/* Map crash type to CWE candidate */
const char *acfp_cwe_map(acfp_crash_type_t type) {
    switch (type) {
        case CRASH_HEAP_OVERFLOW:
        case CRASH_STACK_OVERFLOW:
        case CRASH_OUT_OF_BOUNDS_WRITE:
            return "CWE-787";  /* Out-of-bounds Write */
        case CRASH_OUT_OF_BOUNDS_READ:
            return "CWE-125";  /* Out-of-bounds Read */
        case CRASH_USE_AFTER_FREE:
            return "CWE-416";  /* Use After Free */
        case CRASH_DOUBLE_FREE:
            return "CWE-415";  /* Double Free */
        case CRASH_NULL_DEREFERENCE:
            return "CWE-476";  /* NULL Pointer Dereference */
        case CRASH_INTEGER_OVERFLOW:
            return "CWE-190";  /* Integer Overflow */
        case CRASH_DIVIDE_BY_ZERO:
            return "CWE-369";  /* Divide by Zero */
        case CRASH_UNINITIALIZED_MEMORY:
            return "CWE-457";  /* Use of Uninitialized Variable */
        case CRASH_MEMORY_LEAK:
            return "CWE-401";  /* Memory Leak */
        default:
            return "CWE-Unknown";
    }
}

/* Estimate CVSS score based on crash characteristics */
float acfp_cvss_estimate(acfp_crash_info_t *crash) {
    if (!crash) return 0.0f;

    float base_score = 5.0f;

    /* Adjust based on severity */
    switch (crash->severity) {
        case SEVERITY_CRITICAL:
            base_score = 9.0f;
            break;
        case SEVERITY_HIGH:
            base_score = 7.5f;
            break;
        case SEVERITY_MEDIUM:
            base_score = 5.0f;
            break;
        case SEVERITY_LOW:
            base_score = 3.0f;
            break;
        case SEVERITY_INFO:
            base_score = 1.0f;
            break;
        default:
            base_score = 5.0f;
    }

    /* Adjust based on exploitability */
    switch (crash->exploitability) {
        case EXPLOIT_EXPLOITABLE:
            base_score += 1.0f;
            break;
        case EXPLOIT_PROBABLY_EXPLOITABLE:
            base_score += 0.5f;
            break;
        case EXPLOIT_DOS_ONLY:
            base_score -= 2.0f;
            break;
        default:
            break;
    }

    /* Clamp to valid range */
    if (base_score > 10.0f) base_score = 10.0f;
    if (base_score < 0.0f) base_score = 0.0f;

    return base_score;
}
