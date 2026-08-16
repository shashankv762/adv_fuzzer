/**
 * @file triage.c
 * @brief Crash triage and exploitability assessment
 * 
 * Analyzes crashes, classifies them, deduplicates, and assesses exploitability.
 */

#include "acfp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

/* CWE mappings for common crash types */
static const acfp_cwe_mapping_t g_cwe_mappings[] = {
    {"CWE-120", "Buffer Copy without Checking Size of Input", "Classic buffer overflow", ACFP_CRASH_STACK_OVERFLOW},
    {"CWE-122", "Heap-based Buffer Overflow", "Heap buffer overflow", ACFP_CRASH_HEAP_OVERFLOW},
    {"CWE-125", "Out-of-bounds Read", "Reading past buffer bounds", ACFP_CRASH_OOB_READ},
    {"CWE-787", "Out-of-bounds Write", "Writing past buffer bounds", ACFP_CRASH_OOB_WRITE},
    {"CWE-416", "Use After Free", "Accessing freed memory", ACFP_CRASH_USE_AFTER_FREE},
    {"CWE-415", "Double Free", "Freeing memory twice", ACFP_CRASH_DOUBLE_FREE},
    {"CWE-476", "NULL Pointer Dereference", "Dereferencing NULL pointer", ACFP_CRASH_NULL_DEREF},
    {"CWE-190", "Integer Overflow", "Integer wraparound leading to crash", ACFP_CRASH_INTEGER_OVERFLOW},
    {"CWE-457", "Use of Uninitialized Variable", "Uninitialized memory access", ACFP_CRASH_UNINITIALIZED_MEM},
    {"CWE-369", "Divide by Zero", "Division or modulo by zero", ACFP_CRASH_DIVIDE_BY_ZERO},
    {"CWE-617", "Reachable Assertion", "Assertion failure", ACFP_CRASH_ASSERTION_FAILURE},
    {"CWE-401", "Memory Leak", "Missing free() calls", ACFP_CRASH_LEAK},
    {"CWE-758", "Reliance on Undefined Behavior", "Undefined behavior triggered", ACFP_CRASH_UNDEFINED_BEHAVIOR},
};
#define NUM_CWE_MAPPINGS (sizeof(g_cwe_mappings) / sizeof(g_cwe_mappings[0]))

/**
 * @brief Compute crash hash for deduplication
 */
static uint32_t compute_crash_hash(acfp_crash_type_t type, int signal, void *pc)
{
    /* Hash based on crash type, signal, and program counter */
    uint32_t hash = 5381;
    hash = ((hash << 5) + hash) + (uint32_t)type;
    hash = ((hash << 5) + hash) + (uint32_t)signal;
    hash = ((hash << 5) + hash) + (uint32_t)((uintptr_t)pc >> 4); /* Normalize PC */
    return hash;
}

/**
 * @brief Generate unique crash ID
 */
static void generate_crash_id(char *id, size_t id_size, uint32_t hash)
{
    snprintf(id, id_size, "CRASH_%08X", hash);
}

/**
 * @brief Classify crash from sanitizer output
 */
static acfp_crash_type_t classify_from_sanitizer(const char *san_output)
{
    if (!san_output || strlen(san_output) == 0) {
        return ACFP_CRASH_UNKNOWN;
    }
    
    if (strstr(san_output, "heap-buffer-overflow")) {
        return ACFP_CRASH_HEAP_OVERFLOW;
    } else if (strstr(san_output, "stack-buffer-overflow")) {
        return ACFP_CRASH_STACK_OVERFLOW;
    } else if (strstr(san_output, "heap-use-after-free")) {
        return ACFP_CRASH_USE_AFTER_FREE;
    } else if (strstr(san_output, "double-free")) {
        return ACFP_CRASH_DOUBLE_FREE;
    } else if (strstr(san_output, "global-buffer-overflow") ||
               strstr(san_output, "READ of size") ||
               strstr(san_output, "WRITE of size")) {
        if (strstr(san_output, "write")) {
            return ACFP_CRASH_OOB_WRITE;
        }
        return ACFP_CRASH_OOB_READ;
    } else if (strstr(san_output, "null pointer") || strstr(san_output, "SEGV on unknown address")) {
        return ACFP_CRASH_NULL_DEREF;
    } else if (strstr(san_output, "integer overflow") || strstr(san_output, "signed integer overflow")) {
        return ACFP_CRASH_INTEGER_OVERFLOW;
    } else if (strstr(san_output, "uninitialized")) {
        return ACFP_CRASH_UNINITIALIZED_MEM;
    } else if (strstr(san_output, "division by zero") || strstr(san_output, "divide by zero")) {
        return ACFP_CRASH_DIVIDE_BY_ZERO;
    } else if (strstr(san_output, "assertion") || strstr(san_output, "ASSERTION FAILURE")) {
        return ACFP_CRASH_ASSERTION_FAILURE;
    } else if (strstr(san_output, "LeakSanitizer") || strstr(san_output, "memory leak")) {
        return ACFP_CRASH_LEAK;
    } else if (strstr(san_output, "undefined behavior") || strstr(san_output, "UndefinedBehaviorSanitizer")) {
        return ACFP_CRASH_UNDEFINED_BEHAVIOR;
    }
    
    return ACFP_CRASH_UNKNOWN;
}

/**
 * @brief Assess severity based on crash type
 */
static acfp_severity_t assess_severity(acfp_crash_type_t type)
{
    switch (type) {
        case ACFP_CRASH_HEAP_OVERFLOW:
        case ACFP_CRASH_STACK_OVERFLOW:
        case ACFP_CRASH_USE_AFTER_FREE:
        case ACFP_CRASH_OOB_WRITE:
            return ACFP_SEVERITY_CRITICAL;
        
        case ACFP_CRASH_DOUBLE_FREE:
        case ACFP_CRASH_OOB_READ:
        case ACFP_CRASH_INTEGER_OVERFLOW:
            return ACFP_SEVERITY_HIGH;
        
        case ACFP_CRASH_NULL_DEREF:
        case ACFP_CRASH_UNINITIALIZED_MEM:
        case ACFP_CRASH_UNDEFINED_BEHAVIOR:
            return ACFP_SEVERITY_MEDIUM;
        
        case ACFP_CRASH_ASSERTION_FAILURE:
        case ACFP_CRASH_DIVIDE_BY_ZERO:
            return ACFP_SEVERITY_LOW;
        
        case ACFP_CRASH_LEAK:
            return ACFP_SEVERITY_INFO;
        
        case ACFP_CRASH_TIMEOUT:
        case ACFP_CRASH_HANG:
            return ACFP_SEVERITY_LOW;
        
        default:
            return ACFP_SEVERITY_UNKNOWN;
    }
}

/**
 * @brief Find CWE candidate for crash type
 */
static const char* find_cwe_candidate(acfp_crash_type_t type)
{
    for (size_t i = 0; i < NUM_CWE_MAPPINGS; i++) {
        if (g_cwe_mappings[i].crash_type == type) {
            return g_cwe_mappings[i].cwe_id;
        }
    }
    return "CWE-Unknown";
}

/**
 * @brief Estimate CVSS score
 */
static float estimate_cvss(acfp_crash_type_t type, acfp_severity_t severity)
{
    float base = 0.0f;
    
    /* Base score by severity */
    switch (severity) {
        case ACFP_SEVERITY_CRITICAL: base = 9.0f; break;
        case ACFP_SEVERITY_HIGH: base = 7.5f; break;
        case ACFP_SEVERITY_MEDIUM: base = 5.0f; break;
        case ACFP_SEVERITY_LOW: base = 3.0f; break;
        case ACFP_SEVERITY_INFO: base = 1.0f; break;
        default: base = 5.0f; break;
    }
    
    /* Adjust by crash type */
    switch (type) {
        case ACFP_CRASH_HEAP_OVERFLOW:
        case ACFP_CRASH_STACK_OVERFLOW:
            base += 0.5f; /* Memory corruption is worse */
            break;
        case ACFP_CRASH_USE_AFTER_FREE:
            base += 0.3f;
            break;
        case ACFP_CRASH_LEAK:
            base -= 2.0f; /* Leaks are less severe */
            break;
        case ACFP_CRASH_TIMEOUT:
        case ACFP_CRASH_HANG:
            base -= 1.0f; /* DoS only */
            break;
        default:
            break;
    }
    
    /* Clamp to [0, 10] */
    if (base > 10.0f) base = 10.0f;
    if (base < 0.0f) base = 0.0f;
    
    return base;
}

/**
 * @brief Assess exploitability
 */
acfp_exploitability_t acfp_assess_exploitability(acfp_crash_type_t type, const char *sanitizer_output)
{
    /* Conservative heuristics for defensive purposes */
    
    switch (type) {
        case ACFP_CRASH_HEAP_OVERFLOW:
            /* Heap overflows can be exploitable but often difficult */
            if (sanitizer_output && strstr(sanitizer_output, "WRITE")) {
                return ACFP_EXPLOIT_PROBABLY_EXPLOITABLE;
            }
            return ACFP_EXPLOIT_PROBABLY_EXPLOITABLE;
        
        case ACFP_CRASH_STACK_OVERFLOW:
            /* Stack overflows are classic exploitation vectors */
            return ACFP_EXPLOIT_PROBABLY_EXPLOITABLE;
        
        case ACFP_CRASH_USE_AFTER_FREE:
            /* UAF can be exploitable depending on context */
            return ACFP_EXPLOIT_PROBABLY_EXPLOITABLE;
        
        case ACFP_CRASH_DOUBLE_FREE:
            /* Double-free often leads to heap corruption */
            return ACFP_EXPLOIT_PROBABLY_EXPLOITABLE;
        
        case ACFP_CRASH_OOB_WRITE:
            /* Out-of-bounds write can corrupt adjacent data */
            return ACFP_EXPLOIT_PROBABLY_EXPLOITABLE;
        
        case ACFP_CRASH_OOB_READ:
            /* OOB read is usually information disclosure */
            return ACFP_EXPLOIT_NOT_EXPLOITABLE;
        
        case ACFP_CRASH_NULL_DEREF:
            /* NULL deref is usually not exploitable */
            return ACFP_EXPLOIT_NOT_EXPLOITABLE;
        
        case ACFP_CRASH_INTEGER_OVERFLOW:
            /* Integer overflow can lead to other vulns */
            if (sanitizer_output && strstr(sanitizer_output, "resulted in allocation")) {
                return ACFP_EXPLOIT_PROBABLY_EXPLOITABLE;
            }
            return ACFP_EXPLOIT_PROBABLY_NOT_EXPLOITABLE;
        
        case ACFP_CRASH_UNINITIALIZED_MEM:
            /* Uninitialized memory read - info disclosure */
            return ACFP_EXPLOIT_PROBABLY_NOT_EXPLOITABLE;
        
        case ACFP_CRASH_DIVIDE_BY_ZERO:
        case ACFP_CRASH_ASSERTION_FAILURE:
            /* These are typically DoS only */
            return ACFP_EXPLOIT_DOS_ONLY;
        
        case ACFP_CRASH_LEAK:
            /* Memory leaks are not directly exploitable */
            return ACFP_EXPLOIT_NOT_EXPLOITABLE;
        
        case ACFP_CRASH_TIMEOUT:
        case ACFP_CRASH_HANG:
            /* DoS only */
            return ACFP_EXPLOIT_DOS_ONLY;
        
        default:
            return ACFP_EXPLOIT_UNKNOWN;
    }
}

/**
 * @brief Generate exploitability summary
 */
static void generate_exploitability_summary(acfp_exploitability_t expl, 
                                           acfp_crash_type_t type,
                                           char *summary, size_t max_len)
{
    if (!summary || max_len == 0) return;
    
    const char *expl_str = acfp_exploitability_to_string(expl);
    const char *type_str = acfp_crash_type_to_string(type);
    
    snprintf(summary, max_len, 
             "Exploitability Assessment: %s\n"
             "Crash Type: %s\n"
             "\n"
             "This assessment uses conservative heuristics for defensive security purposes.\n"
             "The classification is based on the crash type and available context.\n"
             "For authoritative assessment, manual analysis by a security researcher is required.\n"
             "\n"
             "Note: This is for authorized, local, defensive testing only.",
             expl_str, type_str);
}

/**
 * @brief Generate remediation recommendation
 */
static void generate_remediation(acfp_crash_type_t type, char *rec, size_t max_len)
{
    if (!rec || max_len == 0) return;
    
    switch (type) {
        case ACFP_CRASH_HEAP_OVERFLOW:
        case ACFP_CRASH_STACK_OVERFLOW:
            snprintf(rec, max_len,
                     "Remediation:\n"
                     "1. Add bounds checking before buffer operations\n"
                     "2. Use safe string functions (strncpy, snprintf)\n"
                     "3. Validate input sizes before copying\n"
                     "4. Consider using safer alternatives (std::vector, std::string in C++)\n"
                     "5. Enable compiler protections (-fstack-protector-strong, ASLR, DEP)");
            break;
        
        case ACFP_CRASH_USE_AFTER_FREE:
            snprintf(rec, max_len,
                     "Remediation:\n"
                     "1. Set pointers to NULL after freeing\n"
                     "2. Use ownership semantics to track memory lifetime\n"
                     "3. Consider smart pointers or reference counting\n"
                     "4. Add checks before dereferencing pointers\n"
                     "5. Use memory sanitizers during development");
            break;
        
        case ACFP_CRASH_DOUBLE_FREE:
            snprintf(rec, max_len,
                     "Remediation:\n"
                     "1. Track allocation state to prevent double-free\n"
                     "2. Set pointers to NULL after freeing\n"
                     "3. Review error handling paths\n"
                     "4. Use RAII patterns where possible");
            break;
        
        case ACFP_CRASH_OOB_READ:
        case ACFP_CRASH_OOB_WRITE:
            snprintf(rec, max_len,
                     "Remediation:\n"
                     "1. Validate array indices before access\n"
                     "2. Check buffer boundaries explicitly\n"
                     "3. Use safe container types with bounds checking\n"
                     "4. Add assertions for debug builds");
            break;
        
        case ACFP_CRASH_INTEGER_OVERFLOW:
            snprintf(rec, max_len,
                     "Remediation:\n"
                     "1. Check for overflow before arithmetic operations\n"
                     "2. Use safe integer libraries\n"
                     "3. Validate input ranges\n"
                     "4. Enable compiler overflow checks where available");
            break;
        
        default:
            snprintf(rec, max_len,
                     "Remediation:\n"
                     "1. Review code at the crash location\n"
                     "2. Add appropriate input validation\n"
                     "3. Enable all relevant sanitizers during testing\n"
                     "4. Consider code review by security team");
            break;
    }
}

/**
 * @brief Triage a crash
 */
int acfp_triage_crash(const char *crash_input_path,
                      const char *binary_path,
                      acfp_triage_result_t *result)
{
    if (!result) return -1;
    
    memset(result, 0, sizeof(*result));
    
    /* If we have sanitizer output, use it */
    /* For now, we'll run the binary and capture output */
    if (!binary_path || !crash_input_path) {
        result->is_crash = false;
        return -1;
    }
    
    /* Run target with crash input */
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    
    if (pid == 0) {
        /* Child - redirect stderr to pipe */
        int pipefd[2];
        if (pipe(pipefd) < 0) _exit(1);
        
        /* Redirect stderr to pipe */
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        
        /* Open crash input */
        FILE *f = fopen(crash_input_path, "r");
        if (!f) _exit(1);
        
        /* Execute */
        execl(binary_path, binary_path, crash_input_path, NULL);
        _exit(127);
    }
    
    /* Parent waits */
    int status = 0;
    waitpid(pid, &status, 0);
    
    if (WIFSIGNALED(status)) {
        result->is_crash = true;
        result->signal_number = WTERMSIG(status);
        
        /* Classify by signal */
        switch (result->signal_number) {
            case SIGSEGV:
                result->crash_type = ACFP_CRASH_NULL_DEREF; /* Default, will be refined */
                break;
            case SIGABRT:
                result->crash_type = ACFP_CRASH_ASSERTION_FAILURE;
                break;
            case SIGFPE:
                result->crash_type = ACFP_CRASH_DIVIDE_BY_ZERO;
                break;
            default:
                result->crash_type = ACFP_CRASH_UNKNOWN;
                break;
        }
        
        result->severity = assess_severity(result->crash_type);
        result->exploitability = acfp_assess_exploitability(result->crash_type, NULL);
        
        /* Compute hash */
        uint32_t hash = compute_crash_hash(result->crash_type, result->signal_number, NULL);
        generate_crash_id(result->crash_hash, sizeof(result->crash_hash), hash);
        
        /* CWE mapping */
        acfp_safe_strcpy(result->cwe_candidate, find_cwe_candidate(result->crash_type), 
                         sizeof(result->cwe_candidate));
        
        /* CVSS estimation */
        result->cvss_score = estimate_cvss(result->crash_type, result->severity);
        
        /* Generate summaries */
        generate_exploitability_summary(result->exploitability, result->crash_type,
                                        result->exploitability_summary, 
                                        sizeof(result->exploitability_summary));
        
        generate_remediation(result->crash_type,
                            result->remediation_recommendation,
                            sizeof(result->remediation_recommendation));
    }
    
    return 0;
}

/**
 * @brief Save crash information
 */
int acfp_crash_save(const acfp_crash_info_t *crash, const char *output_dir)
{
    if (!crash || !output_dir) return -1;
    
    /* Create output directory */
    mkdir(output_dir, 0755);
    
    /* Build crash file path */
    char crash_file[ACFP_MAX_PATH_LEN];
    snprintf(crash_file, sizeof(crash_file), "%s/%s.json", output_dir, crash->id);
    
    /* Write JSON metadata */
    FILE *f = fopen(crash_file, "w");
    if (!f) return -1;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"id\": \"%s\",\n", crash->id);
    fprintf(f, "  \"crash_hash\": \"%s\",\n", crash->crash_hash);
    fprintf(f, "  \"type\": \"%s\",\n", acfp_crash_type_to_string(crash->type));
    fprintf(f, "  \"severity\": \"%s\",\n", acfp_severity_to_string(crash->severity));
    fprintf(f, "  \"exploitability\": \"%s\",\n", acfp_exploitability_to_string(crash->exploitability));
    fprintf(f, "  \"target_name\": \"%s\",\n", crash->target_name);
    fprintf(f, "  \"harness_name\": \"%s\",\n", crash->harness_name);
    fprintf(f, "  \"cwe_candidate\": \"%s\",\n", crash->cwe_candidate);
    fprintf(f, "  \"cvss_score\": %.1f,\n", crash->cvss_score);
    fprintf(f, "  \"first_seen\": %ld,\n", (long)crash->first_seen);
    fprintf(f, "  \"last_seen\": %ld,\n", (long)crash->last_seen);
    fprintf(f, "  \"occurrence_count\": %u,\n", crash->occurrence_count);
    fprintf(f, "  \"signal_number\": %d,\n", crash->signal_number);
    fprintf(f, "  \"state\": %d\n", (int)crash->state);
    fprintf(f, "}\n");
    
    fclose(f);
    
    return 0;
}

/**
 * @brief Check if crash is duplicate
 */
bool acfp_crash_is_duplicate(const acfp_crash_info_t *existing,
                             const acfp_crash_info_t *new_crash)
{
    if (!existing || !new_crash) return false;
    
    /* Compare crash hashes */
    if (strcmp(existing->crash_hash, new_crash->crash_hash) == 0) {
        return true;
    }
    
    /* Compare normalized stack traces if available */
    if (existing->stack_trace[0] && new_crash->stack_trace[0]) {
        if (strcmp(existing->stack_trace, new_crash->stack_trace) == 0) {
            return true;
        }
    }
    
    return false;
}
