/**
 * CVE-FINDER: Core Implementation
 * 
 * Implements initialization, signal handling, crash triage, and logging.
 * Designed for seamless integration with AFL++ and LibFuzzer.
 */

#include "cve_finder_core.h"
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <libgen.h>
#include <sys/ipc.h>
#include <sys/shm.h>

/* POSIX signal handling */
#define _POSIX_C_SOURCE 200809L

/* ============================================================================
 * GLOBAL STATE DEFINITIONS
 * ============================================================================ */

cve_finder_config_t g_config = {0};
fuzzer_stats_t g_stats = {0};
volatile sig_atomic_t g_stop_requested = 0;
uint8_t *afl_coverage_map = NULL;

/* Internal state */
static int g_initialized = 0;
static FILE *g_log_stream = NULL;
static char g_crash_dir[512] = {0};

/* ============================================================================
 * SIGNAL HANDLERS
 * ============================================================================ */

static void handle_crash_signal(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext; /* Unused in minimal handler */
    
    crash_info_t crash = {0};
    crash.type = CRASH_UNKNOWN;
    crash.timestamp = time(NULL);
    crash.pid = getpid();
    crash.severity = SEV_CRITICAL;

    switch (sig) {
        case SIGSEGV:
            crash.type = CRASH_SEGFAULT;
            strcpy(crash.signal_str, "SIGSEGV");
            break;
        case SIGABRT:
            crash.type = CRASH_ABRT;
            strcpy(crash.signal_str, "SIGABRT");
            break;
        case SIGFPE:
            crash.type = CRASH_FPE;
            strcpy(crash.signal_str, "SIGFPE");
            break;
        case SIGBUS:
            crash.type = CRASH_BUS;
            strcpy(crash.signal_str, "SIGBUS");
            break;
        default:
            sprintf(crash.signal_str, "SIG%d", sig);
            break;
    }

    /* Capture backtrace */
    crash.backtrace_size = generate_backtrace(crash.backtrace, MAX_BACKTRACE_DEPTH);

    /* Save input sample if available (simplified for signal context) */
    crash.input_sample_len = 0; 

    /* Report and exit */
    cve_finder_report_crash(&crash);
    
    /* Force exit */
    _exit(128 + sig);
}

void install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handle_crash_signal;

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
}

int generate_backtrace(void **buffer, int max_frames) {
    return backtrace(buffer, max_frames);
}

/* ============================================================================
 * LOGGING & REPORTING
 * ============================================================================ */

void cve_log(severity_level_t level, const char *format, ...) {
    if (!g_initialized) return;

    FILE *out = stdout;
    if (level >= SEV_MEDIUM) out = stderr;

    const char *level_str;
    switch (level) {
        case SEV_INFO: level_str = "INFO"; break;
        case SEV_LOW: level_str = "WARN"; break;
        case SEV_MEDIUM: level_str = "ERROR"; break;
        case SEV_HIGH: level_str = "CRIT"; break;
        case SEV_CRITICAL: level_str = "FATAL"; break;
        default: level_str = "UNK"; break;
    }

    if (g_config.verbose < 1 && level == SEV_INFO) return;

    fprintf(out, "[CVE-FINDER][%s] ", level_str);
    
    va_list args;
    va_start(args, format);
    vfprintf(out, format, args);
    va_end(args);
    
    fprintf(out, "\n");
    fflush(out);
}

int save_crash_log(crash_info_t *info) {
    if (!g_initialized || !g_crash_dir[0]) return -1;

    char filename[1024];
    snprintf(filename, sizeof(filename), "%s/crash_%s_%lu.txt", 
             g_crash_dir, info->signal_str, (unsigned long)info->timestamp);

    FILE *f = fopen(filename, "w");
    if (!f) {
        CVE_LOG_ERROR("Failed to create crash log: %s", filename);
        return -1;
    }

    fprintf(f, "CVE-FINDER Crash Report\n");
    fprintf(f, "=======================\n");
    fprintf(f, "Time: %s", ctime(&info->timestamp));
    fprintf(f, "Signal: %s\n", info->signal_str);
    fprintf(f, "PID: %d\n", info->pid);
    fprintf(f, "Severity: %d\n", info->severity);
    fprintf(f, "\nBacktrace (%d frames):\n", info->backtrace_size);
    
    char **symbols = backtrace_symbols(info->backtrace, info->backtrace_size);
    if (symbols) {
        for (int i = 0; i < info->backtrace_size; i++) {
            fprintf(f, "  [%d] %s\n", i, symbols[i]);
        }
        free(symbols);
    } else {
        for (int i = 0; i < info->backtrace_size; i++) {
            fprintf(f, "  [%d] %p\n", i, info->backtrace[i]);
        }
    }

    if (info->input_sample_len > 0) {
        fprintf(f, "\nInput Sample (hex):\n  ");
        for (size_t i = 0; i < info->input_sample_len; i++) {
            fprintf(f, "%02x ", info->input_sample[i]);
        }
        fprintf(f, "\n");
    }

    fclose(f);
    strcpy(info->log_file_path, filename);
    
    CVE_LOG_CRIT("Crash saved to: %s", filename);
    return 0;
}

void cve_finder_report_crash(crash_info_t *info) {
    g_stats.crashes_found++;
    g_stats.last_crash_time = time(NULL);
    
    save_crash_log(info);

    if (g_config.ci_mode) {
        CVE_LOG_CRIT("CI Mode: Exiting due to crash.");
        exit(1);
    }
}

/* ============================================================================
 * INITIALIZATION & SHUTDOWN
 * ============================================================================ */

int is_afl_mode(void) {
    return (g_config.mode & MODE_AFL) != 0;
}

int is_libfuzzer_mode(void) {
    return (g_config.mode & MODE_LIBFUZZER) != 0;
}

uint8_t* get_coverage_map(void) {
    return afl_coverage_map;
}

int cve_finder_init(int argc, char **argv) {
    if (g_initialized) return 0;

    /* Defaults */
    g_config.max_input_size = MAX_INPUT_SIZE;
    g_config.timeout_sec = 10;
    g_config.verbose = 1;
    g_config.ci_mode = 0;
    g_config.output_dir = getenv("CVE_FINDER_OUT");
    if (!g_config.output_dir) g_config.output_dir = "./output";
    
    g_config.input_dir = getenv("CVE_FINDER_IN");
    if (!g_config.input_dir) g_config.input_dir = "./seeds";

    /* Parse simple args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ci") == 0) g_config.ci_mode = 1;
        else if (strcmp(argv[i], "-v") == 0) g_config.verbose = 2;
        else if (strcmp(argv[i], "-q") == 0) g_config.verbose = 0;
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--ci] [-v] [-q]\n", argv[0]);
            return -1;
        }
    }

    /* Detect Mode */
    if (getenv("AFL_SHM_ID")) {
        g_config.mode |= MODE_AFL;
        CVE_LOG_INFO("Detected AFL++ environment");
        
        /* Map shared memory */
        char *id_str = getenv("AFL_SHM_ID");
        if (id_str) {
            int shm_id = atoi(id_str);
            afl_coverage_map = shmat(shm_id, NULL, 0);
            if (afl_coverage_map == (void *)-1) {
                afl_coverage_map = NULL;
                CVE_LOG_ERROR("Failed to attach AFL shared memory");
            } else {
                g_stats.coverage_map = afl_coverage_map;
            }
        }
    } else {
        /* Standalone or LibFuzzer (LibFuzzer doesn't use AFL shm directly usually) */
        g_config.mode |= MODE_STANDALONE;
        /* Allocate local map if needed for standalone stats */
        afl_coverage_map = calloc(1, SHARED_MEM_MAP_SIZE);
        g_stats.coverage_map = afl_coverage_map;
    }

    /* Setup Directories */
    mkdir(g_config.output_dir, 0755);
    snprintf(g_crash_dir, sizeof(g_crash_dir), "%s/crashes", g_config.output_dir);
    mkdir(g_crash_dir, 0755);

    /* Install Handlers */
    install_signal_handlers();

    g_stats.start_time = time(NULL);
    g_initialized = 1;

    CVE_LOG_INFO("CVE-FINDER initialized (Mode: %s)", 
                 is_afl_mode() ? "AFL++" : (is_libfuzzer_mode() ? "LibFuzzer" : "Standalone"));

    return 0;
}

void cve_finder_shutdown(void) {
    if (!g_initialized) return;

    uint64_t runtime = time(NULL) - g_stats.start_time;
    CVE_LOG_INFO("=== Fuzzing Session Complete ===");
    CVE_LOG_INFO("Total Executions: %lu", g_stats.total_execs);
    CVE_LOG_INFO("Crashes Found: %lu", g_stats.crashes_found);
    CVE_LOG_INFO("Hangs Found: %lu", g_stats.hangs_found);
    CVE_LOG_INFO("Runtime: %lu seconds", runtime);

    if (afl_coverage_map && !(g_config.mode & MODE_AFL)) {
        free(afl_coverage_map);
    }

    g_initialized = 0;
}

/* Stub for coverage update - implemented in instrumentation module if needed */
void cve_finder_update_coverage(uint32_t pc, uint32_t edge) {
    if (afl_coverage_map) {
        uint32_t pos = (pc ^ edge) % SHARED_MEM_MAP_SIZE;
        afl_coverage_map[pos]++;
    }
}
