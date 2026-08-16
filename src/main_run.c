/* mafl-run — the M1 vertical slice driver.
 *
 * Runs a target N times through the execution engine and reports a status breakdown. This
 * is not the fuzzer: there is no mutation, no coverage, and no corpus yet. Its purpose is
 * to prove the execution engine works end to end and to make the M1 exit criteria
 * observable by hand rather than only through the test suite. */

#include "mafl/exec.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Async-signal-safe shutdown: the handler sets a flag and returns, nothing else. Any
   allocation, logging, or I/O in here risks a deadlock (docs/CONTRIBUTING.md §4). */
static volatile sig_atomic_t g_shutdown_requested = 0;

static void on_shutdown(int sig)
{
    (void)sig;
    g_shutdown_requested = 1;
}

static void install_shutdown_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_shutdown;
    (void)sigemptyset(&sa.sa_mask);
    /* No SA_RESTART: an interrupted ppoll should return so the loop can notice the flag
       promptly rather than sitting out the rest of a long deadline. */
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
}

static void usage(const char *argv0)
{
    (void)fprintf(stderr,
        "mafl-run — M1 execution-engine driver\n"
        "\n"
        "usage: %s [options] -- <target> [target-args...]\n"
        "\n"
        "options:\n"
        "  -n <count>      executions to perform (default 100)\n"
        "  -t <ms>         per-execution timeout in milliseconds (default 1000)\n"
        "  -i <file>       read the input from this file (default: empty input)\n"
        "  -f              file-delivery mode; \"@@\" in target-args is replaced\n"
        "                  by the staged input path (default: stdin delivery)\n"
        "  -m <bytes>      RLIMIT_AS for the child (default: unlimited). Setting one also\n"
        "                  surfaces missing malloc() failure handling in the target.\n"
        "  -v              verbose (info); -vv for debug\n"
        "  -q              show the child's stdout/stderr instead of discarding it\n"
        "  -h              this help\n"
        "\n"
        "example:\n"
        "  %s -n 1000 -t 500 -- ./tests/targets/target echo-crash\n",
        argv0, argv0);
}

static bool parse_u64(const char *s, uint64_t *out)
{
    errno = 0;
    char *end = NULL;
    const unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return false;
    }
    *out = (uint64_t)v;
    return true;
}

static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        MAFL_LOG_E("cannot open input '%s': %s", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        MAFL_LOG_E("fseek failed on '%s': %s", path, strerror(errno));
        (void)fclose(f);
        return NULL;
    }
    const long size = ftell(f);
    if (size < 0) {
        MAFL_LOG_E("ftell failed on '%s': %s", path, strerror(errno));
        (void)fclose(f);
        return NULL;
    }
    rewind(f);

    /* malloc(0) may return NULL, which would be indistinguishable from failure. */
    uint8_t *buf = malloc((size_t)size + 1u);
    if (buf == NULL) {
        (void)fclose(f);
        MAFL_LOG_E("out of memory reading '%s'", path);
        return NULL;
    }

    const size_t got = fread(buf, 1, (size_t)size, f);
    (void)fclose(f);
    if (got != (size_t)size) {
        MAFL_LOG_E("short read on '%s'", path);
        free(buf);
        return NULL;
    }

    *out_len = got;
    return buf;
}

int main(int argc, char **argv)
{
    uint64_t count = 100u;
    uint64_t timeout_ms = 1000u;
    const char *input_path = NULL;
    bool file_mode = false;
    bool show_child_output = false;
    uint64_t mem_limit = 0u;
    int verbosity = 0;

    int i = 1;
    for (; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--") == 0) {
            i++;
            break;
        }
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(a, "-f") == 0) { file_mode = true; continue; }
        if (strcmp(a, "-q") == 0) { show_child_output = true; continue; }
        if (strcmp(a, "-v") == 0) { verbosity++; continue; }
        if (strcmp(a, "-vv") == 0) { verbosity += 2; continue; }

        if (i + 1 >= argc) {
            (void)fprintf(stderr, "option %s needs a value\n", a);
            return 2;
        }
        const char *val = argv[++i];

        if (strcmp(a, "-n") == 0) {
            if (!parse_u64(val, &count) || count == 0u) {
                (void)fprintf(stderr, "bad -n value: %s\n", val);
                return 2;
            }
        } else if (strcmp(a, "-t") == 0) {
            if (!parse_u64(val, &timeout_ms) || timeout_ms == 0u) {
                (void)fprintf(stderr, "bad -t value: %s\n", val);
                return 2;
            }
        } else if (strcmp(a, "-m") == 0) {
            if (!parse_u64(val, &mem_limit)) {
                (void)fprintf(stderr, "bad -m value: %s\n", val);
                return 2;
            }
        } else if (strcmp(a, "-i") == 0) {
            input_path = val;
        } else {
            (void)fprintf(stderr, "unknown option: %s\n", a);
            usage(argv[0]);
            return 2;
        }
    }

    if (i >= argc) {
        (void)fprintf(stderr, "no target specified\n\n");
        usage(argv[0]);
        return 2;
    }

    mafl_log_set_level((verbosity >= 2) ? MAFL_LOG_DEBUG
                     : (verbosity == 1) ? MAFL_LOG_INFO
                                        : MAFL_LOG_WARN);

    uint8_t *input = NULL;
    size_t input_len = 0;
    if (input_path != NULL) {
        input = read_file(input_path, &input_len);
        if (input == NULL) {
            return 1;
        }
    }

    mafl_env_audit(NULL);

    mafl_exec_cfg_t cfg;
    mafl_exec_cfg_init(&cfg);
    cfg.argv = &argv[i];
    cfg.timeout_ms = timeout_ms;
    cfg.input_mode = file_mode ? MAFL_INPUT_FILE : MAFL_INPUT_STDIN;
    cfg.quiet_child = !show_child_output;
    cfg.mem_limit_bytes = mem_limit;

    mafl_exec_t *exec = NULL;
    const mafl_err_t cerr = mafl_exec_create(&cfg, &exec);
    if (cerr != MAFL_OK) {
        MAFL_LOG_E("cannot create executor: %s", mafl_err_str(cerr));
        free(input);
        return 1;
    }

    install_shutdown_handlers();

    uint64_t n_ok = 0, n_crash = 0, n_timeout = 0, n_killed = 0, n_spawn_fail = 0;
    uint64_t n_error = 0;
    uint64_t total_ns = 0;
    uint64_t done = 0;

    const uint64_t t0 = mafl_monotonic_ns();

    for (uint64_t k = 0; k < count; k++) {
        if (g_shutdown_requested != 0) {
            (void)printf("\ninterrupted after %" PRIu64 " executions\n", done);
            break;
        }

        mafl_exec_result_t r;
        const mafl_err_t err = mafl_exec_run(exec, input, input_len, &r);
        if (err != MAFL_OK) {
            /* A fuzzer-side failure. Never counted as a target outcome (RISK-15). */
            MAFL_LOG_E("execution machinery failed: %s", mafl_err_str(err));
            n_error++;
            break;
        }

        done++;
        total_ns += r.wall_ns;

        switch (r.status) {
        case MAFL_STATUS_OK:         n_ok++; break;
        case MAFL_STATUS_CRASH:      n_crash++; break;
        case MAFL_STATUS_TIMEOUT:    n_timeout++; break;
        case MAFL_STATUS_KILLED:     n_killed++; break;
        case MAFL_STATUS_SPAWN_FAIL: n_spawn_fail++; break;
        }

        if (verbosity >= 2) {
            MAFL_LOG_D("run %" PRIu64 ": %s (signo=%d exit=%d %.2f ms)", k,
                       mafl_status_str(r.status), r.signo, r.exit_code,
                       (double)r.wall_ns / 1e6);
        }
    }

    const uint64_t elapsed = mafl_monotonic_ns() - t0;
    const double secs = (double)elapsed / 1e9;

    (void)printf("\n");
    (void)printf("executions   : %" PRIu64 "\n", done);
    (void)printf("  ok         : %" PRIu64 "\n", n_ok);
    (void)printf("  crash      : %" PRIu64 "\n", n_crash);
    (void)printf("  timeout    : %" PRIu64 "\n", n_timeout);
    (void)printf("  killed     : %" PRIu64 "\n", n_killed);
    (void)printf("  spawn-fail : %" PRIu64 "\n", n_spawn_fail);
    if (n_error > 0u) {
        (void)printf("  FUZZER ERRORS: %" PRIu64 "  (not target outcomes)\n", n_error);
    }
    (void)printf("elapsed      : %.3f s\n", secs);
    if (secs > 0.0 && done > 0u) {
        (void)printf("throughput   : %.0f exec/sec\n", (double)done / secs);
        (void)printf("mean exec    : %.3f ms\n", (double)total_ns / (double)done / 1e6);
    }

    mafl_exec_destroy(exec);
    free(input);

    /* Non-zero only when the fuzzer itself failed. A target crashing is a successful run
       of this tool, not an error — conflating the two would make CI unusable. */
    return (n_error > 0u) ? 1 : 0;
}
