#ifndef MAFL_TEST_UTIL_H
#define MAFL_TEST_UTIL_H

/* Minimal test harness. No third-party test framework, consistent with the no-dependency
 * rule in docs/CONTRIBUTING.md §1.
 *
 * Assertions print the actual and expected values, because the development host is
 * Windows without WSL (RISK-19) and CI output is the only debugging signal available.
 *
 * Helpers are `static inline` so that a test file which does not use one of them still
 * compiles under -Wunused-function -Werror. */

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_checks_run;
static int g_checks_failed;
static const char *g_current_test = "(none)";

#define TEST_BEGIN(name)                                                               \
    do {                                                                               \
        g_current_test = (name);                                                       \
        (void)printf("  -- %s\n", (name));                                             \
        (void)fflush(stdout);                                                          \
    } while (0)

static inline void test_failf(const char *file, int line, const char *fmt, ...)
{
    g_checks_failed++;
    (void)fprintf(stderr, "FAIL [%s] %s:%d: ", g_current_test, file, line);
    va_list ap;
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fputc('\n', stderr);
    (void)fflush(stderr);
}

#define CHECK(cond)                                                                    \
    do {                                                                               \
        g_checks_run++;                                                                \
        if (!(cond)) {                                                                 \
            test_failf(__FILE__, __LINE__, "CHECK(%s) failed", #cond);                 \
        }                                                                              \
    } while (0)

#define CHECK_EQ_INT(actual, expected)                                                 \
    do {                                                                               \
        g_checks_run++;                                                                \
        const long long a_ = (long long)(actual);                                      \
        const long long e_ = (long long)(expected);                                    \
        if (a_ != e_) {                                                                \
            test_failf(__FILE__, __LINE__, "%s: got %lld, expected %lld (%s)",         \
                       #actual, a_, e_, #expected);                                    \
        }                                                                              \
    } while (0)

/* Status assertions print the symbolic name: "got crash, expected timeout" is immediately
   actionable where "got 1, expected 2" is not. */
#define CHECK_EQ_STATUS(actual, expected)                                              \
    do {                                                                               \
        g_checks_run++;                                                                \
        const mafl_status_t a_ = (actual);                                              \
        const mafl_status_t e_ = (expected);                                            \
        if (a_ != e_) {                                                                \
            test_failf(__FILE__, __LINE__, "%s: got %s, expected %s",                  \
                       #actual, mafl_status_str(a_), mafl_status_str(e_));              \
        }                                                                              \
    } while (0)

#define CHECK_EQ_ERR(actual, expected)                                                 \
    do {                                                                               \
        g_checks_run++;                                                                \
        const mafl_err_t a_ = (actual);                                                \
        const mafl_err_t e_ = (expected);                                              \
        if (a_ != e_) {                                                                \
            test_failf(__FILE__, __LINE__, "%s: got %s, expected %s",                  \
                       #actual, mafl_err_str(a_), mafl_err_str(e_));                   \
        }                                                                              \
    } while (0)

#define CHECK_EQ_SIGNAL(actual, expected)                                              \
    do {                                                                               \
        g_checks_run++;                                                                \
        const int a_ = (actual);                                                       \
        const int e_ = (expected);                                                      \
        if (a_ != e_) {                                                                \
            test_failf(__FILE__, __LINE__, "%s: got signal %d (%s), expected %d (%s)", \
                       #actual, a_, strsignal(a_), e_, strsignal(e_));                 \
        }                                                                              \
    } while (0)

static inline int test_summary(const char *suite)
{
    if (g_checks_failed == 0) {
        (void)printf("PASS %s (%d checks)\n", suite, g_checks_run);
        return 0;
    }
    (void)printf("FAIL %s (%d/%d checks failed)\n", suite, g_checks_failed, g_checks_run);
    return 1;
}

/* Number of open descriptors. Used for equality assertions, not tolerance: a slow leak on
   a rare error path is exactly the failure mode being hunted (RISK-11). */
static inline int count_open_fds(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return -1;
    }
    int n = 0;
    const struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] != '.') {
            n++;
        }
    }
    (void)closedir(d);
    return n; /* includes this directory's own descriptor, consistently */
}

/* True when no unreaped children remain. Any leaked child is a RISK-03 failure. */
static inline int no_children_remain(void)
{
    int status = 0;
    const pid_t r = waitpid(-1, &status, WNOHANG);
    if (r == 0) {
        return 0; /* a child exists and is still running */
    }
    if (r > 0) {
        return 0; /* just reaped a leaked child */
    }
    return (errno == ECHILD) ? 1 : 0;
}

/* True when any process in the given process group still exists. */
static inline int pgroup_alive(pid_t pgid)
{
    if (pgid <= 0) {
        return 0;
    }
    if (kill(-pgid, 0) == 0) {
        return 1;
    }
    return (errno == EPERM) ? 1 : 0;
}

/* argv storage for a test invocation.
 *
 * The build uses -Wwrite-strings (so string literals are const) and -Wcast-qual (so they
 * cannot be cast back), while execve needs a mutable char *argv[]. Copying into these
 * buffers keeps the tests warning-clean without weakening the flags. */
typedef struct {
    char target[4096];
    char mode[64];
    char at[4];
    char *argv[4];
} test_argv_t;

static inline void test_argv_init(test_argv_t *t, const char *target, const char *mode,
                                  int with_at)
{
    (void)snprintf(t->target, sizeof(t->target), "%s", target);
    (void)snprintf(t->mode, sizeof(t->mode), "%s", (mode != NULL) ? mode : "");
    (void)snprintf(t->at, sizeof(t->at), "@@");

    t->argv[0] = t->target;
    if (mode == NULL) {
        t->argv[1] = NULL;
        t->argv[2] = NULL;
    } else if (with_at) {
        t->argv[1] = t->mode;
        t->argv[2] = t->at;
    } else {
        t->argv[1] = t->mode;
        t->argv[2] = NULL;
    }
    t->argv[3] = NULL;
}

#endif /* MAFL_TEST_UTIL_H */
