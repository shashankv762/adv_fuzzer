#include "mafl/common.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static mafl_log_level_t g_log_level = MAFL_LOG_INFO;

void mafl_log_set_level(mafl_log_level_t level) { g_log_level = level; }

mafl_log_level_t mafl_log_get_level(void) { return g_log_level; }

void mafl_log(mafl_log_level_t level, const char *fmt, ...)
{
    static const char *const tags[] = { "ERROR", "WARN ", "INFO ", "DEBUG" };

    if (level > g_log_level) {
        return;
    }
    if (level < MAFL_LOG_ERROR || level > MAFL_LOG_DEBUG) {
        level = MAFL_LOG_ERROR;
    }

    /* stderr so that log output never contaminates a target's stdout when the fuzzer is
       used in a pipeline. */
    (void)fprintf(stderr, "[mafl %s] ", tags[level]);

    va_list ap;
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);

    (void)fputc('\n', stderr);
    (void)fflush(stderr);
}

const char *mafl_err_str(mafl_err_t err)
{
    switch (err) {
    case MAFL_OK:              return "ok";
    case MAFL_ERR_INVAL:       return "invalid argument";
    case MAFL_ERR_NOMEM:       return "out of memory";
    case MAFL_ERR_IO:          return "i/o error";
    case MAFL_ERR_SPAWN:       return "failed to spawn target";
    case MAFL_ERR_WAIT:        return "waitpid failed";
    case MAFL_ERR_KILL_FAILED: return "target survived SIGKILL";
    case MAFL_ERR_OVERFLOW:    return "integer overflow";
    case MAFL_ERR_NOTSUP:      return "not supported on this kernel";
    case MAFL_ERR_BUSY:        return "execution already in flight";
    case MAFL_ERR_INTERNAL:    return "internal error";
    }
    return "unknown error";
}

uint64_t mafl_monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
