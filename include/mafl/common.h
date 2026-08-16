#ifndef MAFL_COMMON_H
#define MAFL_COMMON_H

/* _GNU_SOURCE is also set by the build system; defined here so that a translation
   unit that includes this header first is still correct. Must precede any libc header. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Single error convention for the whole codebase: MAFL_OK is 0, every failure is a
   negative enum. Results travel through out-parameters. See docs/CONTRIBUTING.md §2. */
typedef enum {
    MAFL_OK = 0,
    MAFL_ERR_INVAL = -1,       /* caller passed something impossible */
    MAFL_ERR_NOMEM = -2,
    MAFL_ERR_IO = -3,          /* filesystem / pipe operation failed */
    MAFL_ERR_SPAWN = -4,       /* we could not start the target (never a finding) */
    MAFL_ERR_WAIT = -5,        /* waitpid bookkeeping failed */
    MAFL_ERR_KILL_FAILED = -6, /* target survived SIGKILL past the grace period */
    MAFL_ERR_OVERFLOW = -7,
    MAFL_ERR_NOTSUP = -8,      /* kernel lacks a required facility */
    MAFL_ERR_BUSY = -9,        /* an execution is already in flight (RISK-01 guard) */
    MAFL_ERR_INTERNAL = -10
} mafl_err_t;

const char *mafl_err_str(mafl_err_t err);

typedef enum {
    MAFL_LOG_ERROR = 0,
    MAFL_LOG_WARN = 1,
    MAFL_LOG_INFO = 2,
    MAFL_LOG_DEBUG = 3
} mafl_log_level_t;

void mafl_log_set_level(mafl_log_level_t level);
mafl_log_level_t mafl_log_get_level(void);

/* Never call from a signal handler: not async-signal-safe. */
void mafl_log(mafl_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define MAFL_LOG_E(...) mafl_log(MAFL_LOG_ERROR, __VA_ARGS__)
#define MAFL_LOG_W(...) mafl_log(MAFL_LOG_WARN, __VA_ARGS__)
#define MAFL_LOG_I(...) mafl_log(MAFL_LOG_INFO, __VA_ARGS__)
#define MAFL_LOG_D(...) mafl_log(MAFL_LOG_DEBUG, __VA_ARGS__)

#define MAFL_MUST_USE __attribute__((warn_unused_result))
#define MAFL_UNUSED(x) ((void)(x))

/* Monotonic nanosecond clock. */
uint64_t mafl_monotonic_ns(void);

#endif /* MAFL_COMMON_H */
