#ifndef MAFL_EXEC_H
#define MAFL_EXEC_H

#include "mafl/common.h"

#include <sys/types.h>

/* Outcome of one target execution.
 *
 * The critical distinction (RISK-04): a target we SIGKILLed for exceeding its deadline
 * reports WIFSIGNALED just like a genuine crash. Conflating the two records every hang
 * as a crash and makes the entire findings set worthless. TIMEOUT, KILLED, CRASH and
 * SPAWN_FAIL are therefore separate statuses, not flags on one. */
typedef enum {
    MAFL_STATUS_OK = 0,      /* exited normally; exit_code is valid (may be non-zero) */
    MAFL_STATUS_CRASH,       /* died by a crash signal we did not send; signo is valid */
    MAFL_STATUS_TIMEOUT,     /* exceeded the deadline and we killed it */
    MAFL_STATUS_KILLED,      /* died by a non-crash signal we did not send (e.g. OOM kill) */
    MAFL_STATUS_SPAWN_FAIL   /* we could not start it — our failure, never a finding */
} mafl_status_t;

const char *mafl_status_str(mafl_status_t status);

/* True for the signals that indicate a memory-safety or arithmetic fault in the target:
 * SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL.
 *
 * SIGKILL and SIGTERM are deliberately excluded — they are how *we* stop a target, and
 * treating them as crashes is exactly RISK-04. SIGTRAP is excluded because it is a
 * debugger artifact. SIGSYS is excluded in v1 because we install no seccomp filter, so
 * we have no way to distinguish a target's own filter from a fault. */
bool mafl_signal_is_crash(int signo);

/* Pure classification of a waitpid() status. Separated from the executor precisely so it
 * can be unit-tested exhaustively without spawning anything.
 *
 * we_killed_it must be true if and only if this executor sent the fatal signal.
 * out_signo / out_exit_code may be NULL; both are always initialised when non-NULL. */
mafl_status_t mafl_classify_wait_status(int wait_status, bool we_killed_it,
                                        int *out_signo, int *out_exit_code);

typedef struct {
    mafl_status_t status;
    int exit_code;      /* meaningful only when status == MAFL_STATUS_OK */
    int signo;          /* meaningful only when status is CRASH or KILLED */
    int spawn_errno;    /* meaningful only when status == MAFL_STATUS_SPAWN_FAIL */
    uint64_t wall_ns;   /* wall time from fork() to reap */
} mafl_exec_result_t;

/* How the input reaches the target. Both modes stage the input in a real file rather
 * than a pipe: a target that does not drain stdin would otherwise block our write and
 * deadlock the fuzzer. */
typedef enum {
    MAFL_INPUT_STDIN = 0,  /* staged file is dup2'd onto fd 0 */
    MAFL_INPUT_FILE = 1    /* the "@@" token in argv is replaced by the staged file path */
} mafl_input_mode_t;

typedef struct {
    /* NULL-terminated. argv[0] is the executable path, used verbatim with execve() —
       there is no PATH search, deliberately (see ARCHITECTURE.md D5). */
    char *const *argv;

    mafl_input_mode_t input_mode;

    /* Directory for the staged input file. NULL means "/tmp". */
    const char *work_dir;

    uint64_t timeout_ms;        /* required, > 0 */
    uint64_t kill_grace_ms;     /* wait after SIGKILL before declaring failure; 0 => 1000 */

    bool disable_aslr;          /* personality(ADDR_NO_RANDOMIZE); best-effort */
    bool no_core;               /* RLIMIT_CORE = 0 */
    bool quiet_child;           /* child stdout/stderr to /dev/null */

    /* false (default): the child gets a minimal constructed environment — PATH (or a
       safe default), MAFL_SHM_ID when set in the parent, and nothing else. true: inherit
       the fuzzer's full environ verbatim; needed by targets depending on
       LD_LIBRARY_PATH or locale variables (D5). */
    bool inherit_env;

    /* Reserved for the M2 coverage transport (D8). When non-NULL, the constructed child
       environment carries MAFL_SHM_ID=shm_id so the runtime can find the coverage map
       without a later exec API break. Ignored when inherit_env is true: the parent's
       MAFL_SHM_ID passes through as-is. */
    const char *shm_id;

    uint64_t mem_limit_bytes;   /* RLIMIT_AS; 0 = unlimited (default — see D5) */
    uint64_t fsize_limit_bytes; /* RLIMIT_FSIZE; 0 = leave alone */
    long nproc_limit;           /* RLIMIT_NPROC; 0 = leave alone */
} mafl_exec_cfg_t;

/* Sensible defaults: stdin delivery, 1000 ms timeout, ASLR off, cores off, child quiet,
   no memory limit. Always call this before overriding fields, so adding a field later
   cannot leave a caller with an uninitialised one. */
void mafl_exec_cfg_init(mafl_exec_cfg_t *cfg);

typedef struct mafl_exec mafl_exec_t;

MAFL_MUST_USE mafl_err_t mafl_exec_create(const mafl_exec_cfg_t *cfg, mafl_exec_t **out);

/* Accepts NULL. Kills and reaps any in-flight child before releasing resources. */
void mafl_exec_destroy(mafl_exec_t *exec);

/* Run the target once against the given input.
 *
 * Returns MAFL_OK whenever the *execution machinery* worked, including when the target
 * crashed or hung — those are reported in out_result->status. A negative return means
 * the fuzzer failed, which is a different thing entirely (RISK-15).
 *
 * out_result is written only on MAFL_OK. */
MAFL_MUST_USE mafl_err_t mafl_exec_run(mafl_exec_t *exec, const uint8_t *input, size_t len,
                                       mafl_exec_result_t *out_result);

/* pid (and process-group id) of the most recent child. 0 before the first run.
   Exposed so tests can assert the whole process group is gone. */
pid_t mafl_exec_last_pid(const mafl_exec_t *exec);

uint64_t mafl_exec_run_count(const mafl_exec_t *exec);

/* Path of the staged input file, for diagnostics and repro output. */
const char *mafl_exec_input_path(const mafl_exec_t *exec);

/* Check the host for the configuration mistakes that quietly destroy throughput or
 * correctness: a piped core_pattern, a non-performance CPU governor, an inherited
 * SIG_IGN on SIGCHLD, free-space floor on the output filesystem, yama/ptrace_scope
 * that would block ptrace triage. Logs actionable warnings; never fails, never
 * requires root.
 *
 * audit_dir may be NULL, in which case the free-space check is skipped. When non-NULL
 * the filesystem holding that directory is statvfs'd; a floor of 512 MiB free is
 * enforced as a warning (refusing to *start* is left to the caller, which has the
 * context of whether the floor is survivable). */
void mafl_env_audit(const char *audit_dir);

#endif /* MAFL_EXEC_H */
