/* M1 execution engine: fork + execve + waitpid, one child at a time.
 *
 * Design notes that are not obvious from the code:
 *
 *  - Timeouts use pidfd_open(2) + ppoll(2) rather than setitimer + SIGALRM. No signal
 *    handler is installed anywhere on this path, so nothing here has to be
 *    async-signal-safe and there is no global signal state to restore. See
 *    docs/ARCHITECTURE.md §1.10 and §4.
 *
 *  - Our own kill intent is tracked explicitly (`we_killed_it`) and consulted *before* the
 *    signal number when classifying. A timeout SIGKILL must never be recorded as a target
 *    crash — that is RISK-04, and it silently poisons the entire findings set.
 *
 *  - Child setup failure is reported through a CLOEXEC status pipe, not through exit
 *    codes. The pipe closes automatically on a successful execve, so the parent sees EOF;
 *    on failure the child writes (stage, errno) and exits. Exit-code markers would be
 *    ambiguous against a target that legitimately exits with the same value, and
 *    "infrastructure failure misread as a finding" is RISK-15.
 *
 *  - The input is staged in a real file, reused across runs, for both delivery modes. A
 *    pipe would deadlock the fuzzer against any target that does not drain stdin.
 *
 *  - Exactly one child may be in flight, checked before every fork (RISK-01).
 */

#include "mafl/exec.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define MAFL_INPUT_PLACEHOLDER "@@"
#define MAFL_DEFAULT_KILL_GRACE_MS 1000u

/* glibc did not expose a pidfd_open() wrapper until 2.36 and our baseline is 2.31
   (ARCHITECTURE.md D7), so go through syscall(2). The syscall itself is Linux 5.3+. */
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

static int mafl_pidfd_open(pid_t pid)
{
    return (int)syscall(__NR_pidfd_open, pid, 0U);
}

/* Which child-setup step failed. Sent over the status pipe with the corresponding errno
   so a setup failure produces an actionable message instead of a mystery exit code. */
typedef enum {
    CHILD_STAGE_SETPGID = 1,
    CHILD_STAGE_PDEATHSIG,
    CHILD_STAGE_PARENT_GONE,
    CHILD_STAGE_RLIMIT_CORE,
    CHILD_STAGE_RLIMIT_AS,
    CHILD_STAGE_RLIMIT_FSIZE,
    CHILD_STAGE_RLIMIT_NPROC,
    CHILD_STAGE_DUP_STDIN,
    CHILD_STAGE_DUP_STDOUT,
    CHILD_STAGE_EXECVE
} child_stage_t;

typedef struct {
    int32_t stage;
    int32_t err;
} child_fail_msg_t;

static const char *child_stage_str(int32_t stage)
{
    switch (stage) {
    case CHILD_STAGE_SETPGID:      return "setpgid";
    case CHILD_STAGE_PDEATHSIG:    return "prctl(PR_SET_PDEATHSIG)";
    case CHILD_STAGE_PARENT_GONE:  return "parent exited before setup completed";
    case CHILD_STAGE_RLIMIT_CORE:  return "setrlimit(RLIMIT_CORE)";
    case CHILD_STAGE_RLIMIT_AS:    return "setrlimit(RLIMIT_AS)";
    case CHILD_STAGE_RLIMIT_FSIZE: return "setrlimit(RLIMIT_FSIZE)";
    case CHILD_STAGE_RLIMIT_NPROC: return "setrlimit(RLIMIT_NPROC)";
    case CHILD_STAGE_DUP_STDIN:    return "dup2(stdin)";
    case CHILD_STAGE_DUP_STDOUT:   return "dup2(stdout/stderr)";
    case CHILD_STAGE_EXECVE:       return "execve";
    default:                       return "unknown stage";
    }
}

struct mafl_exec {
    mafl_exec_cfg_t cfg;

    /* Owned copy of argv, so the caller's array need not outlive us. In FILE mode the
       "@@" element is replaced by input_path. */
    char **argv;
    size_t argc;

    char *input_path;
    int input_fd;    /* staged input, kept open across runs; O_CLOEXEC */
    int devnull_fd;  /* always open: also used to keep a target off the real stdin */

    pid_t last_pid;
    uint64_t run_count;
};

void mafl_exec_cfg_init(mafl_exec_cfg_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->input_mode = MAFL_INPUT_STDIN;
    cfg->timeout_ms = 1000u;
    cfg->kill_grace_ms = MAFL_DEFAULT_KILL_GRACE_MS;
    cfg->disable_aslr = true;
    cfg->no_core = true;
    cfg->quiet_child = true;
    cfg->mem_limit_bytes = 0u; /* unlimited, matching AFL++'s default (D5) */
}

const char *mafl_status_str(mafl_status_t status)
{
    switch (status) {
    case MAFL_STATUS_OK:         return "ok";
    case MAFL_STATUS_CRASH:      return "crash";
    case MAFL_STATUS_TIMEOUT:    return "timeout";
    case MAFL_STATUS_KILLED:     return "killed";
    case MAFL_STATUS_SPAWN_FAIL: return "spawn-fail";
    }
    return "unknown";
}

bool mafl_signal_is_crash(int signo)
{
    switch (signo) {
    case SIGSEGV:
    case SIGABRT:
    case SIGBUS:
    case SIGFPE:
    case SIGILL:
        return true;
    default:
        /* SIGKILL/SIGTERM are how *we* stop a target (RISK-04). SIGTRAP is a debugger
           artifact. SIGSYS would need a seccomp filter we do not install in v1. */
        return false;
    }
}

mafl_status_t mafl_classify_wait_status(int wait_status, bool we_killed_it,
                                        int *out_signo, int *out_exit_code)
{
    if (out_signo != NULL) {
        *out_signo = 0;
    }
    if (out_exit_code != NULL) {
        *out_exit_code = 0;
    }

    if (WIFEXITED(wait_status)) {
        if (out_exit_code != NULL) {
            *out_exit_code = WEXITSTATUS(wait_status);
        }
        /* A target can exit normally even after we asked it to stop — it raced our kill
           and won. That is a completed execution, not a timeout. */
        return MAFL_STATUS_OK;
    }

    if (WIFSIGNALED(wait_status)) {
        const int signo = WTERMSIG(wait_status);
        if (out_signo != NULL) {
            *out_signo = signo;
        }
        /* Intent first, signal second. This ordering is the entire point. */
        if (we_killed_it) {
            return MAFL_STATUS_TIMEOUT;
        }
        return mafl_signal_is_crash(signo) ? MAFL_STATUS_CRASH : MAFL_STATUS_KILLED;
    }

    /* Neither exited nor signalled. We never pass WUNTRACED/WCONTINUED, so this is
       unreachable in practice; report it rather than guess. */
    return MAFL_STATUS_KILLED;
}

static mafl_err_t dup_argv(const mafl_exec_cfg_t *cfg, char ***out_argv, size_t *out_argc)
{
    size_t n = 0;
    while (cfg->argv[n] != NULL) {
        if (n == SIZE_MAX - 1u) {
            return MAFL_ERR_OVERFLOW;
        }
        n++;
    }
    if (n == 0u) {
        return MAFL_ERR_INVAL;
    }

    char **argv = calloc(n + 1u, sizeof(*argv));
    if (argv == NULL) {
        return MAFL_ERR_NOMEM;
    }

    for (size_t i = 0; i < n; i++) {
        argv[i] = strdup(cfg->argv[i]);
        if (argv[i] == NULL) {
            for (size_t j = 0; j < i; j++) {
                free(argv[j]);
            }
            free(argv);
            return MAFL_ERR_NOMEM;
        }
    }

    *out_argv = argv;
    *out_argc = n;
    return MAFL_OK;
}

static void free_argv(char **argv, size_t argc)
{
    if (argv == NULL) {
        return;
    }
    for (size_t i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
}

/* Replace the "@@" token with the staged input path. Exactly one occurrence is required
   in FILE mode: zero means the target would never see the input, which is a configuration
   error worth failing on rather than silently fuzzing nothing. */
static mafl_err_t substitute_input_placeholder(mafl_exec_t *exec)
{
    size_t found = 0;

    for (size_t i = 0; i < exec->argc; i++) {
        if (strcmp(exec->argv[i], MAFL_INPUT_PLACEHOLDER) != 0) {
            continue;
        }
        char *dup = strdup(exec->input_path);
        if (dup == NULL) {
            return MAFL_ERR_NOMEM;
        }
        free(exec->argv[i]);
        exec->argv[i] = dup;
        found++;
    }

    if (found != 1u) {
        MAFL_LOG_E("MAFL_INPUT_FILE mode needs exactly one \"@@\" in argv, found %zu", found);
        return MAFL_ERR_INVAL;
    }
    return MAFL_OK;
}

static mafl_err_t create_input_file(mafl_exec_t *exec)
{
    const char *dir = (exec->cfg.work_dir != NULL) ? exec->cfg.work_dir : "/tmp";
    const char suffix[] = "/mafl-input-XXXXXX";
    const size_t dir_len = strlen(dir);

    if (dir_len > SIZE_MAX - sizeof(suffix)) {
        return MAFL_ERR_OVERFLOW;
    }

    char *path = malloc(dir_len + sizeof(suffix));
    if (path == NULL) {
        return MAFL_ERR_NOMEM;
    }
    memcpy(path, dir, dir_len);
    memcpy(path + dir_len, suffix, sizeof(suffix));

    /* O_CLOEXEC: the staging descriptor must not leak into the target, which would both
       leak a descriptor per exec and hand the target a writable handle to its own input.
       In STDIN mode we dup2() a copy, and dup2() clears FD_CLOEXEC on the copy. */
    const int fd = mkostemp(path, O_CLOEXEC);
    if (fd < 0) {
        MAFL_LOG_E("mkostemp(%s) failed: %s", path, strerror(errno));
        free(path);
        return MAFL_ERR_IO;
    }

    exec->input_path = path;
    exec->input_fd = fd;
    return MAFL_OK;
}

mafl_err_t mafl_exec_create(const mafl_exec_cfg_t *cfg, mafl_exec_t **out)
{
    if (cfg == NULL || out == NULL || cfg->argv == NULL || cfg->argv[0] == NULL) {
        return MAFL_ERR_INVAL;
    }
    if (cfg->timeout_ms == 0u) {
        return MAFL_ERR_INVAL;
    }

    mafl_exec_t *exec = calloc(1, sizeof(*exec));
    if (exec == NULL) {
        return MAFL_ERR_NOMEM;
    }
    exec->cfg = *cfg;
    exec->input_fd = -1;
    exec->devnull_fd = -1;
    if (exec->cfg.kill_grace_ms == 0u) {
        exec->cfg.kill_grace_ms = MAFL_DEFAULT_KILL_GRACE_MS;
    }

    mafl_err_t err = dup_argv(cfg, &exec->argv, &exec->argc);
    if (err != MAFL_OK) {
        goto fail;
    }

    err = create_input_file(exec);
    if (err != MAFL_OK) {
        goto fail;
    }

    if (exec->cfg.input_mode == MAFL_INPUT_FILE) {
        err = substitute_input_placeholder(exec);
        if (err != MAFL_OK) {
            goto fail;
        }
    }

    /* Opened unconditionally. Besides silencing the child, this is what keeps a target in
       FILE mode off the real stdin — otherwise a target that reads stdin would block on
       the terminal and every run would time out. */
    exec->devnull_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (exec->devnull_fd < 0) {
        MAFL_LOG_E("open(/dev/null) failed: %s", strerror(errno));
        err = MAFL_ERR_IO;
        goto fail;
    }

    /* An inherited SIG_IGN on SIGCHLD makes waitpid() fail with ECHILD and breaks reaping
       in a maximally confusing way (RISK-03). Reset it: we do all our waiting explicitly. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        MAFL_LOG_W("could not reset SIGCHLD to SIG_DFL: %s", strerror(errno));
    }

    /* Fail fast and clearly if the target is not runnable, rather than reporting
       SPAWN_FAIL once per input for the rest of the campaign. */
    if (access(exec->argv[0], X_OK) != 0) {
        MAFL_LOG_E("target '%s' is not executable: %s", exec->argv[0], strerror(errno));
        err = MAFL_ERR_INVAL;
        goto fail;
    }

    *out = exec;
    return MAFL_OK;

fail:
    mafl_exec_destroy(exec);
    return err;
}

void mafl_exec_destroy(mafl_exec_t *exec)
{
    if (exec == NULL) {
        return;
    }

    /* Never leave a child behind, even on a teardown path (RISK-01). Kill the group while
       the leader is still unreaped so the pgid cannot have been recycled. */
    if (exec->last_pid > 0) {
        (void)kill(-exec->last_pid, SIGKILL);
        (void)kill(exec->last_pid, SIGKILL);
        int status = 0;
        while (waitpid(exec->last_pid, &status, 0) < 0 && errno == EINTR) {
            /* retry */
        }
    }

    if (exec->input_fd >= 0) {
        (void)close(exec->input_fd);
    }
    if (exec->devnull_fd >= 0) {
        (void)close(exec->devnull_fd);
    }
    if (exec->input_path != NULL) {
        (void)unlink(exec->input_path);
        free(exec->input_path);
    }
    free_argv(exec->argv, exec->argc);
    free(exec);
}

static mafl_err_t stage_input(mafl_exec_t *exec, const uint8_t *input, size_t len)
{
    if (ftruncate(exec->input_fd, 0) != 0) {
        MAFL_LOG_E("ftruncate failed: %s", strerror(errno));
        return MAFL_ERR_IO;
    }

    size_t off = 0;
    while (off < len) {
        const ssize_t n = pwrite(exec->input_fd, input + off, len - off, (off_t)off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            MAFL_LOG_E("pwrite failed: %s", strerror(errno));
            return MAFL_ERR_IO;
        }
        if (n == 0) {
            return MAFL_ERR_IO;
        }
        off += (size_t)n;
    }

    /* The child inherits this file description's offset via dup2 in STDIN mode, so it has
       to be rewound before every run. */
    if (lseek(exec->input_fd, 0, SEEK_SET) == (off_t)-1) {
        MAFL_LOG_E("lseek failed: %s", strerror(errno));
        return MAFL_ERR_IO;
    }
    return MAFL_OK;
}

/* Report a setup failure to the parent and exit. Only async-signal-safe calls are used.
   A short write is not retried: the parent treats any failure to read a full message as a
   generic spawn failure, which is the same conclusion. */
static void child_fail(int errfd, child_stage_t stage, int err)
{
    const child_fail_msg_t msg = { .stage = (int32_t)stage, .err = (int32_t)err };
    ssize_t n;
    do {
        n = write(errfd, &msg, sizeof(msg));
    } while (n < 0 && errno == EINTR);
    _exit(126);
}

/* Everything here runs in the child between fork() and execve(). Only async-signal-safe
 * calls are permitted (no malloc, no stdio): the child shares the parent's memory state
 * until exec, and a non-reentrant libc call can deadlock. */
static void child_setup_and_exec(const mafl_exec_t *exec, pid_t parent_pid, int errfd)
{
    /* Own process group, so a timeout kill takes out the target *and* anything it forked
       (RISK-01). Must happen before exec so the target cannot escape it. */
    if (setpgid(0, 0) != 0) {
        child_fail(errfd, CHILD_STAGE_SETPGID, errno);
    }

    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) {
        child_fail(errfd, CHILD_STAGE_PDEATHSIG, errno);
    }

    /* PR_SET_PDEATHSIG has a documented race: if the parent died between fork() and the
       prctl above, the signal was never armed and never will be. Re-check. */
    if (getppid() != parent_pid) {
        child_fail(errfd, CHILD_STAGE_PARENT_GONE, 0);
    }

    if (exec->cfg.no_core) {
        const struct rlimit rl = { .rlim_cur = 0, .rlim_max = 0 };
        if (setrlimit(RLIMIT_CORE, &rl) != 0) {
            child_fail(errfd, CHILD_STAGE_RLIMIT_CORE, errno);
        }
    }

    if (exec->cfg.mem_limit_bytes > 0u) {
        const struct rlimit rl = { .rlim_cur = (rlim_t)exec->cfg.mem_limit_bytes,
                                   .rlim_max = (rlim_t)exec->cfg.mem_limit_bytes };
        if (setrlimit(RLIMIT_AS, &rl) != 0) {
            child_fail(errfd, CHILD_STAGE_RLIMIT_AS, errno);
        }
    }

    if (exec->cfg.fsize_limit_bytes > 0u) {
        const struct rlimit rl = { .rlim_cur = (rlim_t)exec->cfg.fsize_limit_bytes,
                                   .rlim_max = (rlim_t)exec->cfg.fsize_limit_bytes };
        if (setrlimit(RLIMIT_FSIZE, &rl) != 0) {
            child_fail(errfd, CHILD_STAGE_RLIMIT_FSIZE, errno);
        }
    }

    if (exec->cfg.nproc_limit > 0) {
        const struct rlimit rl = { .rlim_cur = (rlim_t)exec->cfg.nproc_limit,
                                   .rlim_max = (rlim_t)exec->cfg.nproc_limit };
        if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
            child_fail(errfd, CHILD_STAGE_RLIMIT_NPROC, errno);
        }
    }

    /* Best-effort: some container configurations block personality(). Losing ASLR control
       degrades crash reproducibility but does not break correctness, so continue. */
    if (exec->cfg.disable_aslr) {
        (void)personality(ADDR_NO_RANDOMIZE);
    }

    const int stdin_src = (exec->cfg.input_mode == MAFL_INPUT_STDIN) ? exec->input_fd
                                                                    : exec->devnull_fd;
    if (dup2(stdin_src, STDIN_FILENO) < 0) {
        child_fail(errfd, CHILD_STAGE_DUP_STDIN, errno);
    }

    if (exec->cfg.quiet_child) {
        if (dup2(exec->devnull_fd, STDOUT_FILENO) < 0 ||
            dup2(exec->devnull_fd, STDERR_FILENO) < 0) {
            child_fail(errfd, CHILD_STAGE_DUP_STDOUT, errno);
        }
    }

    /* execve with an explicit path: no PATH search in a tool that gets pointed at
       untrusted directory trees (D5). environ is inherited deliberately in v1; a minimal
       constructed environment is M6 hardening work. */
    (void)execve(exec->argv[0], exec->argv, environ);

    child_fail(errfd, CHILD_STAGE_EXECVE, errno);
}

/* Read the child's setup-failure message, if any. Returns true when the child failed
 * before exec. A successful execve closes the write end (O_CLOEXEC), so the parent simply
 * sees EOF — which is why this is unambiguous where an exit-code marker would not be. */
static bool read_child_failure(int errfd, child_fail_msg_t *out)
{
    size_t got = 0;
    uint8_t buf[sizeof(child_fail_msg_t)];

    while (got < sizeof(buf)) {
        const ssize_t n = read(errfd, buf + got, sizeof(buf) - got);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (n == 0) {
            break; /* EOF: exec succeeded, or the child died without reporting */
        }
        if (errno == EINTR) {
            continue;
        }
        break;
    }

    if (got != sizeof(buf)) {
        return false;
    }
    memcpy(out, buf, sizeof(*out));
    return true;
}

/* Wait for the child with a deadline, using pidfd + ppoll so neither a signal handler nor
 * SIGALRM is involved. Sets *out_timed_out and leaves the child unreaped. */
static mafl_err_t wait_with_deadline(int pidfd, uint64_t timeout_ms, bool *out_timed_out)
{
    const uint64_t deadline = mafl_monotonic_ns() + timeout_ms * 1000000ULL;

    for (;;) {
        const uint64_t now = mafl_monotonic_ns();
        if (now >= deadline) {
            *out_timed_out = true;
            return MAFL_OK;
        }

        const uint64_t remain_ns = deadline - now;
        const struct timespec ts = {
            .tv_sec = (time_t)(remain_ns / 1000000000ULL),
            .tv_nsec = (long)(remain_ns % 1000000000ULL)
        };

        struct pollfd pfd = { .fd = pidfd, .events = POLLIN, .revents = 0 };
        const int rc = ppoll(&pfd, 1, &ts, NULL);

        if (rc > 0) {
            /* Readable means *terminated*, not reaped — the caller still has to
               waitpid(). Forgetting that is a slow zombie leak (RISK-03). */
            *out_timed_out = false;
            return MAFL_OK;
        }
        if (rc == 0) {
            *out_timed_out = true;
            return MAFL_OK;
        }
        if (errno == EINTR) {
            continue; /* re-derive the remaining time from the monotonic clock */
        }
        MAFL_LOG_E("ppoll failed: %s", strerror(errno));
        return MAFL_ERR_IO;
    }
}

/* Reap a child we have SIGKILLed, allowing a bounded grace period: a child stuck in an
 * uninterruptible kernel wait can briefly outlive its SIGKILL. Outliving the grace period
 * is a hard error, not something to ignore. */
static mafl_err_t reap_killed(pid_t pid, uint64_t grace_ms, int *out_status)
{
    const uint64_t deadline = mafl_monotonic_ns() + grace_ms * 1000000ULL;

    for (;;) {
        const pid_t r = waitpid(pid, out_status, WNOHANG);
        if (r == pid) {
            return MAFL_OK;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            MAFL_LOG_E("waitpid(%d) failed: %s", (int)pid, strerror(errno));
            return MAFL_ERR_WAIT;
        }
        if (mafl_monotonic_ns() >= deadline) {
            MAFL_LOG_E("pid %d survived SIGKILL for %llu ms", (int)pid,
                       (unsigned long long)grace_ms);
            return MAFL_ERR_KILL_FAILED;
        }
        const struct timespec nap = { .tv_sec = 0, .tv_nsec = 200000L }; /* 0.2 ms */
        (void)nanosleep(&nap, NULL);
    }
}

static mafl_err_t reap_blocking(pid_t pid, int *out_status)
{
    for (;;) {
        const pid_t r = waitpid(pid, out_status, 0);
        if (r == pid) {
            return MAFL_OK;
        }
        if (r < 0 && errno == EINTR) {
            continue;
        }
        MAFL_LOG_E("waitpid(%d) failed: %s", (int)pid, strerror(errno));
        return MAFL_ERR_WAIT;
    }
}

mafl_err_t mafl_exec_run(mafl_exec_t *exec, const uint8_t *input, size_t len,
                         mafl_exec_result_t *out_result)
{
    if (exec == NULL || out_result == NULL || (input == NULL && len > 0u)) {
        return MAFL_ERR_INVAL;
    }
    /* Exactly one child in flight, ever (RISK-01). last_pid is cleared after each reap,
       so a non-zero value here means a previous run leaked. */
    if (exec->last_pid != 0) {
        return MAFL_ERR_BUSY;
    }

    mafl_err_t err = stage_input(exec, input, len);
    if (err != MAFL_OK) {
        return err;
    }

    int errpipe[2];
    if (pipe2(errpipe, O_CLOEXEC) != 0) {
        MAFL_LOG_E("pipe2 failed: %s", strerror(errno));
        return MAFL_ERR_IO;
    }

    const pid_t parent_pid = getpid();
    const uint64_t t_start = mafl_monotonic_ns();

    const pid_t pid = fork();
    if (pid < 0) {
        MAFL_LOG_E("fork failed: %s", strerror(errno));
        (void)close(errpipe[0]);
        (void)close(errpipe[1]);
        return MAFL_ERR_SPAWN;
    }
    if (pid == 0) {
        (void)close(errpipe[0]);
        child_setup_and_exec(exec, parent_pid, errpipe[1]);
        _exit(126); /* unreachable: child_setup_and_exec never returns */
    }

    exec->last_pid = pid;
    (void)close(errpipe[1]); /* parent must drop its write end or read() never sees EOF */

    /* Also set the group from the parent, closing the window where we might signal the
       group before the child has created it. EACCES/ESRCH here are both benign. */
    (void)setpgid(pid, pid);

    child_fail_msg_t fail_msg = { 0, 0 };
    const bool child_failed = read_child_failure(errpipe[0], &fail_msg);
    (void)close(errpipe[0]);

    if (child_failed) {
        int scratch = 0;
        (void)reap_blocking(pid, &scratch);
        exec->last_pid = 0;

        MAFL_LOG_E("child setup failed at %s: %s", child_stage_str(fail_msg.stage),
                   (fail_msg.err != 0) ? strerror(fail_msg.err) : "n/a");

        mafl_exec_result_t result;
        memset(&result, 0, sizeof(result));
        result.status = MAFL_STATUS_SPAWN_FAIL;
        result.spawn_errno = fail_msg.err;
        result.wall_ns = mafl_monotonic_ns() - t_start;
        exec->run_count++;
        *out_result = result;
        return MAFL_OK;
    }

    int pidfd = mafl_pidfd_open(pid);
    if (pidfd < 0) {
        const int saved = errno;
        /* Without pidfd we cannot enforce a deadline, and a hanging target would wedge the
           campaign indefinitely. Fail loudly rather than degrade silently. */
        MAFL_LOG_E("pidfd_open failed: %s (Linux 5.3+ required)", strerror(saved));
        (void)kill(-pid, SIGKILL);
        (void)kill(pid, SIGKILL);
        int scratch = 0;
        (void)reap_killed(pid, exec->cfg.kill_grace_ms, &scratch);
        exec->last_pid = 0;
        return (saved == ENOSYS) ? MAFL_ERR_NOTSUP : MAFL_ERR_IO;
    }

    bool timed_out = false;
    err = wait_with_deadline(pidfd, exec->cfg.timeout_ms, &timed_out);
    (void)close(pidfd);

    if (err != MAFL_OK) {
        (void)kill(-pid, SIGKILL);
        (void)kill(pid, SIGKILL);
        int scratch = 0;
        (void)reap_killed(pid, exec->cfg.kill_grace_ms, &scratch);
        exec->last_pid = 0;
        return err;
    }

    int wait_status = 0;
    bool we_killed_it = false;

    if (timed_out) {
        we_killed_it = true;
        (void)kill(-pid, SIGKILL);
        (void)kill(pid, SIGKILL); /* in case setpgid never took effect */
        err = reap_killed(pid, exec->cfg.kill_grace_ms, &wait_status);
    } else {
        /* The target has terminated but may have left children of its own running. Sweep
           the group *before* reaping the leader: once the leader is reaped and the group
           is empty, the pgid can be recycled and kill(-pid) could hit an unrelated
           process. The leader is a zombie at this point, so it holds the pgid for us. */
        (void)kill(-pid, SIGKILL);
        err = reap_blocking(pid, &wait_status);
    }

    exec->last_pid = 0;
    if (err != MAFL_OK) {
        return err;
    }

    mafl_exec_result_t result;
    memset(&result, 0, sizeof(result));
    result.wall_ns = mafl_monotonic_ns() - t_start;
    result.status = mafl_classify_wait_status(wait_status, we_killed_it,
                                              &result.signo, &result.exit_code);
    exec->run_count++;
    *out_result = result;
    return MAFL_OK;
}

pid_t mafl_exec_last_pid(const mafl_exec_t *exec)
{
    return (exec != NULL) ? exec->last_pid : 0;
}

uint64_t mafl_exec_run_count(const mafl_exec_t *exec)
{
    return (exec != NULL) ? exec->run_count : 0u;
}

const char *mafl_exec_input_path(const mafl_exec_t *exec)
{
    return (exec != NULL) ? exec->input_path : NULL;
}
