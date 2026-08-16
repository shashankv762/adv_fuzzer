/* Integration tests for the M1 execution engine: real fork/execve/waitpid against the
 * purpose-built targets in tests/targets/.
 *
 * The resource-leak tests here are the ones that matter most. They use *equality*, not
 * tolerance, because the failure mode being hunted is a slow leak on a rarely-taken error
 * path — the kind that only surfaces at hour six of an unattended run (RISK-03, RISK-11).
 *
 * The target path arrives as argv[1] so the Makefile controls it. */

#include "mafl/exec.h"
#include "../test_util.h"

#include <time.h>

static const char *g_target;

static void cfg_for(mafl_exec_cfg_t *cfg, test_argv_t *ta, const char *mode,
                    uint64_t timeout_ms)
{
    mafl_exec_cfg_init(cfg);
    test_argv_init(ta, g_target, mode, 0);
    cfg->argv = ta->argv;
    cfg->timeout_ms = timeout_ms;
}

/* Run one input against one mode. Returns 0 when the machinery worked — a negative
   mafl_err_t is a fuzzer bug, categorically different from any target outcome. */
static int run_once(const char *mode, const uint8_t *input, size_t len,
                    uint64_t timeout_ms, mafl_exec_result_t *out)
{
    test_argv_t ta;
    mafl_exec_cfg_t cfg;
    cfg_for(&cfg, &ta, mode, timeout_ms);

    mafl_exec_t *exec = NULL;
    const mafl_err_t err = mafl_exec_create(&cfg, &exec);
    g_checks_run++;
    if (err != MAFL_OK) {
        test_failf(__FILE__, __LINE__, "mafl_exec_create(%s) failed: %s", mode,
                   mafl_err_str(err));
        return -1;
    }

    const mafl_err_t rerr = mafl_exec_run(exec, input, len, out);
    g_checks_run++;
    if (rerr != MAFL_OK) {
        test_failf(__FILE__, __LINE__, "mafl_exec_run(%s) failed: %s", mode,
                   mafl_err_str(rerr));
        mafl_exec_destroy(exec);
        return -1;
    }

    mafl_exec_destroy(exec);
    return 0;
}

static void expect_status(const char *mode, mafl_status_t want)
{
    mafl_exec_result_t r;
    if (run_once(mode, NULL, 0, 1000u, &r) != 0) {
        return;
    }
    CHECK_EQ_STATUS(r.status, want);
}

static void expect_crash_signal(const char *mode, int want_signo)
{
    mafl_exec_result_t r;
    if (run_once(mode, NULL, 0, 1000u, &r) != 0) {
        return;
    }
    CHECK_EQ_STATUS(r.status, MAFL_STATUS_CRASH);
    CHECK_EQ_SIGNAL(r.signo, want_signo);
}

static void test_normal_exits(void)
{
    mafl_exec_result_t r;

    TEST_BEGIN("exit 0 is OK");
    if (run_once("exit0", NULL, 0, 1000u, &r) == 0) {
        CHECK_EQ_STATUS(r.status, MAFL_STATUS_OK);
        CHECK_EQ_INT(r.exit_code, 0);
    }

    TEST_BEGIN("exit 42 is OK with exit_code 42, not a crash");
    if (run_once("exit42", NULL, 0, 1000u, &r) == 0) {
        CHECK_EQ_STATUS(r.status, MAFL_STATUS_OK);
        CHECK_EQ_INT(r.exit_code, 42);
    }
}

static void test_crash_signals(void)
{
    TEST_BEGIN("SIGSEGV is classified as a crash");
    expect_crash_signal("segv", SIGSEGV);

    TEST_BEGIN("SIGABRT is classified as a crash");
    expect_crash_signal("abort", SIGABRT);

    TEST_BEGIN("SIGFPE is classified as a crash");
    expect_crash_signal("fpe", SIGFPE);

    TEST_BEGIN("SIGILL is classified as a crash");
    expect_crash_signal("ill", SIGILL);

    TEST_BEGIN("SIGBUS is classified as a crash");
    expect_crash_signal("bus", SIGBUS);
}

/* The RISK-04 integration test. A hanging target is SIGKILLed by us and reports
   WIFSIGNALED exactly as a crash would; it must come back TIMEOUT. */
static void test_timeouts(void)
{
    TEST_BEGIN("a blocked target is TIMEOUT, not CRASH (RISK-04)");
    expect_status("hang", MAFL_STATUS_TIMEOUT);

    TEST_BEGIN("a spinning target is TIMEOUT, not CRASH");
    expect_status("spin", MAFL_STATUS_TIMEOUT);
}

static void test_spawn_failures(void)
{
    test_argv_t ta;
    mafl_exec_cfg_t cfg;
    mafl_exec_t *exec = NULL;

    TEST_BEGIN("a nonexistent target is rejected at create time, never as a finding");
    mafl_exec_cfg_init(&cfg);
    test_argv_init(&ta, "/nonexistent/mafl/target", NULL, 0);
    cfg.argv = ta.argv;
    CHECK_EQ_ERR(mafl_exec_create(&cfg, &exec), MAFL_ERR_INVAL);
    CHECK(exec == NULL);

    TEST_BEGIN("a non-executable file is rejected at create time");
    mafl_exec_cfg_init(&cfg);
    test_argv_init(&ta, "/etc/hostname", NULL, 0); /* exists, not executable */
    cfg.argv = ta.argv;
    exec = NULL;
    CHECK_EQ_ERR(mafl_exec_create(&cfg, &exec), MAFL_ERR_INVAL);
    CHECK(exec == NULL);
}

static void test_config_validation(void)
{
    test_argv_t ta;
    mafl_exec_cfg_t cfg;
    mafl_exec_t *exec = NULL;

    TEST_BEGIN("config validation rejects impossible inputs");
    CHECK_EQ_ERR(mafl_exec_create(NULL, &exec), MAFL_ERR_INVAL);

    mafl_exec_cfg_init(&cfg);
    cfg.argv = NULL;
    CHECK_EQ_ERR(mafl_exec_create(&cfg, &exec), MAFL_ERR_INVAL);

    mafl_exec_cfg_init(&cfg);
    test_argv_init(&ta, g_target, "exit0", 0);
    cfg.argv = ta.argv;
    cfg.timeout_ms = 0u; /* a zero deadline is nonsense and must be rejected */
    CHECK_EQ_ERR(mafl_exec_create(&cfg, &exec), MAFL_ERR_INVAL);

    TEST_BEGIN("FILE mode without a \"@@\" placeholder is rejected");
    mafl_exec_cfg_init(&cfg);
    test_argv_init(&ta, g_target, "exit0", 0); /* no "@@" in argv */
    cfg.argv = ta.argv;
    cfg.input_mode = MAFL_INPUT_FILE;
    exec = NULL;
    CHECK_EQ_ERR(mafl_exec_create(&cfg, &exec), MAFL_ERR_INVAL);
    CHECK(exec == NULL);

    TEST_BEGIN("destroy(NULL) is safe");
    mafl_exec_destroy(NULL);
    CHECK(1);
}

/* Input must actually reach the target: a fuzzer whose input delivery is broken reports a
   perfectly healthy campaign while testing nothing at all. */
static void test_stdin_delivery(void)
{
    mafl_exec_result_t r;

    TEST_BEGIN("stdin delivery: benign input exits cleanly");
    if (run_once("echo-crash", (const uint8_t *)"hello", 5u, 1000u, &r) == 0) {
        CHECK_EQ_STATUS(r.status, MAFL_STATUS_OK);
        CHECK_EQ_INT(r.exit_code, 0);
    }

    TEST_BEGIN("stdin delivery: the magic input reaches the target and crashes it");
    if (run_once("echo-crash", (const uint8_t *)"CRASH", 5u, 1000u, &r) == 0) {
        CHECK_EQ_STATUS(r.status, MAFL_STATUS_CRASH);
        CHECK_EQ_SIGNAL(r.signo, SIGSEGV);
    }

    TEST_BEGIN("stdin delivery: an input that makes the target hang is TIMEOUT");
    if (run_once("echo-crash", (const uint8_t *)"HANG", 4u, 500u, &r) == 0) {
        CHECK_EQ_STATUS(r.status, MAFL_STATUS_TIMEOUT);
    }

    TEST_BEGIN("stdin delivery: a zero-length input is handled");
    if (run_once("echo-crash", NULL, 0, 1000u, &r) == 0) {
        CHECK_EQ_STATUS(r.status, MAFL_STATUS_OK);
        CHECK_EQ_INT(r.exit_code, 3); /* the target's "read returned nothing" path */
    }
}

static void test_file_delivery(void)
{
    TEST_BEGIN("file delivery: @@ is replaced and the target reads the staged file");

    test_argv_t ta;
    mafl_exec_cfg_t cfg;
    mafl_exec_cfg_init(&cfg);
    test_argv_init(&ta, g_target, "file-crash", 1); /* argv gains a "@@" */
    cfg.argv = ta.argv;
    cfg.input_mode = MAFL_INPUT_FILE;
    cfg.timeout_ms = 1000u;

    mafl_exec_t *exec = NULL;
    const mafl_err_t err = mafl_exec_create(&cfg, &exec);
    g_checks_run++;
    if (err != MAFL_OK) {
        test_failf(__FILE__, __LINE__, "create failed: %s", mafl_err_str(err));
        return;
    }

    mafl_exec_result_t r;
    if (mafl_exec_run(exec, (const uint8_t *)"hello", 5u, &r) == MAFL_OK) {
        CHECK_EQ_STATUS(r.status, MAFL_STATUS_OK);
        CHECK_EQ_INT(r.exit_code, 0);
    }
    if (mafl_exec_run(exec, (const uint8_t *)"CRASH", 5u, &r) == MAFL_OK) {
        CHECK_EQ_STATUS(r.status, MAFL_STATUS_CRASH);
        CHECK_EQ_SIGNAL(r.signo, SIGSEGV);
    }

    mafl_exec_destroy(exec);
}

/* The same input must always produce the same status. Without this, nothing downstream —
   minimisation, dedup, crash reproduction — can be trusted. */
static void test_determinism(void)
{
    TEST_BEGIN("the same input yields the same status across 50 runs");

    test_argv_t ta;
    mafl_exec_cfg_t cfg;
    cfg_for(&cfg, &ta, "echo-crash", 1000u);

    mafl_exec_t *exec = NULL;
    g_checks_run++;
    if (mafl_exec_create(&cfg, &exec) != MAFL_OK) {
        test_failf(__FILE__, __LINE__, "create failed");
        return;
    }

    int mismatches = 0;
    for (int i = 0; i < 50; i++) {
        mafl_exec_result_t r;
        if (mafl_exec_run(exec, (const uint8_t *)"CRASH", 5u, &r) != MAFL_OK) {
            mismatches++;
            continue;
        }
        if (r.status != MAFL_STATUS_CRASH || r.signo != SIGSEGV) {
            mismatches++;
        }
    }
    CHECK_EQ_INT(mismatches, 0);
    mafl_exec_destroy(exec);
}

/* Timeout accuracy: a target that would run far past its deadline must be killed close to
   it. A timeout that does not fire caps throughput at one hang per campaign. */
static void test_timeout_accuracy(void)
{
    TEST_BEGIN("a hang is killed within 2x the configured deadline, every time");

    test_argv_t ta;
    mafl_exec_cfg_t cfg;
    cfg_for(&cfg, &ta, "hang", 100u);

    mafl_exec_t *exec = NULL;
    g_checks_run++;
    if (mafl_exec_create(&cfg, &exec) != MAFL_OK) {
        test_failf(__FILE__, __LINE__, "create failed");
        return;
    }

    int over_budget = 0;
    uint64_t worst_ms = 0;
    for (int i = 0; i < 20; i++) {
        mafl_exec_result_t r;
        if (mafl_exec_run(exec, NULL, 0, &r) != MAFL_OK || r.status != MAFL_STATUS_TIMEOUT) {
            over_budget++;
            continue;
        }
        const uint64_t ms = r.wall_ns / 1000000ULL;
        if (ms > worst_ms) {
            worst_ms = ms;
        }
        if (ms > 200u) {
            over_budget++;
        }
    }

    g_checks_run++;
    if (over_budget != 0) {
        test_failf(__FILE__, __LINE__,
                   "%d/20 runs exceeded 2x the 100ms deadline (worst %llu ms)",
                   over_budget, (unsigned long long)worst_ms);
    }
    mafl_exec_destroy(exec);
}

/* M1 exit criterion 5: a target that forks a grandchild ignoring SIGTERM must leave
   nothing running. Otherwise an unattended run accumulates unkillable processes. */
static void test_process_group_kill(void)
{
    TEST_BEGIN("a forking, hanging target leaves nothing alive in its process group");

    test_argv_t ta;
    mafl_exec_cfg_t cfg;
    cfg_for(&cfg, &ta, "fork-hang", 200u);

    mafl_exec_t *exec = NULL;
    g_checks_run++;
    if (mafl_exec_create(&cfg, &exec) != MAFL_OK) {
        test_failf(__FILE__, __LINE__, "create failed");
        return;
    }

    mafl_exec_result_t r;
    const mafl_err_t err = mafl_exec_run(exec, NULL, 0, &r);
    g_checks_run++;
    if (err != MAFL_OK) {
        test_failf(__FILE__, __LINE__, "run failed: %s", mafl_err_str(err));
        mafl_exec_destroy(exec);
        return;
    }
    CHECK_EQ_STATUS(r.status, MAFL_STATUS_TIMEOUT);

    /* Give the kernel a moment to finish tearing the group down, so this asserts a real
       leak rather than a race. */
    const struct timespec nap = { .tv_sec = 0, .tv_nsec = 100000000L }; /* 100 ms */
    (void)nanosleep(&nap, NULL);

    /* The grandchild was in the child's process group. If the group kill worked, no
       unreaped children of ours remain. */
    CHECK(no_children_remain());

    mafl_exec_destroy(exec);
}

/* RISK-03: a leaked child is a slow, silent failure that ends in fork() failing hours into
   a run. Assert zero, over enough iterations to exercise the rare paths. */
static void test_no_child_leaks(int iterations)
{
    TEST_BEGIN("no unreaped children after a long mixed workload (RISK-03)");

    static const char *const modes[] = { "exit0", "exit42", "segv", "abort", "hang" };
    const size_t nmodes = sizeof(modes) / sizeof(modes[0]);

    int run_failures = 0;
    for (int i = 0; i < iterations; i++) {
        test_argv_t ta;
        mafl_exec_cfg_t cfg;
        /* A short deadline keeps the hang cases from dominating the runtime. */
        cfg_for(&cfg, &ta, modes[(size_t)i % nmodes], 50u);

        mafl_exec_t *exec = NULL;
        if (mafl_exec_create(&cfg, &exec) != MAFL_OK) {
            run_failures++;
            continue;
        }
        mafl_exec_result_t r;
        if (mafl_exec_run(exec, NULL, 0, &r) != MAFL_OK) {
            run_failures++;
        }
        mafl_exec_destroy(exec);
    }

    CHECK_EQ_INT(run_failures, 0);
    CHECK(no_children_remain());
}

/* RISK-11: exact equality, not tolerance. One descriptor leaked per execution exhausts the
   default limit in seconds; one leaked on a rare error path takes hours and is far harder
   to attribute. */
static void test_no_fd_leaks(int iterations)
{
    TEST_BEGIN("open descriptor count is unchanged after a long mixed workload (RISK-11)");

    /* Warm up first: the first run may lazily open things (locale data, /dev/null) that
       legitimately stay open, and counting those as a leak would be a false positive. */
    mafl_exec_result_t warm;
    (void)run_once("exit0", NULL, 0, 1000u, &warm);

    const int before = count_open_fds();
    if (before < 0) {
        (void)printf("     (skipped: /proc/self/fd unavailable)\n");
        return;
    }

    static const char *const modes[] = { "exit0", "segv", "hang", "exit42", "abort" };
    const size_t nmodes = sizeof(modes) / sizeof(modes[0]);

    for (int i = 0; i < iterations; i++) {
        test_argv_t ta;
        mafl_exec_cfg_t cfg;
        cfg_for(&cfg, &ta, modes[(size_t)i % nmodes], 50u);

        mafl_exec_t *exec = NULL;
        if (mafl_exec_create(&cfg, &exec) != MAFL_OK) {
            continue;
        }
        mafl_exec_result_t r;
        mafl_err_t _rr = mafl_exec_run(exec, NULL, 0, &r); if (_rr != MAFL_OK) { test_failf(__FILE__, __LINE__, "mafl_exec_run failed: %s", mafl_err_str(_rr)); return; }
        mafl_exec_destroy(exec);
    }

    const int after = count_open_fds();
    g_checks_run++;
    if (after != before) {
        test_failf(__FILE__, __LINE__,
                   "descriptor leak: %d open before, %d after %d executions",
                   before, after, iterations);
    }
}

/* A single executor reused across many runs is the real fuzzing pattern; the per-run
   create/destroy elsewhere would mask a leak in the reuse path. */
static void test_executor_reuse(int iterations)
{
    TEST_BEGIN("one executor reused across many runs stays correct and leak-free");

    test_argv_t ta;
    mafl_exec_cfg_t cfg;
    cfg_for(&cfg, &ta, "echo-crash", 200u);

    mafl_exec_t *exec = NULL;
    g_checks_run++;
    if (mafl_exec_create(&cfg, &exec) != MAFL_OK) {
        test_failf(__FILE__, __LINE__, "create failed");
        return;
    }

    const int fds_before = count_open_fds();
    int wrong = 0;

    for (int i = 0; i < iterations; i++) {
        mafl_exec_result_t r;
        const bool want_crash = ((i % 3) == 0);
        const uint8_t *in = want_crash ? (const uint8_t *)"CRASH" : (const uint8_t *)"safe";
        const size_t len = want_crash ? 5u : 4u;

        if (mafl_exec_run(exec, in, len, &r) != MAFL_OK) {
            wrong++;
            continue;
        }
        if (r.status != (want_crash ? MAFL_STATUS_CRASH : MAFL_STATUS_OK)) {
            wrong++;
        }
    }

    CHECK_EQ_INT(wrong, 0);
    CHECK_EQ_INT((int)mafl_exec_run_count(exec), iterations);
    CHECK_EQ_INT((int)mafl_exec_last_pid(exec), 0); /* cleared after every reap */

    const int fds_after = count_open_fds();
    g_checks_run++;
    if (fds_before >= 0 && fds_after != fds_before) {
        test_failf(__FILE__, __LINE__, "reuse leaked descriptors: %d -> %d",
                   fds_before, fds_after);
    }

    mafl_exec_destroy(exec);
    CHECK(no_children_remain());
}

/* A throughput floor, recorded so the M5 fork-server speedup has a real baseline to be
   measured against (M1 exit criterion 6). Deliberately lenient: CI runners are shared and
   slow, and a flaky performance test that everyone learns to ignore is worse than none. */
static void test_throughput_baseline(void)
{
    TEST_BEGIN("fork/exec throughput baseline (recorded; floor asserted loosely)");

    test_argv_t ta;
    mafl_exec_cfg_t cfg;
    cfg_for(&cfg, &ta, "exit0", 1000u);

    mafl_exec_t *exec = NULL;
    g_checks_run++;
    if (mafl_exec_create(&cfg, &exec) != MAFL_OK) {
        test_failf(__FILE__, __LINE__, "create failed");
        return;
    }

    const int n = 300;
    const uint64_t t0 = mafl_monotonic_ns();
    for (int i = 0; i < n; i++) {
        mafl_exec_result_t r;
        mafl_err_t _rr = mafl_exec_run(exec, NULL, 0, &r); if (_rr != MAFL_OK) { test_failf(__FILE__, __LINE__, "mafl_exec_run failed: %s", mafl_err_str(_rr)); return; }
    }
    const uint64_t elapsed = mafl_monotonic_ns() - t0;
    mafl_exec_destroy(exec);

    const double secs = (double)elapsed / 1e9;
    const double per_sec = (secs > 0.0) ? ((double)n / secs) : 0.0;
    (void)printf("     baseline: %.0f exec/sec (%d execs in %.3f s)\n", per_sec, n, secs);

    /* The real target is >=1000 exec/sec on dedicated hardware (M1 criterion 6). Under
       ASan on a shared CI runner that is unreachable, so assert only that the loop is not
       pathologically broken, and record the number for comparison. */
    CHECK(per_sec > 20.0);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        (void)fprintf(stderr, "usage: %s <path-to-test-target>\n", argv[0]);
        return 2;
    }
    g_target = argv[1];

    /* Reduced loop counts when MAFL_QUICK_TESTS is set, so the dev loop stays fast while
       CI runs the full counts. */
    const bool quick = (getenv("MAFL_QUICK_TESTS") != NULL);
    const int leak_iters = quick ? 200 : 2000;
    const int reuse_iters = quick ? 100 : 1000;

    test_normal_exits();
    test_crash_signals();
    test_timeouts();
    test_spawn_failures();
    test_config_validation();
    test_stdin_delivery();
    test_file_delivery();
    test_determinism();
    test_timeout_accuracy();
    test_process_group_kill();
    test_executor_reuse(reuse_iters);
    test_no_child_leaks(leak_iters);
    test_no_fd_leaks(leak_iters);
    test_throughput_baseline();

    return test_summary("integration_exec");
}
