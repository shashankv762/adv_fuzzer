/* Unit tests for pure logic: wait-status classification and crash-signal identification.
 *
 * These spawn nothing. mafl_classify_wait_status() is separated from the executor
 * precisely so the RISK-04 distinction (our own kill vs a target crash) can be tested
 * exhaustively and cheaply. */

#include "mafl/exec.h"
#include "../test_util.h"

#include <sys/wait.h>

/* Construct wait-status encodings directly rather than by spawning. W_EXITCODE is a glibc
   extension; define it if absent so these tests also build against musl. */
#ifndef W_EXITCODE
#define W_EXITCODE(ret, sig) (((ret) << 8) | (sig))
#endif

static int status_exited(int code) { return W_EXITCODE(code, 0); }
static int status_signalled(int signo) { return W_EXITCODE(0, signo); }

static void test_signal_is_crash(void)
{
    TEST_BEGIN("mafl_signal_is_crash: the five fault signals");
    CHECK(mafl_signal_is_crash(SIGSEGV));
    CHECK(mafl_signal_is_crash(SIGABRT));
    CHECK(mafl_signal_is_crash(SIGBUS));
    CHECK(mafl_signal_is_crash(SIGFPE));
    CHECK(mafl_signal_is_crash(SIGILL));

    TEST_BEGIN("mafl_signal_is_crash: our own kill signals are NOT crashes (RISK-04)");
    CHECK(!mafl_signal_is_crash(SIGKILL));
    CHECK(!mafl_signal_is_crash(SIGTERM));

    TEST_BEGIN("mafl_signal_is_crash: other signals are not crashes");
    CHECK(!mafl_signal_is_crash(SIGINT));
    CHECK(!mafl_signal_is_crash(SIGALRM));
    CHECK(!mafl_signal_is_crash(SIGCHLD));
    CHECK(!mafl_signal_is_crash(SIGTRAP));
    CHECK(!mafl_signal_is_crash(SIGPIPE));
    CHECK(!mafl_signal_is_crash(0));
}

static void test_classify_normal_exit(void)
{
    int signo = -1;
    int code = -1;

    TEST_BEGIN("classify: exit 0");
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_exited(0), false, &signo, &code),
                    MAFL_STATUS_OK);
    CHECK_EQ_INT(code, 0);
    CHECK_EQ_INT(signo, 0);

    TEST_BEGIN("classify: non-zero exit is still OK, not a crash");
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_exited(42), false, &signo, &code),
                    MAFL_STATUS_OK);
    CHECK_EQ_INT(code, 42);

    TEST_BEGIN("classify: exit 255");
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_exited(255), false, &signo, &code),
                    MAFL_STATUS_OK);
    CHECK_EQ_INT(code, 255);
}

static void test_classify_crashes(void)
{
    static const int crash_signals[] = { SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL };

    for (size_t i = 0; i < sizeof(crash_signals) / sizeof(crash_signals[0]); i++) {
        const int sig = crash_signals[i];
        int signo = -1;
        int code = -1;

        TEST_BEGIN("classify: fault signal we did not send is a CRASH");
        CHECK_EQ_STATUS(mafl_classify_wait_status(status_signalled(sig), false, &signo, &code),
                        MAFL_STATUS_CRASH);
        CHECK_EQ_SIGNAL(signo, sig);
    }
}

/* The central RISK-04 test. A target we SIGKILLed reports WIFSIGNALED exactly like a
   crash; only our recorded intent distinguishes them. Getting this wrong records every
   hang as a crash and makes the whole findings set noise. */
static void test_classify_our_own_kills(void)
{
    int signo = -1;
    int code = -1;

    TEST_BEGIN("classify: SIGKILL we sent is TIMEOUT, never CRASH (RISK-04)");
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_signalled(SIGKILL), true, &signo, &code),
                    MAFL_STATUS_TIMEOUT);
    CHECK_EQ_SIGNAL(signo, SIGKILL);

    TEST_BEGIN("classify: SIGKILL we did NOT send is KILLED (e.g. the OOM killer)");
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_signalled(SIGKILL), false, &signo, &code),
                    MAFL_STATUS_KILLED);
    CHECK_EQ_SIGNAL(signo, SIGKILL);

    TEST_BEGIN("classify: intent wins even for a fault signal");
    /* If we killed it and it also happened to fault, intent still wins: the run did not
       complete, so it is not reportable as a finding. */
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_signalled(SIGSEGV), true, &signo, &code),
                    MAFL_STATUS_TIMEOUT);

    TEST_BEGIN("classify: a target that exits normally after our kill is OK, not TIMEOUT");
    /* It raced our SIGKILL and won. The execution completed. */
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_exited(0), true, &signo, &code),
                    MAFL_STATUS_OK);
    CHECK_EQ_INT(code, 0);
}

static void test_classify_non_crash_signals(void)
{
    int signo = -1;

    TEST_BEGIN("classify: SIGTERM from elsewhere is KILLED, not CRASH");
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_signalled(SIGTERM), false, &signo, NULL),
                    MAFL_STATUS_KILLED);
    CHECK_EQ_SIGNAL(signo, SIGTERM);

    TEST_BEGIN("classify: SIGPIPE is KILLED, not CRASH");
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_signalled(SIGPIPE), false, &signo, NULL),
                    MAFL_STATUS_KILLED);
}

static void test_classify_null_outparams(void)
{
    TEST_BEGIN("classify: NULL out-parameters are accepted");
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_exited(7), false, NULL, NULL),
                    MAFL_STATUS_OK);
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_signalled(SIGSEGV), false, NULL, NULL),
                    MAFL_STATUS_CRASH);
}

/* Out-parameters must be initialised on every path, so a caller can never read a stale
   value from a previous run and mistake it for this one's. */
static void test_classify_initialises_outparams(void)
{
    TEST_BEGIN("classify: out-params initialised even when not meaningful");

    int signo = 12345;
    int code = 12345;
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_exited(0), false, &signo, &code),
                    MAFL_STATUS_OK);
    CHECK_EQ_INT(signo, 0); /* no signal was involved */

    signo = 12345;
    code = 12345;
    CHECK_EQ_STATUS(mafl_classify_wait_status(status_signalled(SIGSEGV), false, &signo, &code),
                    MAFL_STATUS_CRASH);
    CHECK_EQ_INT(code, 0); /* no exit code was involved */
}

static void test_status_and_err_strings(void)
{
    TEST_BEGIN("status/err strings are present and distinct");
    CHECK(strcmp(mafl_status_str(MAFL_STATUS_OK), "ok") == 0);
    CHECK(strcmp(mafl_status_str(MAFL_STATUS_CRASH), "crash") == 0);
    CHECK(strcmp(mafl_status_str(MAFL_STATUS_TIMEOUT), "timeout") == 0);
    CHECK(strcmp(mafl_status_str(MAFL_STATUS_KILLED), "killed") == 0);
    CHECK(strcmp(mafl_status_str(MAFL_STATUS_SPAWN_FAIL), "spawn-fail") == 0);

    CHECK(strcmp(mafl_err_str(MAFL_OK), "ok") == 0);
    CHECK(mafl_err_str(MAFL_ERR_SPAWN) != NULL);
    CHECK(mafl_err_str(MAFL_ERR_BUSY) != NULL);
    CHECK(mafl_err_str((mafl_err_t)-9999) != NULL); /* must not read out of bounds */
}

int main(void)
{
    test_signal_is_crash();
    test_classify_normal_exit();
    test_classify_crashes();
    test_classify_our_own_kills();
    test_classify_non_crash_signals();
    test_classify_null_outparams();
    test_classify_initialises_outparams();
    test_status_and_err_strings();
    return test_summary("unit_classify");
}
