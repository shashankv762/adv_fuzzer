/* Test targets for the M1 execution engine.
 *
 * Built as one binary with a mode selected by argv[1], so the test suite needs a single
 * build rule. Compiled WITHOUT sanitizers, deliberately: ASan installs its own SIGSEGV
 * handler and exits with a normal exit code instead of dying by signal, which would
 * invalidate every signal-classification assertion (docs/ARCHITECTURE.md §6). */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Volatile and heap-allocated so the compiler cannot prove the fault away and optimise
   the whole thing out. */
static void do_segv(void)
{
    volatile int *p = NULL;
    *p = 1;
}

static void do_abort(void)
{
    abort();
}

static void do_fpe(void)
{
    /* Runtime values, so this is not folded at compile time. */
    volatile int zero = 0;
    volatile int one = 1;
    volatile int r = one / zero;
    (void)r;
}

static void do_ill(void)
{
    /* raise() is the portable way to get a specific signal without relying on an
       architecture-specific illegal encoding. */
    raise(SIGILL);
}

static void do_bus(void)
{
    raise(SIGBUS);
}

static void do_hang(void)
{
    for (;;) {
        (void)pause();
        sleep(1);
    }
}

static void do_spin(void)
{
    volatile unsigned long x = 0;
    for (;;) {
        x++;
    }
}

/* Fork a grandchild that ignores SIGTERM, then hang. Verifies that the executor kills the
   whole process group rather than just the direct child (M1 exit criterion 5). */
static void do_fork_hang(void)
{
    const pid_t pid = fork();
    if (pid == 0) {
        (void)signal(SIGTERM, SIG_IGN);
        (void)signal(SIGINT, SIG_IGN);
        for (;;) {
            sleep(1);
        }
    }
    for (;;) {
        sleep(1);
    }
}

/* Read stdin and crash only on a specific magic prefix. Used to prove that input actually
   reaches the target and that the same input reproduces the same status. */
static int do_echo_crash(void)
{
    char buf[64];
    const ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (n <= 0) {
        return 3;
    }
    buf[n] = '\0';
    if (strncmp(buf, "CRASH", 5) == 0) {
        do_segv();
    }
    if (strncmp(buf, "HANG", 4) == 0) {
        do_hang();
    }
    return 0;
}

/* Same, but reads the input from a path in argv — exercises MAFL_INPUT_FILE mode. */
static int do_file_crash(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return 4;
    }
    char buf[64] = { 0 };
    const size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    (void)fclose(f);
    if (n == 0) {
        return 5;
    }
    buf[n] = '\0';
    if (strncmp(buf, "CRASH", 5) == 0) {
        do_segv();
    }
    return 0;
}

static void usage(void)
{
    (void)fprintf(stderr,
                  "usage: target <mode>\n"
                  "modes: exit0 exit42 segv abort fpe ill bus hang spin fork-hang\n"
                  "       echo-crash file-crash <path> closes-stdin dtor-exit\n");
}

/* Exits from a destructor, after main has returned — checks that we classify on the real
   process exit rather than on anything observed earlier. */
static void __attribute__((destructor)) maybe_exit_from_dtor(void)
{
    if (getenv("MAFL_TEST_DTOR_EXIT") != NULL) {
        _exit(77);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 2;
    }

    const char *mode = argv[1];

    if (strcmp(mode, "exit0") == 0)     { return 0; }
    if (strcmp(mode, "exit42") == 0)    { return 42; }
    if (strcmp(mode, "segv") == 0)      { do_segv(); return 1; }
    if (strcmp(mode, "abort") == 0)     { do_abort(); return 1; }
    if (strcmp(mode, "fpe") == 0)       { do_fpe(); return 1; }
    if (strcmp(mode, "ill") == 0)       { do_ill(); return 1; }
    if (strcmp(mode, "bus") == 0)       { do_bus(); return 1; }
    if (strcmp(mode, "hang") == 0)      { do_hang(); return 1; }
    if (strcmp(mode, "spin") == 0)      { do_spin(); return 1; }
    if (strcmp(mode, "fork-hang") == 0) { do_fork_hang(); return 1; }
    if (strcmp(mode, "echo-crash") == 0) { return do_echo_crash(); }
    if (strcmp(mode, "closes-stdin") == 0) { (void)close(STDIN_FILENO); return 0; }
    if (strcmp(mode, "dtor-exit") == 0) { return 0; } /* destructor may override */

    if (strcmp(mode, "file-crash") == 0) {
        if (argc < 3) {
            usage();
            return 2;
        }
        return do_file_crash(argv[2]);
    }

    usage();
    return 2;
}
