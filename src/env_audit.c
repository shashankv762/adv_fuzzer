/* Host environment audit.
 *
 * Every check here corresponds to a documented failure mode (RISK-02, RISK-16). None of
 * them require root, and none of them are fatal: we print the exact command that fixes
 * the problem and continue. A vague warning nobody can act on is worse than none. */

#include "mafl/exec.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

static void audit_core_pattern(void)
{
    FILE *f = fopen("/proc/sys/kernel/core_pattern", "re");
    if (f == NULL) {
        MAFL_LOG_D("core_pattern unreadable (%s); skipping check", strerror(errno));
        return;
    }

    char buf[256] = { 0 };
    char *line = fgets(buf, (int)sizeof(buf), f);
    (void)fclose(f);

    if (line == NULL) {
        return;
    }

    /* A leading '|' means the kernel pipes every core dump to a userspace handler
       (systemd-coredump, apport). At high crash rates that adds seconds of latency per
       crash, so crashes get misclassified as hangs, and cores accumulate outside our
       RLIMIT_CORE control. This is the single most common cause of an inexplicably slow
       fuzzer. */
    if (buf[0] == '|') {
        MAFL_LOG_W("core_pattern pipes cores to a userspace handler: %s", buf);
        MAFL_LOG_W("  crashes will be slow and may be misclassified as hangs.");
        MAFL_LOG_W("  fix: echo core | sudo tee /proc/sys/kernel/core_pattern");
    }
}

static void audit_cpu_governor(void)
{
    FILE *f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "re");
    if (f == NULL) {
        /* Absent in most containers and on many VMs. Not worth mentioning. */
        return;
    }

    char buf[64] = { 0 };
    char *line = fgets(buf, (int)sizeof(buf), f);
    (void)fclose(f);

    if (line == NULL) {
        return;
    }
    buf[strcspn(buf, "\n")] = '\0';

    if (strcmp(buf, "performance") != 0) {
        MAFL_LOG_W("CPU governor is '%s', not 'performance'.", buf);
        MAFL_LOG_W("  execution timing will be unstable, which poisons timeout calibration.");
    }
}

static void audit_sigchld_disposition(void)
{
    struct sigaction sa;

    if (sigaction(SIGCHLD, NULL, &sa) != 0) {
        return;
    }

    /* An inherited SIG_IGN on SIGCHLD makes waitpid() fail with ECHILD, which breaks
       child reaping in a way that is extremely confusing to diagnose (RISK-03). The
       executor resets this at creation; warn so the cause is visible if it happens. */
    if (sa.sa_handler == SIG_IGN) {
        MAFL_LOG_W("inherited SIG_IGN on SIGCHLD; the executor will reset it to SIG_DFL.");
    }
}

static void audit_core_rlimit(void)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_CORE, &rl) != 0) {
        return;
    }
    if (rl.rlim_cur != 0) {
        MAFL_LOG_D("inherited RLIMIT_CORE is non-zero; children will have it set to 0.");
    }
}

static void audit_nofile(void)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        return;
    }
    if (rl.rlim_cur < 1024) {
        MAFL_LOG_W("RLIMIT_NOFILE soft limit is %llu; raise it (ulimit -n 4096).",
                   (unsigned long long)rl.rlim_cur);
    }
}

void mafl_env_audit(void)
{
    audit_core_pattern();
    audit_cpu_governor();
    audit_sigchld_disposition();
    audit_core_rlimit();
    audit_nofile();
}
