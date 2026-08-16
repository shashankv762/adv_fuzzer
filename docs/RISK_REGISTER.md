# Mini-AFL — Risk Register

A fuzzer is an adversarial program that runs unattended for hours, deliberately provokes
memory corruption in another process, and holds the only copy of its findings. Most of the
ways it fails are **silent**: it keeps printing plausible statistics while producing garbage.
That is the organising principle of this register — for each risk, the question that matters
is *"how would I ever notice?"*

Each risk has: likelihood, impact, whether failure is **silent or loud**, a mitigation, and a
**detection** mechanism. Silent risks are the dangerous ones and are marked accordingly.

Severity = likelihood × impact, adjusted upward for silence.

| ID | Risk | Sev |
| --- | --- | --- |
| [RISK-01](#risk-01) | Fork-bombing / runaway process accumulation | High |
| [RISK-02](#risk-02) | Disk exhaustion from core dumps and crash artifacts | High |
| [RISK-03](#risk-03) | Zombie accumulation from `waitpid()` bookkeeping bugs | High |
| [RISK-04](#risk-04) | Status misclassification: our kills recorded as target crashes | **Critical** |
| [RISK-05](#risk-05) | Shared-memory segment leaks | Medium |
| [RISK-06](#risk-06) | Coverage map corrupting the target's memory | **Critical** |
| [RISK-07](#risk-07) | Non-deterministic crashes breaking minimisation | **Critical** |
| [RISK-08](#risk-08) | The fuzzer itself is memory-unsafe | **Critical** |
| [RISK-09](#risk-09) | Signal-handler unsafety | Medium |
| [RISK-10](#risk-10) | Corrupt or truncated findings on disk | High |
| [RISK-11](#risk-11) | Descriptor exhaustion | Medium |
| [RISK-12](#risk-12) | Fork-server deadlock | High |
| [RISK-13](#risk-13) | Persistent-mode state carryover | High |
| [RISK-14](#risk-14) | Silent coverage loss (collisions, overflow, wrap) | **Critical** |
| [RISK-15](#risk-15) | Fuzzer-induced crashes reported as target bugs | **Critical** |
| [RISK-16](#risk-16) | Environment misconfiguration destroying throughput | Medium |
| [RISK-17](#risk-17) | Target escaping the sandbox / damaging the host | Medium |
| [RISK-18](#risk-18) | Prior-art constants transcribed wrong from memory | High |
| [RISK-19](#risk-19) | Development-host mismatch (Windows, no WSL) | Medium |
| [RISK-20](#risk-20) | Disclosure and legal missteps in M6+ | High |
| [RISK-21](#risk-21) | Scope creep / never-finished syndrome | Medium |
| [RISK-22](#risk-22) | Coverage plateau: works but finds nothing | High |
| [RISK-23](#risk-23) | Fork-server pipe desync deadlock | High |
| [RISK-24](#risk-24) | Sanitizer interference with crash classification | **Critical** |
| [RISK-25](#risk-25) | Mutation-engine memory unsafety in the fuzzer itself | **Critical** |
| [RISK-26](#risk-26) | Non-reproducible campaigns (non-deterministic PRNG / scheduling) | High |
| [RISK-27](#risk-27) | Shared-corpus corruption under multi-process parallelism | High |
| [RISK-28](#risk-28) | Coverage-feedback poisoning: instrumented build diverges from baseline | **Critical** |
| [RISK-29](#risk-29) | Dedup over-merge hiding a second exploitable bug | **Critical** |
| [RISK-30](#risk-30) | Supply-chain / dependency risk from any future third-party lib | Medium |
| [RISK-31](#risk-31) | TOCTOU on the staged input file and `@@` substitution | Medium |

---

## RISK-01
### Fork-bombing / runaway process accumulation
**Likelihood** Medium · **Impact** High (host unusable, requires hard reboot) · **Loud**

A bug in the spawn path that forks without waiting, or a target that forks children we never
track, saturates the process table. Under a `fork()` loop bug the host can become unusable
within seconds — including losing the ability to spawn a shell to fix it.

**Mitigation**
- Exactly **one** in-flight child per executor instance in v1, tracked in an explicit field.
  The spawn path asserts that field is empty before forking; a violation aborts rather than
  continues.
- Every child gets its own process group (`setpgid(0, 0)`), and timeout kill targets the
  **group** (`kill(-pgid, SIGKILL)`), so a target's own children die with it.
- `PR_SET_PDEATHSIG(SIGKILL)` plus a `getppid()` re-check in the child, so nothing survives
  the fuzzer.
- `RLIMIT_NPROC` on the child, so a target that itself fork-bombs is capped.
- Development discipline: any change to the spawn path runs first under a shell `ulimit -u`
  cap, so a mistake hits the limit instead of the host.

**Detection** Integration test forks a grandchild that ignores `SIGTERM` and asserts nothing
survives. CI asserts the process count is unchanged after 10 000 executions.

---

## RISK-02
### Disk exhaustion from core dumps and crash artifacts
**Likelihood** High (near-certain if unmitigated) · **Impact** High · **Loud, but late**

A target crashing hundreds of times per second, each producing a multi-megabyte core dump,
fills any disk in minutes. Separately, saving every crashing input rather than every *unique*
crash produces millions of near-identical files.

**Mitigation**
- `setrlimit(RLIMIT_CORE, 0)` on every child. Non-negotiable.
- Startup check on `/proc/sys/kernel/core_pattern`: warn prominently if it begins with `|`
  (piped to `systemd-coredump`/`apport`), which adds latency *and* stores cores outside our
  rlimit's control.
- **Bucket first, save second** — an artifact is written only for a previously-unseen crash
  bucket.
- `RLIMIT_FSIZE` on children, so a target cannot write a huge file itself.
- A configurable cap on total artifacts and total output-directory bytes; on reaching it, stop
  saving and warn loudly rather than filling the disk.
- Free-space check at startup and periodically during the run; refuse to start below a
  threshold. *(Implemented in the M1 hardening addendum as a `statvfs` audit on the output
  directory; it was previously listed here as mitigation but not actually run — see the audit
  note on RISK-16.)*

**Detection** CI test: a target that crashes on every input across 10 000 inputs must produce
exactly one artifact directory and no core files.

---

## RISK-03
### Zombie accumulation from `waitpid()` bookkeeping bugs
**Likelihood** Medium · **Impact** Medium (gradual, ends in `fork()` failure) · **Silent until fatal**

A terminated-but-unreaped child stays in the process table. The specific trap in our design:
`pidfd` readability signals *termination*, not *reaping* — the `waitpid()` is still required.
Skip it and the leak accumulates invisibly for hours, then `fork()` starts failing and the
campaign dies far from the actual bug.

**Mitigation**
- Reaping is centralised in exactly one function; no other code calls `waitpid()`.
- Every exit path from the spawn function — including all error paths — goes through that
  function. Enforced by review and by structuring the function with a single exit point.
- On timeout: kill, then reap with a bounded retry; if the child is still unreaped after the
  bound, that is a **hard error** reported to the user, not a silently-ignored condition.
- `SIGCHLD` explicitly reset to `SIG_DFL` at executor creation — an inherited `SIG_IGN` makes
  `waitpid()` fail `ECHILD` and breaks reaping in a maximally confusing way.

**Detection** M1 exit criterion 2: after 10 000 mixed executions,
`waitpid(-1, ..., WNOHANG)` must return `-1/ECHILD`. This is a cross-milestone invariant, so it
runs in CI forever, not just at M1.

---

## RISK-04
### Status misclassification: our own kills recorded as target crashes
**Likelihood** High · **Impact** **Critical** · **SILENT**

We `SIGKILL` a child on timeout. That child then reports `WIFSIGNALED` with `SIGKILL`. If the
executor's classification only looks at `WIFSIGNALED`, **every hang is recorded as a crash**.
The crash directory fills with inputs that do not crash anything, and the entire findings set
becomes untrustworthy. Nothing about the fuzzer's output looks wrong while this is happening —
it looks like a *productive* campaign.

**Mitigation**
- The executor tracks its own kill intent in an explicit state variable set *before* the kill
  is issued. Classification consults intent first, signal second.
- `SIGKILL` and `SIGTERM` are never classified as target crashes; only `SIGSEGV`, `SIGABRT`,
  `SIGBUS`, `SIGFPE`, `SIGILL` (plus a documented tail) are.
- `TIMEOUT` and `KILLED` are distinct statuses from `CRASH` in the API — the type system makes
  the distinction impossible to lose accidentally.
- Every crash is **re-verified in a fresh process** before it is recorded (see RISK-15), which
  catches this class independently.

**Detection** M1 exit criterion 1 asserts the exact expected status for a
sleep-past-the-timeout target and for an infinite-loop target. Not "a crash was detected" —
the *exact* status.

---

## RISK-05
### Shared-memory segment leaks
**Likelihood** Medium · **Impact** Medium (eventual `ENOSPC`/`shmmni` exhaustion) · **Silent**

A SysV segment created with `shmget` **outlives the process that created it**. A fuzzer killed
with `SIGKILL` — which will happen constantly during development — leaks a segment every time,
until the system limit is hit or the machine is rebooted. Debugging "why does my fuzzer fail to
start now" hours later is a bad afternoon.

**Mitigation**
- Use **`shm_open` + `mmap`**, not `shmget`/`shmat` (ARCHITECTURE.md D4).
- `shm_unlink()` **immediately after mapping**, so the name is gone from `/dev/shm` while the
  mapping stays valid — the kernel reclaims the memory when the last reference drops, including
  on `SIGKILL`. This makes leaks structurally impossible rather than handled.
- The child inherits the mapping across `fork`, and receives the descriptor/mapping information
  by environment variable for the `execve` path.
- A `--cleanup` subcommand that removes any stale `mafl-*` entries, for the case where an older
  build left some behind.

**Detection** M2 exit criterion 5: `/dev/shm` contains no `mafl-*` entries after 10 000
executions **and** after the fuzzer is `SIGKILL`ed mid-run. Cross-milestone invariant.

---

## RISK-06
### Coverage map corrupting the target's memory
**Likelihood** Medium · **Impact** **Critical** · **SILENT AND ACTIVELY MISLEADING**

The coverage runtime writes into the target's address space on every branch. If the map pointer
is wrong, unmapped, or smaller than the largest index written, the runtime corrupts the target's
memory — and the resulting crashes look exactly like genuine memory-safety bugs in the target.
This is the failure mode that leads to **reporting a nonexistent bug to a maintainer**, which is
the worst outcome this project can produce.

Three concrete paths in:
1. Guard callbacks fire from a module constructor *before* our map is attached (null or stale
   pointer).
2. The runtime's compiled-in map size disagrees with the fuzzer's, so indices run past the end.
3. Guard count exceeds the map size and index arithmetic wraps incorrectly.

**Mitigation**
- A **static dummy map inside the runtime**, used from process start, so the callback is always
  writing somewhere valid even before attachment. The real map replaces it atomically.
- **Explicit map-size negotiation** between fuzzer and runtime at startup; a mismatch is a hard
  error that refuses to run, never a warning.
- Every map index is masked to the map size — bounds safety by construction, not by argument.
- The runtime is compiled with `-fno-sanitize-coverage` and asserted to contain no guards, so it
  cannot instrument itself into recursion.
- The runtime is deliberately tiny and has no dynamic allocation, so it can be reviewed
  exhaustively.
- **Every crash is re-verified against an uninstrumented build** before it is reported. If the
  crash disappears without instrumentation, it is *ours*, not the target's. This is the backstop
  that makes the whole risk survivable.

**Detection** M2 exit criteria 6 and 7 (constructor safety, multi-module ID disjointness). ASan
on the *target* would catch out-of-bounds writes into it. M4's re-verification pass is the final
gate before anything is called a finding.

---

## RISK-07
### Non-deterministic crashes breaking minimisation
**Likelihood** High (many real targets are non-deterministic) · **Impact** **Critical** · **SILENT**

Minimisation assumes a deterministic oracle: "does this smaller input still crash the same way?"
Heap-layout-dependent, timing-dependent, ASLR-dependent, and uninitialised-memory-dependent
crashes violate that. The minimiser then happily deletes the bytes that actually mattered
because the crash *happened* not to reproduce on that trial, and emits a "minimised" input that
does not reproduce at all. You then send it to a maintainer.

**Mitigation**
- `personality(ADDR_NO_RANDOMIZE)` to remove ASLR as a variable.
- **Stability measurement in M2**: quantify per-target non-determinism up front and warn the
  user before any minimisation is attempted.
- `mafl-tmin --oracle-runs N` requiring **unanimity** across N runs before accepting a
  reduction. Default N > 1 for any target flagged unstable.
- **Post-minimisation verification**: the minimised input is re-run N times and must reproduce
  the same bucket every time. If not, the artifact keeps the *original* input and is flagged
  `UNSTABLE` — we ship a bigger input rather than a wrong one.
- Artifacts record the observed reproduction rate, so a report can state it honestly.

**Detection** M4 exit criterion 4: against a target that crashes ~50 % of the time,
minimisation with `--oracle-runs 5` must **never** emit a non-reproducing artifact.

---

## RISK-08
### The fuzzer itself is memory-unsafe
**Likelihood** Medium · **Impact** **Critical** (loses hours of findings; destroys the tool's credibility) · **Loud**

This is a C program doing pointer-heavy work on attacker-shaped data — the mutation engine
manipulates arbitrary byte buffers with arbitrary lengths, which is precisely the code shape
that produces off-by-ones. A memory-safety bug in a *security tool* is also a credibility
problem beyond the crash itself.

**Mitigation**
- Whole test suite runs under **ASan + UBSan** in CI on every push, both compilers.
- `-Wall -Wextra -Werror` plus `-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`,
  `-Wformat=2`, `-Wconversion` where practical.
- Mutators are **pure functions** of `(input, RNG state)` — no globals, no I/O — so they can be
  property-tested over millions of random inputs.
- Explicit length bounds on every buffer operation; no `strcpy`/`sprintf`/`strcat`/`alloca`
  anywhere in the codebase, enforced by a grep-based CI check.
- Zero-length and maximum-length inputs are explicit test cases for every mutator, because they
  are where these bugs live.
- `scan-build` / `clang-tidy` in CI; `valgrind` on the fuzzer at M6.
- The fuzzer's own crash is treated as a **P0 bug**, never worked around.

**Detection** CI (every push). M6 exit criterion 1: a 72-hour unattended run with zero fuzzer
crashes.

---

## RISK-09
### Signal-handler unsafety
**Likelihood** Medium · **Impact** Medium (rare deadlocks and corruption, extremely hard to diagnose) · **Silent**

Calling non-async-signal-safe functions from a handler — `printf`, `malloc`, anything touching
locks — can deadlock or corrupt state. It fails rarely and non-reproducibly, which makes it one
of the worst bugs to chase.

**Mitigation**
- **Structurally avoided on the hot path**: timeouts use `pidfd_open` + `ppoll`, so the
  execution path installs *no* handlers at all (ARCHITECTURE.md §4). This removes most of the
  risk by design rather than by discipline.
- The only handlers are `SIGINT`/`SIGTERM` for shutdown. They do exactly one thing: set a
  `volatile sig_atomic_t` flag and return. No allocation, no I/O, no logging.
- The main loop polls the flag and performs shutdown in normal context.
- Handlers installed with `sigaction` (well-defined semantics), never `signal()`.
- A CI grep check rejects `printf`/`malloc`/`free` textually appearing inside handler functions.

**Detection** Code review, the CI grep check, and TSan where applicable.

---

## RISK-10
### Corrupt or truncated findings on disk
**Likelihood** Medium · **Impact** High · **Silent**

The fuzzer is killed (by the user, the OOM killer, or a power loss) mid-write to a crash
artifact. The result is a truncated input file that does not reproduce — an apparently-valid
finding that is actually garbage. The brief calls this out explicitly: the tool must be
"trusted not to corrupt its own findings."

**Mitigation**
- **All persistence is atomic**: write to a temp file in the same directory → `fsync(fd)` →
  `rename()` into place → `fsync` the directory. A reader therefore sees either the complete
  file or no file.
- Metadata is written **last**, after the input, so an artifact directory without valid metadata
  is recognisably incomplete and can be discarded on resume.
- Every artifact carries a checksum of its input, verified on load.
- On startup, incomplete artifact directories are detected and quarantined rather than trusted.

**Detection** M4 exit criterion 7: `SIGKILL` the fuzzer mid-write 100 times; every artifact on
disk must be complete-and-valid or absent. Cross-milestone invariant.

---

## RISK-11
### Descriptor exhaustion
**Likelihood** Medium · **Impact** Medium · **Silent until fatal**

Each execution opens an input file, a `pidfd`, and possibly stdio redirections. Leaking one
descriptor per execution at 1 000 exec/sec exhausts the default limit in about a second — or, if
the leak is on a rarely-taken error path, in about six hours, which is much worse to diagnose.

**Mitigation**
- `O_CLOEXEC` on **every** descriptor we open, so nothing leaks across `execve` into the target
  by accident.
- Single-exit-point cleanup in the spawn function; every error path releases what it acquired.
- Reuse a single input-file descriptor across executions (`ftruncate` + `pwrite` + `lseek`)
  rather than open/close per run — fewer descriptors touched and faster.
- Raise `RLIMIT_NOFILE` at startup where permitted, so headroom masks nothing but tolerates
  bursts.

**Detection** M1 exit criterion 3: `/proc/self/fd` count after 10 000 executions must **exactly
equal** the count before. Cross-milestone invariant. The count is compared for equality, not for
"roughly stable" — a slow leak is the failure mode being hunted.

---

## RISK-12
### Fork-server deadlock (baseline; protocol-drift detail is RISK-23)
**Likelihood** High (this is the hardest code in the project) · **Impact** High · **Silent — the campaign just stops**

The fork server is a two-process protocol over pipes where one participant may be actively
corrupting its own memory. If the two sides desynchronise, both block on `read()` forever. The
status screen keeps showing the last numbers; exec/sec goes to zero; nothing crashes and nothing
errors. It can look like "the target got slower."

**Mitigation**
- **Deferred to M5 deliberately** (ARCHITECTURE.md D2), so it is built against a known-good
  `fork`/`exec` baseline rather than in the dark.
- **Every** pipe read has a timeout (`ppoll`); there is no unbounded blocking read anywhere in
  the protocol.
- Handshake and protocol are versioned; a mismatch is a hard error.
- On any protocol violation: kill the fork server, restart it, log loudly. Recovery is
  automatic, but never silent.
- Explicit fault-injection tests: kill the fork server mid-handshake, kill the child before it
  reports, close the pipe unexpectedly, have the target `exec` something else.
- The **differential test** (M5 exit criterion 2) — 100 000 inputs, identical maps and statuses
  vs the `fork`/`exec` executor — is the ship gate. No divergence tolerated.
- A stall detector in the main loop: exec/sec dropping to zero for N seconds is reported as an
  error, not just displayed.

**Detection** Fault-injection suite with a **global test timeout**, so a hang fails CI instead of
hanging it. Plus the stall detector at runtime.

---

## RISK-13
### Persistent-mode state carryover
**Likelihood** High (inherent to the technique) · **Impact** High · **SILENT**

In-process fuzzing accumulates global state, cached allocations, and heap layout across
iterations. A crash on iteration 40 000 may depend on the preceding 39 999 inputs, so the
single input we save does not reproduce it. Reporting that to a maintainer wastes their time and
damages the project's credibility.

**Mitigation**
- Persistent mode is **opt-in, never a default** (ARCHITECTURE.md §1.5).
- **Mandatory re-verification**: every persistent-mode crash is replayed in a **fresh
  `fork`/`exec` process** before being recorded. This is not configurable.
- Crashes that fail re-verification go to a separate `quarantine/` directory with a clear
  explanation, and are **never** presented as findings.
- A bounded iteration count per process (`__AFL_LOOP(N)`-style) caps carryover.
- Documentation states plainly what persistent mode does and does not guarantee, so a user
  opting in knows the trade.

**Detection** M5 exit criterion 5. The quarantine directory being non-empty is itself a signal
worth surfacing in the status output.

---

## RISK-14
### Silent coverage loss
**Likelihood** Medium · **Impact** **Critical** (the fuzzer looks healthy and finds much less) · **SILENT**

Several independent mechanisms quietly discard coverage:
- **Hash collisions** (avoided by design in D4, but a future binary-only backend reintroduces
  them).
- **Guard count exceeding the map size**, wrapping IDs.
- **Counter wrap** at 256 landing a hot edge in a *lower* bucket than a colder one.
- A module that was never instrumented at all — e.g. the interesting parser lives in a
  dependency built without `mafl-cc`.

Every one of these presents as "the fuzzer runs fine but finds less than it should," with no
error anywhere.

**Mitigation**
- **Collision-free sequential IDs** from the guard array (D4), removing the largest source.
- **Loud warning with actual numbers** when the guard count exceeds the map size, stating the
  count and the implied collision rate — plus a pointer to the build-time map-size override.
- **Saturating counters** at 255 instead of wrapping (D4), removing the bucket-inversion source.
- Report the **instrumented module list and total guard count** at startup, so "my dependency
  wasn't instrumented" is visible in the first ten lines of output rather than never.
- Report map utilisation (fraction of slots used) in the status output.

**Detection** M2 exit criterion 2 (ground-truth edge count against a hand-counted CFG) and
criterion 8 (recorded overhead). Startup diagnostics make the common case self-evident.

---

## RISK-15
### Fuzzer-induced crashes reported as target bugs
**Likelihood** Medium · **Impact** **Critical** (reputational; wastes maintainers' time) · **SILENT**

A crash can originate from *us* rather than the target: coverage-map corruption (RISK-06), a
malformed argv, a bad input file, an environment problem, or an OOM. Recorded naively, it
becomes a bug report for a bug that does not exist. Because the project's end goal is
disclosure to real maintainers, this is a first-class risk, not a nuisance.

**Mitigation**
- **Every crash is re-verified before being recorded**, in a fresh `fork`/`exec` process with a
  clean environment.
- Additionally re-verified against an **uninstrumented build** where one is available — if the
  crash needs our instrumentation to happen, it is ours.
- `SPAWN_FAIL` is a distinct status from `CRASH`; an infrastructure failure can never be
  recorded as a finding.
- The generated `repro.sh` is **self-contained** and does not depend on the fuzzer at all, so
  reproduction is verified independently of our code.
- Every artifact records the exact target build configuration, sanitizer flags, and commit.
- Manual review of the artifact plus an independent reproduction is a **required step** before
  any disclosure — this is written into the M6 disclosure rules, not left to judgement.

**Detection** M4 exit criterion 6 (`repro.sh` works from a clean shell in a fresh container) and
M6 exit criterion 3 (findings reproduce on a *different* machine).

---

## RISK-16
### Environment misconfiguration destroying throughput
**Likelihood** High (default-configured Linux systems are typically wrong for fuzzing) · **Impact** Medium · **Loud once you know to look**

Piped `core_pattern` adds seconds per crash and causes crashes to be misclassified as hangs. A
`powersave` CPU governor makes timing unstable and poisons timeout calibration. Thermal
throttling, a filesystem output directory instead of tmpfs, and an over-restrictive `RLIMIT_AS`
each cost throughput or correctness.

**Mitigation**
- A startup **environment audit** that checks each of these and prints a specific, actionable
  fix (the exact command to run) rather than a vague warning. The audit is extended in the M1
  hardening addendum with the `RLIMIT_NOFILE` check it already had, plus two checks it was
  missing: a `statvfs` free-space floor on the output directory (the RISK-02 startup check that
  was promised here but not implemented) and a `/proc/sys/kernel/yama/ptrace_scope` warning,
  because a restrictive `ptrace_scope` silently breaks the M4/M5 `ptrace`-based triage and
  fork-server debugging paths.
- Recommend a tmpfs output directory in the documentation, with a measured comparison.
- `RLIMIT_AS` **off by default** (D5), because it breaks sanitizer builds — which are exactly
  what M6 needs.
- Never require root: everything is advice plus a documented rationale.

**Detection** The audit runs on every startup. A troubleshooting guide (M6) keys each symptom to
the corresponding warning.

---

## RISK-17
### Target escaping containment / damaging the host
**Likelihood** Low–Medium · **Impact** High · **Loud**

The target is a program being fed deliberately malformed input. It may write files, open
sockets, spawn processes, or delete data — and under a memory-safety bug it may do so with
attacker-influenced arguments.

**Mitigation**
- Children get restrictive rlimits (`NPROC`, `FSIZE`, `CORE`, optionally `CPU`), a dedicated
  process group, `PDEATHSIG`, and stdio redirected to `/dev/null`.
- `execve` with an explicit path, never `execvp` — no `PATH` searching in a tool pointed at
  untrusted directory trees.
- A minimal, explicitly-constructed environment for the child rather than inheriting ours
  wholesale — **`inherit_env` defaults to false**. *(Audit note: until the M1 hardening
  addendum lands, the code inherited the fuzzer's full `environ` verbatim while this document
  claimed the opposite, so this mitigation was only partially effective. The addendum closes
  that gap and is the delivery vehicle for `MAFL_SHM_ID`.)*
- The child runs with its **working directory set to a scratch directory**, so relative-path
  writes land somewhere disposable.
- Documentation states plainly what we do **not** contain — we are not a sandbox; no seccomp
  filter, no namespaces, no network isolation in v1 — and recommends running campaigns in a
  container or VM. Honesty here is worth more than an overstated guarantee.
- Seccomp/namespace isolation is a documented post-v1 candidate, not an implied feature.

**Detection** M6 sandboxing review. Validation campaigns run in containers.

---

## RISK-18
### Prior-art constants transcribed wrong from memory
**Likelihood** High · **Impact** High · **SILENT**

Design constants recalled rather than read — the fork-server FD numbers, the `INTERESTING_*`
tables, `ARITH_MAX`, the bucket thresholds, the `>> 1` in the edge hash — are individually
plausible and collectively load-bearing. A wrong value does not produce an error; it produces a
fuzzer that works but is measurably worse, and the cause is nearly impossible to find later
because the code *looks* right.

This risk is elevated for this project specifically: the design pass was authored without
network access, so a set of constants was initially recalled rather than verified.

**It has already materialised, which is why it is rated High rather than theoretical.** The
Phase 0 research pass found that **two** confidently-held recollections were flatly wrong:

- AFL++'s deterministic stage was recalled as *disabled* by default (`-D` to enable). In
  current builds it is **enabled** by default, disabled with `-z`, and `-d`/`-D` are ignored.
  Acting on the recalled version would have set our own default backwards.
- AFL++'s default power schedule was recalled as `explore`. It is **`fast`**.

Neither would have produced an error message. Both would have produced a quietly inferior
fuzzer whose deficiency is invisible from the outside.

**Mitigation**
- Every claim in ARCHITECTURE.md carries a marker: `[K]` (structural), `[V-OK]` (verified,
  with a source URL in §10), or `[V?]` (recalled, unverified).
- Each open backlog item is **blocking for the milestone that consumes it**, and the resolved
  value plus source URL is recorded on resolution.
- Value tables are transcribed **from upstream source**, and a unit test pins every entry so a
  later edit cannot silently change one.
- **Version-dependence is treated as a first-class hazard.** The deterministic-stage default
  differs across AFL++ releases and much published documentation still describes the old
  behaviour, so the doc records *both* states and says to check the installed build.
- Where our design deliberately diverges from AFL (collision-free IDs, saturating counters), the
  divergence is documented as a decision **with** its rationale, so it is not mistaken for a
  transcription error by a future reader.

**Detection** The M2/M3/M4/M5 exit criteria each begin with "resolve the relevant verification
backlog items." A milestone cannot be marked done with an open `[V?]` it depends on.

---

## RISK-19
### Development-host mismatch (Windows, no WSL)
**Likelihood** Certain (current state) · **Impact** Medium (slows everything; risks untested code) · **Loud**

The development machine is Windows with no WSL distribution installed. None of this code can be
compiled or run locally. Every `fork`/`shm`/signal behaviour would have to be validated through
CI round-trips, which is a brutal iteration loop for exactly the class of bug that needs a
debugger — and creates pressure to write code that is "probably right" instead of tested.

**Mitigation**
- **CI is a hard gate from the first commit**, not an afterthought — GCC and Clang, plus
  sanitizer runs, on every push.
- Tests are written to be diagnostic (they report *what* differed) so a CI failure is actionable
  without a local debugger.
- **Recommendation: install WSL2 (Ubuntu 22.04+) or a Linux VM before starting M2.** M1's
  vertical slice can survive CI-only iteration; M2's shared-memory and constructor-ordering work
  realistically cannot.
- No line-ending or path-separator assumptions in scripts; all shell scripts are LF and
  POSIX-portable.

**Detection** CI is the only correctness signal until a Linux environment exists. That is
precisely why it is set up first.

---

## RISK-20
### Disclosure and legal missteps in M6+
**Likelihood** Medium · **Impact** High (legal exposure; reputational damage; harm to maintainers) · **Loud, and irreversible**

Fuzzing something we lack authorisation for, publishing before a fix ships, or dumping
low-quality reports on unpaid maintainers each cause real harm — and unlike the technical risks,
these cannot be rolled back.

**Mitigation**
The ten standing disclosure rules in ROADMAP.md, binding from M6 onward. In summary: only
locally-built open-source targets on our own hardware; never live or hosted systems; the
project's own security process first; respect coordinated timelines; no exploit development
beyond demonstrating impact; minimised, high-quality reports only; duplicate-check first; no CVE
farming; credit is an outcome, never the objective.

Operationally: a written pre-flight checklist per target (built locally? disclosure process
identified? already-known?) completed **before** a campaign starts, not after a crash is found
and enthusiasm is high.

**Detection** Process discipline. This is the one risk with no automated detector, which is why
the rules are written down as binding rather than left to in-the-moment judgement.

---

## RISK-21
### Scope creep / never-finished syndrome
**Likelihood** High · **Impact** Medium · **Loud in hindsight**

A fuzzer has an infinite feature backlog: grammar-aware mutation, concolic execution, hardware
tracing, distributed fuzzing, a web UI. The failure mode is a project that is perpetually 80 %
done on six subsystems and has never found a bug.

**Mitigation**
- Milestones are defined as **shippable increments** with concrete exit criteria; a milestone
  ends when its criteria pass, not when it feels complete.
- ARCHITECTURE.md §7 lists what v1 deliberately does **not** do, so "missing" is distinguishable
  from "forgotten."
- The next milestone does not start until the current one's tests are green.
- The primary success metric is **"found a real bug in a real library"** (M6 criterion 5), not
  feature count.

**Detection** Milestone exit criteria are checklists. An unchecked box is visible.

---

## RISK-22
### Coverage plateau — the fuzzer works but finds nothing
**Likelihood** High · **Impact** High · **SILENT**

The most common real-world outcome for a home-built fuzzer: everything is technically correct,
exec/sec looks great, and coverage stops growing after ten minutes because the mutator cannot
get past a magic-number check, a checksum, or a length field. The tool reports healthy
statistics forever while exploring 3 % of the target.

**Mitigation**
- **Dictionary support in M3** — the single highest-leverage feature for structured formats, and
  the difference between reaching a parser's body and never getting past its header.
- Good seed corpora: documentation emphasises starting from real, valid, *diverse* files, which
  matters more than any mutator refinement.
- Splicing, to escape local optima that bit-level mutation cannot.
- **Coverage-over-time reporting and plateau detection**, so the plateau is *visible* rather
  than inferred — a warning when no new coverage has appeared for N minutes.
- M5 scheduling work to spend effort where it pays.
- Documented guidance on removing checksum checks from the target build (the standard practice),
  since no mutator will ever satisfy a CRC by chance.

**Detection** M3 exit criterion 6 (coverage must grow then plateau, not start flat) and the
runtime plateau warning. M6 criterion 5 — rediscovering a known CVE — is the honest end-to-end
check that the pipeline actually finds things.

---

## RISK-23
### Fork-server pipe desync under protocol drift / version skew
**Likelihood** High · **Impact** High · **Silent — the campaign stops and the status screen keeps printing**

The fork server is a two-process protocol over pipes where one side is under test and may be
scrambling its own memory. If the two sides desynchronise — a short read, a torn 4-byte message,
a child that forked but never reported — both block on `read()` forever. exec/sec collapses to
zero, nothing crashes, nothing errors, and a stall detector is the only thing that distinguishes
it from "the target got slow."

**Mitigation**
- A **versioned handshake**: the fork server and fuzzer exchange a protocol version in the hello
  message; a mismatch is a hard startup error, never a silent desync.
- **Every** pipe read has a deadline via `ppoll`; there is no unbounded blocking read anywhere in
  the protocol (this is a fuzzing-loop invariant, CONTRIBUTING.md §5b).
- On any protocol violation: kill the fork server, restart it, log loudly. Recovery is automatic
  and always reported, never silent.
- The M1 `fork`/`exec` executor is retained as the correctness reference; the fork-server path
  is gated on the M5 differential-equivalence test, not shipped ad hoc.

**Detection** M5 exit criteria 2 (100 000-input differential equivalence vs the M1 executor) and
4 (fault-injection suite with a global test timeout). A hang fails CI rather than hanging it.

---

## RISK-24
### Sanitizer interference with crash classification
**Likelihood** High on sanitizer-built targets · **Impact** **Critical** · **SILENT**

Sanitizers change the observable behaviour we classify on. ASan installs its own `SIGSEGV`
handler and exits with a normal **exit code** rather than dying by signal, so a genuine crash in
an ASan-built target classifies as `OK` — the exact inversion of RISK-04, and invisible because
the executor is "correct" by its own wasted-sample test. Separately, ASan's multi-terabyte
shadow reservation is counted by `RLIMIT_AS`, so our default-off memory cap breaks sanitizer
builds if set carelessly.

**Mitigation**
- Test targets are always built **without** sanitizers, in a separate compiler invocation from
  the fuzzer (enforced in the Makefile and stated in ARCHITECTURE.md §6).
- For sanitizer-built targets, classification is informed by **parsed sanitizer output**
  (captured via a child-stderr side channel), flagged in the result as such, and never silently
  relied on (M4, RISK-24 scope).
- `RLIMIT_AS` stays **off by default** (D5); the truer ASan interaction is recorded as verified
  only when V10 is resolved, not asserted from folklore.
- Every finding that matters is re-verified against an **uninstrumented build** before reporting
  (RISK-15), which is the final backstop.

**Detection** M4 exit criterion 2 requires one purpose-built crasher per class *including* an
ASan-built and UBSan-built variant, each classified correctly. The unsanitized-test-target rule
is asserted by the build, not by review.

---

## RISK-25
### Mutation-engine memory unsafety in the fuzzer itself
**Likelihood** Medium · **Impact** **Critical** (a fuzzer crash mid-campaign zeroes hours of state) · **SILENT until hourly**

The mutation engine manipulates arbitrary-length buffers with arbitrary lengths — precisely the
code shape that produces off-by-ones — and it runs millions of times per campaign inside the
process that holds the only copy of the findings. A mutator off-by-one is a crash in the
*fuzzer*, indistinguishable from a target bug until it costs a run.

**Mitigation**
- Mutators are **pure and total functions** of `(input bytes, RNG state)`: no globals, no I/O,
  terminate for every input including empty and maximum-length, never produce a length outside
  configured bounds (CONTRIBUTING.md §5b). Purity is what makes the following test possible.
- **Property tests over 10⁶ random inputs under ASan**: never read/write out of bounds, always
  terminate, always respect bounds (M3 exit criterion 2).
- Explicit length bounds on every buffer operation; banned functions apply to the mutation
  module the same as everywhere (§3).
- A fuzzer crash is treated as a P0 defect in the fuzzer itself, never blamed on the target.

**Detection** M3 exit criterion 2; cross-milestone invariant 5 (clean under ASan+UBSan) on every
milestone after M3.

---

## RISK-26
### Non-reproducible campaigns (non-deterministic PRNG or scheduling)
**Likelihood** Medium · **Impact** High · **SILENT**

If the campaign PRNG is `rand()`/`random()`, the mutation sequence varies across libc
implementations and machines; if time-of-day or wall-clock statistics leak into scheduling or
mutation-operator selection, the same campaign run twice diverges. Either way, a "reproduce this
finding" workflow quietly breaks, and the failure surfaces only when a maintainer or a re-run
cannot repeat an earlier result — the worst possible moment.

**Mitigation**
- A self-contained deterministic PRNG (splitmix64/xoshiro256** class), seeded explicitly; the
  **seed is recorded in the campaign header** and accepted as a CLI flag (CONTRIBUTING.md §5b).
- `rand()`/`random()` are banned for anything PRNG-related (the ban-list check in CI, §3).
- Scheduling decisions — including any MOpt-style operator statistics — are seeded from corpus
  state, never from the wall clock (M5 design note).
- A replayed campaign under the recorded seed must produce a byte-identical mutation sequence and
  the same interesting-input set; this is cross-milestone invariant 10.

**Detection** M3 exit criterion 3 (fixed-seed reproducibility across runs, machines, both
compilers) and invariant 10 on every milestone.

---

## RISK-27
### Shared-corpus corruption under multi-process parallelism
**Likelihood** Medium · **Impact** High · **SILENT**

M5 runs N fuzzer processes against one corpus directory. Concurrent writes — corpus import, new
seed addition, `mafl-cmin` output — race unless disciplined. A torn write looks like a perfectly
valid input to the peer that imports it, so corruption propagates: a truncated or spliced file
becomes a seed, gets mutated, and prompts "found nothing useful" results that are actually our
own corruption.

**Mitigation**
- All corpus writes are atomic (temp + `fsync` + `rename` + dir `fsync`, per ARCHITECTURE.md §3)
  — a peer sees a complete file or no file.
- Per-process queue namespaces with a documented periodic sync/import window (AFL-style), rather
  than a lock on the shared directory.
- Corpus reads are validated by checksum where artifacts carry one, and a corrupted imported file
  is quarantined, not fuzzed.
- `mafl-cmin` writes to a staging area and only atomically publishes.

**Detection** M5 exit criterion 8's replay-check (checksums + full replay after a 4-process run,
asserting no corruption and no lost entries). Cross-milestone invariant 11 applies from M5.

---

## RISK-28
### Coverage-feedback poisoning: instrumented build diverges from baseline
**Likelihood** Medium · **Impact** **Critical** · **SILENT**

The runtime writes into the target's address space on every edge. If instrumentation changes
observable behaviour — a timing shift that alters a race, a layout change that alters a heap
bug's visibility, an out-of-bounds *write by us* that nudges the target's parser — the coverage
we gain steers mutation into paths **that only exist because we instrumented the binary**. The
fuzzer then converges on inputs whose "bugs" are instrumentation artifacts with no counterpart
in the distribution binary.

**Mitigation**
- The M2 standing **instrumented-vs-uninstrumented differential harness**: a fixed corpus run
  against both builds must produce identical exit statuses, wired into CI from M2, not
  retrofitted (M2 exit criterion 10).
- Every finding is re-verified against the uninstrumented build before recording (RISK-15);
  a crash that only reproduces with our instrumentation is quarantined, never reported (M4
  scope and criterion 8).
- Map-size negotiation and per-index masking so our writes can never run past the map (D4).
- The runtime is deliberately tiny, allocation-free, and compiled `-fno-sanitize-coverage`, so
  it cannot instrument itself into recursive divergence (RISK-06 mitigation re-anchored here).

**Detection** M2 exit criterion 10 and M4 exit criterion 8; cross-milestone invariant 9 on every
milestone after M2.

---

## RISK-29
### Dedup over-merge hiding a second exploitable bug
**Likelihood** Medium · **Impact** **Critical** · **SILENT**

Layer-1 dedup buckets on `(signal, bucketed-map fingerprint)`; Layer-2 merges further by stack
hash. If the bucketing is too coarse — two genuinely distinct bugs that share a faulting signal
*and* a similar coverage fingerprint — they collapse into one bucket, one artifact directory,
one report. The second bug is never disclosed, never fixed, and the campaign statistics look
healthier than reality. This is the dual of under-merging and is tested in **both directions**.

**Mitigation**
- Dedup accuracy is asserted in **both directions** in M4: 10 000 inputs hitting one bug produce
  one artifact, **and** two genuinely distinct bugs — including two that share the same faulting
  signal — produce two (M4 exit criterion 5).
- Stack-hash merges are **confirmed against the uninstrumented faulting address and parsed
  sanitizer class** before collapsing two Layer-1 buckets into one; a merge that would rely on a
  single shared signal alone is rejected.
- The artifact metadata records every Layer-1 bucket that was merged into it, so a later audit
  can expand an over-merge without re-running the campaign.
- Bucket parameters are recorded per campaign; a default that bloats mergers is visible in the
  artifact layout.

**Detection** M4 exit criterion 5 (both-directions dedup test); the merge-confirmation record in
each artifact makes over-merging auditable after the fact.

---

## RISK-30
### Supply-chain / dependency risk from any future third-party library
**Likelihood** Low now, non-zero from M7 onward · **Impact** High · **Loud once it happens, preventable only in advance**

v1 holds a hard no-third-party-dependency rule for the fuzzer core (D7), which is itself a risk
mitigation: each dependency is code that can crash *us* and lose findings. The moment an
advanced module — a concolic-solver bridge, a structured-input library, a grammar engine — pulls
in external code, the trust surface doubles and the rule starts to erode by a thousand small
justifications.

**Mitigation**
- The **D7 rule stands for the hot path**: the fuzzer core, executor, runtime, mutator, and crash
  manager stay libc + POSIX only. Any exception requires a written justification in
  ARCHITECTURE.md §D7 **and** review sign-off, in the same commit (CONTRIBUTING.md §12).
- Advanced modules that genuinely need a third-party component run as **separate binaries**
  feeding the corpus directory (per M7's solver-integration design), never linked into the
  fuzzer core.
- A CI **`ldd` audit** asserts the shipped binary links only the expected system libraries; a new
  linked library fails the build until justified.
- Any third-party code that must be vendored is pinned, reviewed, and carried under
  `third_party/` with its license, never silently fetched.

**Detection** The `ldd` audit in CI on every push (CONTRIBUTING.md §10 gate 7). The D7 review
trail makes any erosion visible in the commit history.

---

## RISK-31
### TOCTOU on the staged input file and `@@` substitution
**Likelihood** Low · **Impact** Medium · **Silent until a bizarre mis-trip**

The input is staged in a real file in the work directory and, in FILE mode, its path is handed to
the target via `@@`. A symlink planted in a predictable location, a work directory shared with
another process, or a name a target could guess between our `mkostemp` and the target's `open()`
could redirect reads or writes. The M1 code already uses `mkostemp` + `O_CLOEXEC` and a private
staging file, which eliminates the classic class, but the discipline must not regress as file
delivery gains features.

**Mitigation**
- The staged input lives in a **private, attacker-unshared work directory** (default `/tmp` is a
  safe floor; a campaign-scoped directory is better and is settable via `cfg.work_dir`).
- `mkostemp` names are unpredictable; the file is created before the target is spawned and its
  descriptor is opened `O_CLOEXEC` so it never leaks to the child.
- The file is re-staged per run (`ftruncate` + `pwrite` + `lseek`) rather than appended, so a
  target that corrupted a previous input cannot smuggle that into the next run.
- The constructed child environment (M1 addendum) removes any locale- or path-driven surprise in
  how the target resolves the staged file path.
- Document that FILE mode is designed against *accidental* misuse, not against a target with a
  malicious local helper that shares our work dir with write access — that belongs in a
  container (RISK-17).

**Detection** The M1 hardening addendum's environment tests; review against CONTRIBUTING.md §5
(process handling) and §6 (persistence) on any change to `stage_input` or the `@@` path.

---

## Summary: the six risks that matter most

If attention is limited, these are the ones that produce **wrong findings** rather than merely a
broken tool — and every one of them is silent:

1. **RISK-06** — coverage map corrupting the target → fake bugs reported to maintainers.
2. **RISK-07** — non-determinism breaking minimisation → reports that do not reproduce.
3. **RISK-15** — fuzzer-induced crashes recorded as target bugs → reports for bugs that do not exist.
4. **RISK-04** — hangs misclassified as crashes → the findings set is noise.
5. **RISK-28** — instrumented-build divergence → the fuzzer chases and reports paths that only
   exist because we instrumented the binary.
6. **RISK-29** — dedup over-merge → a second exploitable bug collapses into an already-reported
   bucket and is never disclosed.

All six are addressed by the same architectural commitment, which is the most important single
decision in this design: **every crash is re-verified in a fresh, isolated, uninstrumented
process before it is recorded as a finding.** The M1 `fork`/`exec` executor is retained forever
precisely so that this path always exists (ARCHITECTURE.md D2), and the M2 instrumented-vs-
uninstrumented differential is the standing detector that the instrumentation itself is not
changing the answer.
