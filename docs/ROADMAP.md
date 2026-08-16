# Mini-AFL — Roadmap

Six core milestones over 6–12 months, plus one explicitly optional extension track. Each core
milestone is a **shippable, independently testable increment**: at the end of every milestone the
tool works, the test suite is green in CI, and the thing it claims to do is demonstrable on a real
command line. "Production-ready" is achieved at the end of M6; M7 collects advanced methodologies
that are individually valuable but **not required** to call the tool trustworthy.

**Sequencing rule.** A milestone is not started until the previous one's exit criteria are met
and its tests are green. The temptation to start M3's mutators while M1's reaping is still
flaky is the single most likely way this project produces an unreliable fuzzer — mutation bugs
and executor bugs look identical from the outside (both manifest as "coverage looks wrong"),
so they must never be in flight simultaneously.

**Time estimates** assume part-time work and are deliberately wide. Ordering and exit criteria
matter; the dates do not.

---

## M0 — Scaffold *(done in this pass)*

Repository layout, build system, CI, engineering standards, design docs, and a minimal
`fork`/`exec`/`waitpid` vertical slice that proves the toolchain works end to end.

**Exit criteria**
- [x] `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/RISK_REGISTER.md`, `docs/CONTRIBUTING.md`
- [x] `make && make test` builds and runs a passing suite
- [x] CI builds with GCC and Clang and runs tests on every push
- [x] Vertical slice distinguishes normal exit / signal crash / timeout, reaps all children

---

## M1 — Target Execution Engine

**Goal.** A process-spawning engine that is *correct and boring*: it never leaks a child,
never leaks a descriptor, never misclassifies a status, and never hangs. Everything later in
the project sits on top of this, so latent bugs here surface as inexplicable coverage or
phantom crashes months from now.

### Scope
- `mafl_exec` API: create / run-one-input / destroy.
- Input delivery: **file argument** (`@@` placeholder in argv) and **stdin**.
- Status classification: `OK`, `CRASH(signal)`, `TIMEOUT`, `KILLED`, `SPAWN_FAIL`.
- All ten controls from ARCHITECTURE.md D5 applied between `fork()` and `execve()`.
- Timeout via `pidfd_open` + `ppoll` (no signal handlers), with `syscall()` fallback.
- Escalating kill: `SIGKILL` to the process **group**, then a bounded reap wait, then a
  hard-failure report if the child is still unreaped.
- `SIGSEGV`, `SIGABRT`, `SIGBUS`, `SIGFPE`, `SIGILL` distinguished, plus `SIGKILL`/`SIGTERM`
  recognised as *our own* kills rather than target crashes.
- Startup environment audit: piped `core_pattern`, CPU governor, `RLIMIT_CORE`, missing or
  non-executable target → clear, actionable warnings.
- Graceful shutdown on `SIGINT`/`SIGTERM` that kills in-flight children before exiting.

### M1 hardening addendum (Phase-1 security-audit findings — landed under M1, no renumbering)

The execution-engine vertical slice passed its original exit criteria, but a deep audit surfaced
a set of edge-case and hardening defects that must be closed before the coverage milestone builds
on the executor. None of these change the public API shape; all are priced in *here* so M2 does
not start with a known-fragile base.

1. **`read_file` guards and termination** (`src/main_run.c`). Reject non-regular inputs (`fstat`
   + `S_ISREG`) before the `fseek`/`ftell`/`fread` dance so a device, FIFO, or `/proc` path fails
   loudly instead of hanging or lying about size. The buffer already allocates a spare byte;
   write `buf[len] = '\0'` so downstream string handling can never over-read the unstated
   terminator.
2. **Bounded reap in `mafl_exec_destroy`** (`src/exec.c`). Replace the unbounded
   `waitpid(pid, &status, 0)` teardown loop with the existing bounded `reap_killed` discipline,
   so a child stuck in an uninterruptible kernel wait (`D` state) produces a hard error instead
   of hanging a Ctrl-C'd campaign on exit forever (RISK-03 on the teardown path).
3. **Minimal constructed child environment behind an `inherit_env` flag** (`src/exec.c`). Stop
   handing the target the fuzzer's full `environ` by default. Default to a minimal
   explicitly-constructed environment; `cfg.inherit_env = true` restores the current behaviour
   for targets that genuinely need `LD_LIBRARY_PATH` or locale variables. This closes the gap
   between ARCHITECTURE.md D5's claimed "minimal environment" and the code's actual full
   inheritance, and carries the `MAFL_SHM_ID` plumbing M2 needs without a later exec.c API break.
4. **Host audits: `statvfs` free-space and `ptrace_scope`** (`src/env_audit.c`). Refuse to start
   when the output filesystem has less than a threshold of free space (the "free-space check at
   startup" RISK-02 already promises but the code does not yet run), and warn when
   `/proc/sys/kernel/yama/ptrace_scope` would block the M4/M5 `ptrace`-based triage and
   fork-server debugging paths, with the exact command to relax it (completing RISK-16).

**Tests (addendum).** Each item ships with a dedicated failing-first regression test: a
non-regular `-i` path is rejected; teardown reap is bounded and errors visibly against a
SIGKILL-surviving stub; an env-dumping target sees only the constructed set by default and the
full set under `inherit_env`; and fudged fixtures make both new audits emit their documented
warning text.

### Exit criteria — concrete and testable
1. **Correct classification.** One purpose-built test target per case in `tests/targets/`:
   clean exit 0, non-zero exit, each of the five crash signals, infinite loop, sleep-longer-
   than-timeout, fork-a-child-then-hang, `exit()` from a static destructor, a target that
   closes stdin, a nonexistent path, and a non-executable file. Every case asserts the exact
   expected status.
2. **Zero child leakage.** After 10 000 mixed executions, `waitpid(-1, ..., WNOHANG)` returns
   `-1/ECHILD` — no unreaped children, no zombies.
3. **Zero descriptor leakage.** Open-fd count (`/proc/self/fd`) after 10 000 executions equals
   the count before, exactly. Asserted in CI, not eyeballed.
4. **Timeout accuracy.** A target sleeping 5× the timeout is killed within 2× the configured
   deadline, measured over 100 runs. No run exceeds the bound.
5. **Process-tree kill.** A target that forks a grandchild which ignores `SIGTERM` leaves
   **nothing** running after the executor returns. Verified by scanning for the process group.
6. **Throughput floor.** ≥ 1 000 exec/sec on a trivial static target on one core. This is the
   `fork`/`exec` baseline; it exists so the M5 fork-server win can be measured against a
   recorded number.
7. **Clean under sanitizers.** Whole suite passes under ASan + UBSan with zero findings.
8. **No signal handlers on the exec path.** Enforced by review and asserted by a test that
   verifies `SIGALRM`/`SIGCHLD` dispositions are untouched after N executions.
9. **Hardening addendum landed.** All four addendum items implemented with their dedicated
   tests, listed above, passing in CI. M1 does not exit until this box is checked, because M2
   and M4 both depend on the fixed behaviours.

### What could go wrong
- **`waitpid` bookkeeping.** The classic bug is treating `WIFSIGNALED` as "target crashed"
  when it was *our* `SIGKILL` for a timeout. Result: every hang recorded as a crash, and the
  crash directory fills with garbage. Mitigation: track our own kill intent explicitly and
  test the hang case directly.
- **`pidfd` semantics.** A readable `pidfd` means *terminated*, not *reaped*. Forgetting the
  subsequent `waitpid()` produces a slow zombie leak that only shows up hours in — which is
  precisely why exit criterion 2 uses 10 000 iterations and not 10.
- **Descriptor leak on the error path.** The input-file fd or the `pidfd` leaks when `execve`
  fails. Invisible until `EMFILE` at hour six. Criterion 3 exists for this.
- **`PR_SET_PDEATHSIG` race.** Parent dies between `fork()` and `prctl()` → orphan. Mitigated
  by the child re-checking `getppid()`.
- **`SIGCHLD` set to `SIG_IGN`** by an inherited disposition makes `waitpid()` fail `ECHILD`.
  Explicitly reset at executor creation.
- **`vfork`/`posix_spawn` temptation** for speed. Both have subtle restrictions on what may run
  in the child; our child must call several `setrlimit`/`prctl`/`personality` functions before
  `execve`. Use plain `fork()`. Speed is M5's problem.
- **Environment minimisation breaking real targets** (addendum item 3). A target that silently
  depends on inherited `LD_LIBRARY_PATH` or locale variables starts failing for non-obvious
  reasons. The fix is the flag and a clear error message, not reverting to full inheritance.
- **An unbounded reap on the teardown path** (addendum item 2) hanging a Ctrl-C'd campaign
  against a target in uninterruptible I/O. This is exactly the failure that convinces a user the
  tool "locks up on exit"; bound it.

**Estimate.** 3–6 weeks for the core (done); **+1–2 weeks** for the hardening addendum.

---

## M2 — Shared-Memory Coverage Tracker

**Goal.** The instrumented target reports edge coverage into a shared bitmap, and the fuzzer
decides "is this new?" correctly and cheaply.

### Scope
- `mafl_rt`: the coverage runtime linked into the target, implementing
  `__sanitizer_cov_trace_pc_guard_init` and `__sanitizer_cov_trace_pc_guard`.
- Sequential, collision-free guard→slot ID assignment across all instrumented modules, with a
  loud warning when the guard count exceeds the map size.
- Shared memory via `shm_open` + `mmap` (**not** `shmget`/`shmat` — see RISK-05), with the name
  passed to the target via the **`MAFL_SHM_ID` environment variable** (the `inherit_env`
  constructed-environment plumbing for this lands in the M1 hardening addendum) and the segment
  `shm_unlink`ed immediately after mapping so the kernel reclaims it even on a hard kill.
- A **dummy fallback map** in the runtime so the guard callback is safe from process start,
  before the real map is attached (the constructor-ordering race, ARCHITECTURE.md §1.3).
- Map-size negotiation between fuzzer and runtime; a mismatch is a hard error.
- Hit-count bucketing and the global accumulated "virgin" map.
- New-coverage detection: does any bucket exceed the global map?
- `mafl-cc` wrapper: a compiler shim that adds `-fsanitize-coverage=trace-pc-guard` and links
  `mafl_rt`, so instrumenting a target is `CC=mafl-cc make`.
- **Target-determinism / stability probe** (resolves ARCHITECTURE.md Q4): run the same input
  twice, report the fraction of edges that differ. A target below a threshold is flagged as
  non-deterministic *up front*, because everything downstream (minimisation, dedup, crash
  reproduction) assumes determinism. The probe runs automatically at campaign start and its
  verdict is recorded in the campaign header.
- **Instrumented-vs-uninstrumented differential harness**: for a sanity target with known
  behaviour, the same input set is executed against both builds and the exit statuses must match
  exactly. This is the standing detector for RISK-06-class instrumentation-induced behaviour
  changes, and it is wired into CI from this milestone, not retrofitted at M4.

### Exit criteria
1. **Verification backlog items V2d, V3, V5b, V10, V11 resolved** with source URLs recorded in
   ARCHITECTURE.md §10. V5b (edge critical-edge splitting, no-prune scope, call-vs-inline overhead) is the one
   that can change the design, so it is resolved **first**, before this milestone's code is
   written.
2. **Ground-truth coverage.** A target with a hand-counted CFG (a documented number of edges)
   reports exactly the expected set of edges for a set of hand-chosen inputs.
3. **Determinism.** The same input produces a byte-identical map across 1 000 runs on a
   deterministic target.
4. **New-coverage correctness.** An input exercising a known-new branch is reported new; a
   replay of an already-seen input is reported not-new. Both asserted, not sampled.
5. **No segment leaks.** After 10 000 executions including crashes and `SIGKILL`s,
   `/dev/shm` contains no `mafl-*` entries. Also asserted after killing the fuzzer with
   `SIGKILL` mid-run.
6. **Constructor-ordering safety.** A target with an `__attribute__((constructor))` containing
   an instrumented branch does not crash and does not corrupt memory.
7. **Multi-module.** A target linking two separately-instrumented shared objects gets disjoint,
   non-overlapping ID ranges. Verified by inspecting the assignment.
8. **Overhead measured and recorded.** Instrumented vs uninstrumented exec/sec, written down
   so D3's "revisit if the call overhead dominates" has a number behind it.
9. **Stability probe works.** A deterministic target reports 100 % stability; a deliberately
   non-deterministic target (reads `/dev/urandom`, or branches on an uninitialised value) is
   correctly flagged, with the measured fraction shown.
10. **Instrumentation differential is clean (RISK-06, RISK-28).** On a sanity target with known
    behaviour, the instrumented and uninstrumented builds produce **identical exit statuses**
    for every input in a fixed corpus. Any divergence is a milestone blocker — it means our
    runtime changes the target's observable behaviour, which is exactly the failure that
    manufactures fake findings later.

### What could go wrong
- **The constructor race is the sharpest edge in this milestone.** `_init` and the first guard
  callbacks can fire before our map is attached. A null-pointer map means an immediate crash in
  every target; worse, a *stale* pointer means silent memory corruption inside the target,
  producing phantom crashes that look like real bugs. The dummy-map fallback is mandatory, not
  optional.
- **SysV shm leaks.** A `shmget` segment outlives the process that created it; a crashing
  fuzzer leaks segments until reboot. This is exactly why D4 specifies `shm_open` + immediate
  `shm_unlink`.
- **Map-size mismatch** between the runtime's compiled-in size and the fuzzer's expectation
  means out-of-bounds writes into the target's address space — memory corruption that presents
  as random crashes in the target and would burn days. Negotiate explicitly; fail loudly.
- **Silent guard-count overflow.** More guards than map slots wraps IDs and quietly destroys
  coverage quality with no error. Must warn prominently with the actual numbers.
- **Coverage from our own runtime** polluting the map if `mafl_rt` is accidentally compiled with
  instrumentation. Enforce `-fno-sanitize-coverage` on the runtime and assert it in the build.
- **`MAFL_SHM_ID` plumbing colliding with the target's own environment use** or being stripped
  by the M1 constructed-environment change. The env plumbing belongs to both milestones; the
  addendum makes the constructed environment carry exactly this variable plus nothing
  instrument-specific by accident.

**Estimate.** 4–8 weeks. The single highest-risk milestone: it is the one that can corrupt the
target's memory and thereby manufacture fake findings.

---

## M3 — Input Mutation Engine

**Goal.** A closed loop: mutate → execute → measure → keep-if-interesting. At the end of M3
the tool finds a planted bug in a toy program on its own — under a **recorded seed**, so anyone
can replay the exact campaign.

### Scope
- **Deterministic PRNG with a recorded per-campaign seed** (RISK-26): a self-contained PRNG
  (**not** `rand()`, whose behaviour varies across libc implementations and would make
  campaigns irreproducible). The seed is logged in the campaign header and accepted as a CLI
  flag, so a campaign is byte-for-byte replayable.
- Deterministic stages: bit flips (1/2/4), byte/word/dword flips, arithmetic ±, interesting-value
  overwrites — walking every position exhaustively.
- Havoc: randomly stacked mutations at the **AFL `HAVOC_BLK_*` tiers** (32 / 128 / 1500 /
  32768, with the XL-tier selection probability pinned from source), using the
  **`ARITH_MAX = 35` bound and the `INTERESTING_8/16/32` tables transcribed from upstream
  `config.h` — from source, not memory — and pinned by a unit test over every entry** (RISK-18).
- **AFL-compatible dictionaries**: dictionary/token mutation reading the standard AFL dictionary
  file format, so existing per-format dictionaries drop in unmodified.
- **Splicing** between two corpus entries.
- **Trimming**: shrink new queue entries while preserving coverage, so the corpus does not bloat.
- **Corpus management**: load `corpus/`, dedupe, write newly-interesting inputs back atomically
  (temp + fsync + rename, per ARCHITECTURE.md §3), in an AFL-compatible layout so external
  tooling interoperates.

### Exit criteria
1. **V9c resolved** (exact INTERESTING_8/16/32 membership; `ARITH_MAX`, `INTERESTING_*` tables, `HAVOC_BLK_*`, `HAVOC_BLK` tier
   probabilities, AFL++ deterministic default) with sources recorded. The value tables are
   transcribed **from source, not memory**, and a unit test pins every entry.
2. **Mutators are pure and total.** Property tests over **10⁶ random inputs**: never read or
   write out of bounds (verified under ASan — this is RISK-25's guard), never produce a length
   outside configured bounds, always terminate. Zero-length and single-byte inputs handled —
   these are the classic crash cases.
3. **Reproducibility.** A fixed PRNG seed produces a byte-identical mutation sequence across
   runs, machines, and both compilers; the campaign header records the seed.
4. **Deterministic-stage completeness.** For a small input, the bit-flip stage produces exactly
   the expected number of distinct outputs — a counted assertion, not a smoke test.
5. **End-to-end bug discovery.** Against `tests/targets/buggy_parser.c` (a deliberately
   vulnerable toy parser with a documented planted stack overflow reachable only through
   several nested branches), starting from a single trivial seed, the fuzzer finds the crash in
   **under 60 seconds** on one core, in **10 consecutive runs with different PRNG seeds**. The
   ten-run requirement is the point: one lucky find proves nothing.
6. **Coverage grows.** Queue size and edge count increase monotonically over a 10-minute run
   and then plateau — the expected shape. A flat line from the start means the loop is broken.
7. **Dictionary demonstrably helps.** On a target gated behind a magic string, the run *with*
   the dictionary finds the gated branch and the run without it does not, within a fixed budget.

### What could go wrong
- **Off-by-one in block operations** is the most likely bug class here, and it manifests as a
  crash in the *fuzzer*, mid-campaign, losing hours of work. ASan on the whole suite plus
  property tests over millions of inputs is the defence (RISK-25).
- **A too-clever mutator that never explores.** If havoc always mutates near offset 0, deep
  parser states stay unreachable and the tool looks like it works while finding nothing. Exit
  criterion 6 is the detector.
- **Corpus explosion.** Without trimming, entries grow until execution slows to a crawl.
- **`rand()` / `random()`** would make campaigns non-reproducible across libc versions and
  quietly break every "reproduce this finding" workflow (RISK-26).
- **Constants recalled instead of read.** `ARITH_MAX`, the interesting tables, the havoc block
  sizes are all plausible-from-memory and wrong-in-practice (RISK-18). Transcribe, pin, test.
- **Length-change bugs** producing zero-length or absurdly large inputs, which then wedge the
  executor rather than the mutator — a confusing cross-subsystem symptom.

**Estimate.** 4–8 weeks.

---

## M4 — Crash Sanitizer / Triage

**Goal.** Turn "it crashed" into "here is a minimal input, a classification, a backtrace, and a
one-line reproduction command" — the artifact that actually goes into a disclosure report. And
never record a finding the target did not produce on its own.

### Scope
- **Layer 1 (inline):** bucket on `(signal, bucketed-map fingerprint)`; save an artifact only
  for a new bucket. No subprocess spawning.
- **ASan/UBSan report parsing as a first-class classifier input** (RISK-24): when the target is
  sanitizer-built, capture and parse the sanitizer report (error class, top frames, faulting
  access size/address) and feed it into classification and stack-hash dedup as structured
  input, not free text. The parser is tolerant: an unparsable report degrades to Layer-1-only
  classification, never to a failed run.
- **`mafl-tmin`:** minimisation via block deletion at decreasing sizes → alphabet minimisation
  → character minimisation, with an `--oracle-runs N` unanimity requirement for
  non-deterministic targets.
- **`mafl-triage`:** offline `gdb -batch` post-mortem extracting registers, backtrace, faulting
  address, faulting instruction, and a stack hash; merges Layer-1 buckets that share a stack
  hash.
- Classification: stack overflow (faulting address near the stack guard, deep recursion),
  null dereference (faulting address near 0), wild write, heap overflow / UAF / double-free
  (from the parsed ASan/UBSan report when present), divide-by-zero, illegal instruction,
  assertion failure.
- Artifact layout, one directory per unique crash:
  `id_NNN__sig_SIGSEGV__stackhash_XXXX/` containing `input.bin`, `input.min.bin`,
  `metadata.json`, `gdb.txt`, `asan.txt` (when present), and `repro.sh`.
- **Mandatory instrumented + uninstrumented re-verification**: every crash is replayed in a
  fresh `fork`/`exec` process, against **both** the instrumented build and, where available,
  an uninstrumented build of the same target, before it is recorded. A crash that needs our
  instrumentation to occur is *ours* (RISK-06/RISK-15), quarantined, never reported.
- **`UNSTABLE` artifact flag**: a crash or minimised input whose reproduction rate across N
  oracle runs is not unanimous keeps the *original* input and is flagged `UNSTABLE` in
  `metadata.json` with the observed rate, so a report states it honestly (RISK-07).

### Exit criteria
1. **V13 resolved** (`afl-tmin` pass order, block size, filler byte) with sources recorded.
2. **Correct classification** on a suite of purpose-built crashers — one target per bug class,
   each with a known ground-truth classification, including ASan-built and UBSan-built variants
   whose reports are parsed and classified from the sanitizer output. Every one classified
   correctly.
3. **Minimisation is sound and effective.** For each crasher, the minimised input still
   reproduces the *same* bucket (asserted, every time), and shrinks by ≥ 80 % on a padded input.
4. **Non-deterministic safety.** Against a target that crashes only ~50 % of the time,
   minimisation with `--oracle-runs 5` **never** emits a non-reproducing artifact; the artifact
   carries the `UNSTABLE` flag and the observed rate. This is the criterion that protects
   report credibility.
5. **Dedup is accurate in both directions (RISK-29).** 10 000 inputs hitting one bug produce
   **one** artifact directory (under-merging test), **and** two genuinely distinct bugs —
   including two that share the same faulting signal — produce **two** (over-merging test).
   Both asserted.
6. **`repro.sh` works from a clean shell**, with no environment inherited from the fuzzer.
   Tested in CI in a fresh container.
7. **Artifacts are never corrupt.** The fuzzer is `SIGKILL`ed mid-write 100 times; every
   artifact on disk is either complete and valid or absent. No truncated files. (This is the
   temp-file + `fsync` + `rename` discipline from ARCHITECTURE.md §3.)
8. **Re-verification is enforced.** A purpose-built "crash" that only occurs under
   instrumentation (triggered via a runtime-injected fault in a test build) is quarantined and
   **absent** from the findings directory. Asserted, not reviewed.
9. **Graceful GDB absence.** With GDB uninstalled, the fuzzer works and artifacts are still
   produced, minus `gdb.txt`.

### What could go wrong
- **Minimisation producing a non-reproducing input** is the worst failure in the whole project:
  it means sending a maintainer a bug report that does not reproduce, which destroys credibility
  and wastes their time. Criterion 4 exists solely for this.
- **Over-merging in dedup** hides real bugs behind one bucket; **under-merging** buries the
  interesting crash under thousands of duplicates. Both directions are tested (criterion 5).
- **Sanitizer output format drift** breaking the ASan/UBSan parser on a newer Clang. The parser
  must never be load-bearing for the run itself: parse failure degrades classification quality,
  it does not stop fuzzing.
- **Disk exhaustion** from saving every crash. Bucket-first, save-second is the fix, plus a
  configurable cap.
- **GDB parsing fragility** across versions and distributions. Treat it as best-effort,
  never let a parse failure abort a run, and pin nothing to exact output formatting.
- **Fuzzer-induced crashes** (from a bad map size, a bad argv, or a mutator bug) recorded as
  target bugs. Dual-build re-verification in a fresh process is the guard (criterion 8).

**Estimate.** 4–8 weeks.

---

## M5 — Throughput, Scheduling, and Stability

**Goal.** Go from "correct" to "fast and smart" — without giving up any of M1–M4's guarantees.
Every optimisation here is gated on a differential test against the M1 baseline.

### Scope
- **Fork server** (ARCHITECTURE.md D2 deferred work): pipe handshake on FDs 198/199, a
  **versioned protocol handshake** (a mismatch with an incompatible runtime build is a hard
  error, not a desync), **per-read deadlines** so no `ppoll` waits forever (RISK-23), deferred-init
  support, child reaping, and hard-timeout recovery when the fork server itself wedges.
- **Persistent mode**, opt-in only, with mandatory fresh-process re-verification of any crash it
  finds (ARCHITECTURE.md §1.5).
- **Queue scheduling**: `top_rated` favoured-set selection via greedy set cover, probabilistic
  skipping, per-seed scoring, and selectable power schedules.
- **MOpt-style operator selection** (stretch): probabilistic mutation-operator choice driven by
  per-operator yield statistics, behind the same deterministic-seed discipline as everything in
  M3, so the recorded-seed invariant survives.
- **`mafl-cmin`**: offline corpus minimisation.
- **Stability handling**: quantify per-target flakiness using the M2 probe and de-prioritise
  unstable edges rather than chasing them forever.
- Shared-memory test-case delivery to remove the per-input file write.
- **Parallel multi-process fuzzing over a shared corpus directory** with a documented sync
  protocol: per-process queue namespaces, periodic import of peers' new entries, and all writes
  atomic (temp + fsync + rename), so a process killed mid-sync never corrupts a peer (RISK-27).

### Exit criteria
1. **V1b, V6, V8b resolved** with sources recorded (FS_OPT_* bits; honggfuzz stack-hash count / Intel-PT viability; top_rated/scoring weights).
2. **Differential equivalence — the gate for shipping the fork server.** For **100 000 inputs**
   across ≥ 3 targets, the `fork`/`exec` executor and the fork-server executor produce
   **identical** coverage maps and **identical** statuses. Any divergence blocks the milestone;
   there is no "close enough" here. The same differential is rerun whenever the executor path
   changes, forever.
3. **Measured speedup** of ≥ 1.5× over the M1 baseline number recorded in M1 criterion 6, on a
   target with non-trivial dynamic linking.
4. **Fork-server robustness.** Injected faults — fork server killed mid-handshake, child killed
   before reporting, pipe closed unexpectedly, target `exec`ing something else, truncated or
   garbage protocol bytes — each produce a clean error and automatic recovery, never a
   deadlock. Asserted with a global test timeout so a hang fails the suite instead of
   hanging CI.
5. **Persistent-mode safety.** Every crash found in persistent mode is re-verified in a fresh
   process; unreproducible ones are quarantined separately, never reported as findings.
6. **Scheduling measurably helps — with numbers.** On a benchmark target, favoured-set
   scheduling reaches a given edge count in measurably fewer executions than round-robin, and
   each shipped power schedule is compared against round-robin in a recorded table
   (executions-to-coverage, not vibes).
7. **No leak regressions.** M1's criteria 2 and 3 (zero child and fd leaks) still hold for the
   fork-server path over 100 000 executions.
8. **Parallel sanity and integrity.** 4 processes over a shared corpus find the M3 planted bug
   faster than 1, and a post-run corpus check (checksums + replay) shows no corruption and no
   lost entries.
9. **`mafl-cmin` correctness.** Minimising a redundant corpus yields a subset whose combined
   coverage equals the original's, verified map-for-map, and never grows it.

### What could go wrong
- **Fork-server pipe desync → deadlock.** Both sides block on `read()` forever and the campaign
  silently stops making progress. Every read needs a deadline (RISK-23); the test suite needs a
  global timeout so a hang is a *failure*, not a hang.
- **Fork server inheriting a dirty state** because the target did input-dependent work before
  the fork point — silently invalidating every result after the first. Detected by criterion 2.
- **Persistent mode's carryover crashes** wasting a maintainer's time on an unreproducible
  report. Criterion 5 is the guard.
- **Scheduling starvation:** an aggressive favoured set stops exploring entirely and coverage
  plateaus early. Needs a long-run comparison, not a short one.
- **Corpus corruption under parallelism** (RISK-27) from concurrent writes to a shared
  directory. Atomic rename discipline, again — plus a replay-check in the test, because "no
  error" is not evidence of "no corruption."
- **MOpt statistics coupled to wall time** making campaigns non-replayable. Operator statistics
  must be seeded from the corpus state, not the clock, so the recorded-seed invariant survives.
- **Optimising the wrong thing.** Profile before changing anything; the map clear, the input
  write, and the `fork` are all plausible bottlenecks and intuition is unreliable here.

**Estimate.** 6–12 weeks. Highest complexity; the fork server is the hardest code in the project.

---

## M6 — Hardening, Packaging, and Real-Target Validation

**Goal.** Something a stranger can install, point at a real library, and trust with an
overnight run. This is the production-ready gate.

### Scope
- CLI and config surface: coherent flags, a config file, `--help` that explains rather than lists.
- Logging and observability: a live status screen, a **machine-readable structured stats file**
  for plotting, a structured campaign log, and crash-rate/exec-rate/stability trends.
- **Resumable campaigns**: `-i -` style resume from an existing output directory, surviving a
  restart (including a `SIGKILL`) without losing the queue, the coverage state, the recorded
  PRNG seed, or the crash buckets.
- Sandboxing review: default-deny posture on what the target can touch; document what we do and
  do **not** contain, honestly (RISK-17), and recommend running real campaigns in a container
  or VM.
- `make install`, a man page, and a tarball release.
- Documentation: quick-start, a worked example instrumenting a real library, and a
  **troubleshooting guide keyed to the M1 environment-audit warnings** — each warning text
  mapped to its symptom, cause, and fix, so a user can go from message to resolution without
  reading source.
- **Validation campaigns** against real open-source libraries, under the guardrails below.

### Exit criteria
1. **72-hour unattended run** on a real target with zero fuzzer crashes, zero leaked processes,
   zero leaked shm segments, bounded disk growth, and no corrupt artifacts.
2. **A stranger can use it.** Someone not involved in development follows the quick-start on a
   clean machine and gets a working campaign against a real library without asking questions.
   If they get stuck, the docs are wrong, not the person.
3. **Reproducibility of findings.** Every crash artifact from the validation campaigns
   reproduces from `repro.sh` on a *different* machine.
4. **Resume works.** Kill a campaign at hour 6 (including with `SIGKILL`), resume, and confirm
   the queue, coverage, and crash buckets are intact and **state-equal**, not merely "it starts
   again."
5. **Rediscovery check.** Pointed at a library version with a *known, already-public* CVE, the
   fuzzer rediscovers that bug. This is the real end-to-end proof that the whole pipeline works
   — and it is done against an already-disclosed bug specifically so that success or failure
   raises no disclosure questions.
6. **Clean static analysis.** `-Wall -Wextra -Werror`, `scan-build`/`clang-tidy`, plus ASan +
   UBSan + `valgrind` on the fuzzer itself, all clean. The tool is a security tool; it will be
   read critically.
7. **Honest containment statement (RISK-17).** The sandboxing documentation states plainly what
   is and is **not** contained — rlimits, process-group kill, `/dev/null` redirection, minimal
   child environment: yes; seccomp filters, mount/network namespaces, syscall filtering: **no**
   — and recommends a container or VM for any target the user does not fully trust. No
   overstated guarantees.

### What could go wrong
- **The fuzzer becomes the thing that crashes** at hour 40, taking the findings with it. This is
  why criterion 1 is 72 hours and not 2.
- **Docs that only work for the author.** Criterion 2 requires an actual outside person.
- **Findings that do not reproduce elsewhere** because of an unnoticed environmental dependency.
  Criterion 3 requires a different machine.
- **Resume that restores a subtly different state** (queue order, PRNG position) making
  post-resume campaigns diverge from uninterrupted ones. Test for state equality, not just
  "it starts again."
- **Scope creep into feature work** instead of hardening. M6 is about trust, not features.

**Estimate.** 8–16 weeks, overlapping with validation runs.

---

## M7 — Advanced methodologies (post-v1 candidates)

**Goal.** Stretch work, individually valuable and individually gated. **M7 is not required for
"production-ready"** — v1 ships at the end of M6. Every item here has explicit entry criteria so
it cannot be started opportunistically mid-milestone, and each slots into an existing interface
(the `coverage_source` abstraction from D3, the M5 executor interface) rather than rewriting one.

### Stretch goals and entry criteria

1. **Persistent mode beyond the N-loop.** Deeper in-process fuzzing than M5's bounded
   `__AFL_LOOP(N)`: custom harness-driven state reset between iterations, snapshot/restore of the
   heap arena, longer-lived processes. *Entry:* M5 done, including the differential gate,
   **plus** mandatory fresh-process re-verification of every finding (inherited from M5
   criterion 5 — this is never relaxed, regardless of how fast the persistent path gets). A
   finding that only reproduces inside the persistent process is a quarantine entry, not a bug
   report (RISK-13).
2. **Concolic / symbolic hybrid integration point.** An interface by which an external
   solver/hybrid engine (SymCC-style) can receive branch constraints for queue entries we cannot
   mutate past, and return candidate inputs that enter the normal corpus. Implemented **behind
   the `coverage_source` interface** as a second acquisition path. *Entry:* M6 done; a concrete
   target whose plateau is demonstrably caused by a checksum/magic compare; the D7 dependency
   policy amended in writing first, because this is the first item that pulls in real
   third-party components — the fuzzer core stays libc-only; the hybrid lives in a separate
   binary that feeds the corpus directory.
3. **Grammar-aware mutation beyond dictionaries.** Structure-aware mutators for a fixed set of
   grammars (JSON, and one binary container format), generating near-valid inputs that reach
   depths havoc never will. *Entry:* M6 done; a documented plateau (RISK-22) on a
   grammar-shaped target that dictionaries demonstrably fail to break, evidenced by M5's
   scheduling numbers. General-purpose grammar inference is explicitly out of scope.
4. **Hardware tracing (Intel PT).** Coverage acquisition via `perf_event_open` + Intel PT for
   uninstrumented or binary-only-adjacent targets, as a third `coverage_source` implementation.
   *Entry:* **V6 verification first** — the current viability of PT on the target CPUs and
   kernels is verified from source; then M5's differential test reused with PT as one side, over
   100 000 inputs, with the same zero-tolerance gate. If V6 comes back negative for the
   supported platforms, this item is dropped, documenting the finding rather than shipping a
   degraded path.
5. **Distributed fuzzing controller.** A coordinator over the M5 multi-process sync protocol:
   many machines as one logical campaign, aggregated stats, per-node resume. *Entry:* M6 done;
   the single-host parallel path proven over the 72-hour run with ≥ 8 processes; and a stated
   multi-machine use case from actual validation-campaign experience — not an anticipated one
   (RISK-21).

### What could go wrong
- **M7 cannibalising M6.** Advanced features are the fun part; hardening is the shipped part.
  The entry criteria exist precisely so none of this starts before v1 is trustworthy.
- **Persistent-state carryover silently defeating re-verification** if the re-verify path is
  ever allowed to share state with the fast path. It never is — re-verification always uses the
  M1 `fork`/`exec` reference executor.
- **A solver integration holding unreviewed third-party code** in the trust path of a security
  tool. Contained by the separate-binary-plus-corpus-directory design.

**Estimate.** Unbounded by design; each item is estimated when its entry criteria are met.

---

## Standing constraint on M6 and beyond — responsible-disclosure rules

**These are binding project rules, not guidance.** They apply to every validation and
bug-hunting activity from M6 onward. A violation is a project failure regardless of how good the
bug was.

1. **Targets are only real open-source projects**, fetched and built locally from their public
   repositories.
2. **Fuzzing runs only against locally-built binaries on machines we control.** Never against
   live, hosted, shared, or production systems. Never against a service endpoint. Never against
   anyone else's infrastructure.
3. **No fuzzing of anything we do not have the right to test.** Open source license to use the
   code is not the question; the rule is that the *binary under test is one we built, on
   hardware we own*.
4. **Every crash goes through the project's own security/disclosure process first** — the
   documented `SECURITY.md` process, security mailing list, or maintainer contact — before any
   public write-up, blog post, conference talk, tweet, or repository commit that describes the
   bug.
5. **Coordinated disclosure timelines are respected**, including a maintainer's request for more
   time. Publication happens after a fix ships or after an agreed embargo lapses, whichever the
   maintainer accepts.
6. **No exploit development beyond what the report needs.** Demonstrating impact to a maintainer
   is legitimate and often necessary for triage. Building a weaponised exploit, a reliable
   control-flow-hijack chain, or anything resembling a delivery mechanism for an undisclosed bug
   is out of scope for this project, permanently.
7. **Reports are useful, not noisy.** Minimised reproducer, affected version and commit, build
   configuration, sanitizer output, classification, and a clear impact assessment. Unminimised
   crash dumps and low-quality volume reports waste unpaid maintainers' time and are worse than
   silence.
8. **No CVE farming.** If a crash is not a genuine security-relevant memory-safety issue, it is
   reported as a plain bug or not at all. Inflating findings for credit is not the goal; the
   goal is that the library is safer afterwards.
9. **Duplicate-check before reporting.** Search existing issues, advisories, and OSS-Fuzz reports
   first. Many crashes in heavily-fuzzed libraries are already known.
10. **CVE credit is an outcome, never the objective.** If the choice is between a fast public
    write-up and a maintainer's preferred timeline, the maintainer wins.

---

## Milestone dependency graph

```
M0 scaffold ──▶ M1 executor ──▶ M2 coverage ──▶ M3 mutation ──▶ M4 triage ──▶ M5 perf ──▶ M6 hardening ──▶ production-ready
                    │                │                              │            │              │
                    │                └──── stability metric ────────┴────────────┘              │
                    │                                                                           │
                    │              (M2 instrumented-vs-uninstrumented differential) ────────────┘
                    │               feeds M4 dual-build re-verification and M5 100k-input gate
                    │
                    └──── stays the correctness reference for the whole project ────▶ M5 differential test

M6 ──▶ M7 advanced methodologies (optional branch; per-item entry criteria; NOT required for production-ready)
         ├─ persistent beyond N-loop   (entry: M5 + mandatory re-verification)
         ├─ concolic/symbolic hybrid    (entry: M6 + documented plateau; behind coverage_source)
         ├─ grammar-aware mutation      (entry: M6 + measured dictionary-insufficient plateau)
         ├─ Intel PT hardware tracing   (entry: V6 verified + M5 differential gate)
         └─ distributed controller      (entry: M6 + proven multi-process 72h run)
```

M1's `fork`/`exec` executor is never replaced — it remains the trusted reference that M5's fork
server is validated against, and the isolated path used for crash re-verification and
minimisation forever.

---

## Cross-milestone invariants

Checked in CI at **every** milestone, not just the one that introduced them. These are the
properties that make the tool trustworthy, and each is exactly the kind of thing that regresses
silently:

1. No leaked child processes.
2. No leaked file descriptors.
3. No leaked shared-memory segments.
4. No corrupt on-disk artifacts, even under `SIGKILL`.
5. Clean under ASan + UBSan.
6. No compiler warnings under `-Wall -Wextra -Werror`.
7. Builds with both GCC and Clang.
8. Every recorded crash reproduces from its own artifact.
9. **Instrumented-vs-uninstrumented crash reproducibility**: every recorded finding also
   reproduces against an uninstrumented build of the target (where one can be built); a crash
   that needs our instrumentation is quarantined, never reported. (RISK-06, RISK-15.)
10. **Campaign determinism under a fixed seed**: given the same recorded PRNG seed, target, and
    corpus, a replayed campaign produces the same mutation sequence and the same set of
    interesting inputs. (RISK-26.)
11. **Corpus integrity under parallelism**: after any multi-process run, the shared corpus
    passes a checksum + replay check — no corrupted, truncated, or silently lost entries.
    (RISK-27.)
