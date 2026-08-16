# Contributing to Mini-AFL — Engineering Standards

This is a security tool. It will be read critically by people deciding whether to trust it, and
it holds the only copy of its findings during a long unattended run. Both facts push in the same
direction: **boring, auditable, obviously-correct code beats clever code, every time.**

These rules are not stylistic preferences. Each one exists because violating it produces a
specific failure documented in [RISK_REGISTER.md](RISK_REGISTER.md).

---

## 1. Language and build

- **C11** (`-std=c11`), `_GNU_SOURCE` defined centrally in `include/mafl/common.h`.
- Must compile clean under **both GCC ≥ 9 and Clang ≥ 10** with `-Wall -Wextra -Werror`. This
  is a permanent gate, not an aspiration: each compiler's diagnostics catch bugs the other
  misses, Clang is the reference toolchain for the coverage instrumentation, and the
  development host compiles nothing locally (RISK-19), so the two-compiler CI matrix is the
  only signal.
- **Hardening flags are part of the default build, not a release-only configuration.**
  `CFLAGS` always carries `-fstack-protector-strong` and `-fno-omit-frame-pointer`, and
  `CPPFLAGS` always defines `_FORTIFY_SOURCE=2` — which is why the baseline optimisation
  level is `-O2` rather than something weaker: the fortification checks compile out entirely
  at `-O0`. Frame pointers stay on in every build so crash triage always has a usable
  backtrace. No build configuration may drop these. (RISK-08 — this codebase manipulates
  attacker-shaped buffers; these are cheap, always-on defences against our own memory-safety
  bugs.)
- **Test targets are always built unsanitized and at `-O0`**, in a separate compiler
  invocation from the fuzzer itself. ASan installs its own `SIGSEGV` handler and exits with a
  normal *exit code* instead of dying by signal, which would invalidate every
  signal-classification assertion — and those assertions are exactly where RISK-04's
  detector lives. `-O0` keeps the deliberate faults from being optimised away.
- **No third-party dependencies** in the fuzzer core. libc + POSIX only. Adding one requires a
  written justification in ARCHITECTURE.md §D7 and review sign-off. (Reason: every dependency is
  code that can crash *us* and lose the findings.)
- GDB is an **optional runtime tool** for offline triage, invoked as a subprocess, never linked.
- No compiler-specific extensions without a documented fallback.

---

## 2. Error handling — one convention, no exceptions

**Every fallible function returns `mafl_err_t`.** Results come back through out-parameters.

```c
/* Correct. */
mafl_err_t mafl_exec_run(mafl_exec_t *exec, const uint8_t *input, size_t len,
                         mafl_exec_result_t *out_result);

/* Wrong — a sentinel return conflates success and failure. */
int mafl_exec_run(mafl_exec_t *exec, const uint8_t *input, size_t len);
```

Rules:

- `MAFL_OK` is `0`. Every error is a **negative** enum value in `mafl_err_t`.
- **Never return a raw `errno`** across a module boundary. Capture it, log it *at the point of
  failure*, and return a `mafl_err_t`. Reason: any intervening call may clobber `errno`, so a
  value read later is not necessarily the one you think it is.
- `*_destroy()` returns `void` and **must accept `NULL`**. This makes cleanup paths trivially
  correct and removes a whole class of double-free and null-deref bugs from error handling.
- Trivial accessors may return a value directly. Nothing else may.
- **Never ignore a return value.** Fallible functions are declared
  `__attribute__((warn_unused_result))`; if a result is genuinely irrelevant, cast to `(void)`
  *with a comment explaining why*.
- Out-parameters are written **only on success**, so a caller can never read a half-written
  result after an error.

**Fuzzer failure and target failure are different things.** `MAFL_ERR_SPAWN` (we could not start
the target) is never conflated with `MAFL_STATUS_CRASH` (the target died). Reason: RISK-15 — an
infrastructure problem must never be recorded as a security finding.

---

## 3. Memory safety

This codebase manipulates arbitrary-length attacker-shaped buffers. That is exactly the shape of
code that produces off-by-ones, so the rules are strict.

**Banned outright** (enforced by a CI grep check):
`strcpy` · `strcat` · `sprintf` · `vsprintf` · `gets` · `alloca` · `atoi`/`atol` (no error
reporting) · variable-length arrays · **`rand()`/`random()` for anything PRNG-related** — the
mutation pool's deterministic seeded PRNG is used instead (RISK-26): `rand()`'s sequence varies
across libc implementations and versions, which would make campaigns irreproducible across
machines and quietly break every "reproduce this finding" workflow.

**Required:**

- Every buffer operation carries an explicit length. Pointer-only APIs are not acceptable.
- **Every** `snprintf` result is checked for truncation. Every one, no exceptions. A truncated
  path or label is a silent wrong answer — the fuzzer writes to (or verifies) the wrong file and
  nothing anywhere complains — and the class hides until a long-enough path shows up mid-campaign
  (RISK-10: a finding under a mispelled or truncated name is indistinguishable from a corrupt
  finding).
- Allocation size arithmetic must be **overflow-checked before the allocation**, not after:

  ```c
  if (count > SIZE_MAX / elem_size) return MAFL_ERR_OVERFLOW;
  void *p = malloc(count * elem_size);
  if (p == NULL) return MAFL_ERR_NOMEM;
  ```

- Every allocation's result is checked. Every one.
- Pointers are set to `NULL` immediately after being freed.
- Ownership is documented in the header for every function that takes or returns a pointer:
  who allocates, who frees, and how long it stays valid.
- Buffers holding untrusted input are `const`-qualified wherever they are not being deliberately
  mutated.

**Mutators are pure functions** of `(input bytes, RNG state)`. No globals, no I/O, no hidden
state. Reason: purity is what makes property testing over millions of random inputs possible,
and that is the only practical way to find the off-by-one before it eats a campaign at hour six.

---

## 4. Signal safety

- **No signal handlers on the execution hot path.** Timeouts use `pidfd_open` + `ppoll`. This is
  an architectural commitment (ARCHITECTURE.md §4), not a preference.
- The only handlers are `SIGINT`/`SIGTERM`, and they do exactly one thing:

  ```c
  static volatile sig_atomic_t g_shutdown_requested = 0;
  static void on_shutdown(int sig) { (void)sig; g_shutdown_requested = 1; }
  ```

- **Nothing else may appear in a handler.** No `printf`, no `malloc`, no `free`, no filesystem
  access, no locks. Only async-signal-safe operations, and in practice only the flag write.
- Install with `sigaction`, never `signal()` — the latter's semantics vary.
- The main loop polls the flag and performs shutdown in normal context.

---

## 5. Process handling

The rules that keep RISK-01, RISK-03, RISK-04, and RISK-11 from happening:

- **One place reaps children.** No other code calls `waitpid()`. Ever.
- Every descriptor is opened `O_CLOEXEC`.
- Every child gets its own process group; kills target the **group**.
- Every child gets `PR_SET_PDEATHSIG` **and** a `getppid()` re-check afterwards (the prctl has a
  documented race).
- **Our own kill intent is tracked explicitly** and consulted during status classification, so a
  timeout `SIGKILL` is never classified as a target crash.
- The spawn function has a **single exit point** with unified cleanup. Multiple returns in a
  function holding a pid and two descriptors is how leaks get written.
- Only async-signal-safe calls between `fork()` and `execve()` in the child.

---

## 5b. Fuzzing-loop invariants (M2+)

Rules for the coverage runtime, the mutation pool, and the campaign loop once M2 lands. Most of
them defend silent risks: violating one does not produce an error, it produces a fuzzer that
keeps printing plausible statistics while quietly lying.

- **Mutators are pure and total.** They accept any input — including the empty input and the
  maximum-length input — always terminate, and never produce a size outside configured bounds.
  Totality is what makes the 10⁶-input property tests possible (§9), and those tests are the
  only practical detector for the off-by-one that otherwise surfaces mid-campaign (RISK-08).
- **The coverage runtime never dereferences an unattached map.** It starts on a static dummy
  map from process start; the real shared map replaces it atomically once attached. Guard
  callbacks can fire from other modules' constructors before our attach runs, and a NULL or
  stale map pointer at that moment is a write into wild memory *inside the target* — corruption
  that presents as a real crash (RISK-06, ARCHITECTURE.md §1.3). The dummy-map rule is
  mandatory, not defensive padding.
- **Every crash is re-verified in a fresh `fork`/`exec` process before it is recorded**, and
  re-verified against an **uninstrumented build** before any disclosure: if a crash needs our
  instrumentation to happen, it is ours, not the target's (RISK-04, RISK-06, RISK-15). This is
  never skipped. It is the reason the M1 executor is permanent rather than scaffolding.
- **The campaign PRNG is deterministic, self-contained, and its seed is recorded** with every
  campaign, so the run is replayable exactly (RISK-26). `rand()`/`random()` are banned here
  (§3).
- **Timeouts are always bounded.** No unbounded `read()`, `ppoll()`, or `waitpid()` anywhere in
  the fuzzing loop or the fork-server protocol; every wait has an explicit deadline (RISK-12 —
  a deadlocked protocol participant looks like a slow campaign, not an error).

---

## 6. Filesystem persistence

**Every write that must survive a crash is atomic:**

```
write to tmpfile in the same directory
  → fsync(fd)
  → close
  → rename() into final position
  → fsync(dirfd)
```

- Metadata is written **after** the payload, so an artifact lacking metadata is recognisably
  incomplete.
- Every artifact carries a checksum of its input, verified on load.
- Reason: RISK-10 — the brief requires that the tool be trusted not to corrupt its own findings,
  and `SIGKILL` mid-write is a routine event during development.

---

## 7. Naming and layout

| Kind | Convention | Example |
| --- | --- | --- |
| Public function | `mafl_<module>_<verb>` | `mafl_exec_run` |
| Public type | `mafl_<name>_t` | `mafl_exec_result_t` |
| Public enum value | `MAFL_<SCOPE>_<NAME>` | `MAFL_STATUS_TIMEOUT` |
| Internal function | `static`, no prefix | `classify_wait_status` |
| File-scope variable | `g_` prefix, `static` | `g_shutdown_requested` |
| Macro / constant | `MAFL_` prefix, uppercase | `MAFL_MAP_SIZE` |

- Every non-`static` symbol is `mafl_`/`MAFL_` prefixed. The runtime is linked into *other
  people's programs*; a symbol collision there is a hard-to-diagnose disaster.
- Anything that can be `static` **is** `static`.
- 4-space indent, no tabs. 100-column soft limit. K&R braces. LF line endings everywhere
  (`.gitattributes` enforces this — the development host is Windows).
- One module per `.c`/`.h` pair. Headers are self-contained and include-guarded.
- Headers declare the interface; implementation details stay in the `.c` file.

---

## 8. Comments

Default to **no comment**. Well-named code documents *what* it does.

Write a comment only when the **why** is non-obvious:

```c
/* pidfd readability means terminated, not reaped — waitpid() is still required. */
/* PR_SET_PDEATHSIG races if the parent dies before this line; re-check getppid(). */
/* Saturate rather than wrap: a wrapped counter can land in a LOWER bucket than a
   colder edge, which makes coverage non-monotonic. Deliberate divergence from AFL. */
```

Each of those encodes a real constraint a reader would otherwise get wrong.

Never write: what the next line obviously does · multi-paragraph docstrings · references to the
task or PR that introduced the code ("added for the M2 work") · commented-out code.

**Every deliberate divergence from AFL's behaviour gets a comment naming it as deliberate**, so
a future reader does not "fix" it back.

---

## 9. Testing expectations

**Per milestone**, from ROADMAP.md:

| Milestone | Required tests |
| --- | --- |
| M1 | Status classification for every case; zero child leaks over 10 000 runs; zero fd leaks; timeout accuracy; process-tree kill; throughput baseline recorded |
| M2 | Ground-truth coverage vs a hand-counted CFG; determinism over 1 000 runs; no shm leaks incl. after `SIGKILL`; constructor-ordering safety; multi-module ID disjointness |
| M3 | Mutator property tests over 10⁶ inputs under ASan; PRNG reproducibility; end-to-end bug discovery in 10/10 runs with different seeds |
| M4 | Classification correctness per bug class; minimisation soundness; non-deterministic safety; dedup accuracy both directions; artifact integrity under `SIGKILL` |
| M5 | Differential equivalence vs the M1 executor over 100 000 inputs; fork-server fault injection with a global timeout; no leak regressions |
| M6 | 72-hour unattended run; third-party usability; cross-machine reproduction; clean static analysis |
| M7 (stretch goals) | Post-v1 candidates only (custom GCC-plugin instrumentation per ARCHITECTURE.md D3; seccomp/namespace isolation per §7 and RISK-17): each lands behind the M5 differential-equivalence gate and every cross-milestone invariant; nothing ships while the M1 reference executor regresses |

**Rules:**

- A bug fix comes with a **regression test that fails before the fix**. Verify it fails first —
  a test that passes against the broken code tests nothing.
- Tests assert **exact** expected values, not "something happened." `assert(status == MAFL_STATUS_TIMEOUT)`,
  never `assert(status != MAFL_STATUS_OK)`. Reason: RISK-04 is exactly the bug a loose assertion
  lets through.
- Resource-leak tests use **equality**, not tolerance. A slow leak is the failure mode being
  hunted; "roughly stable" hides it.
- Every test has a **timeout**, so a hang fails CI rather than hanging it.
- Test targets are compiled **without sanitizers**, in a separate invocation. ASan installs its
  own `SIGSEGV` handler and exits with a normal *exit code* instead of dying by signal, which
  would invalidate every signal-classification assertion.
- Tests are **deterministic**. A randomised test seeds its PRNG from a fixed constant and prints
  the seed on failure.
- No test depends on wall-clock timing beyond generous documented bounds, and none depends on
  network access.
- **Mutator property tests cover ≥ 10⁶ random inputs under ASan per mutator** (RISK-08). Zero-length
  and maximum-length inputs are explicit cases. A mutator that survives ten inputs is a mutator
  that has not been tested.
- **Campaign determinism is tested across machines and both compilers:** a fixed seed produces a
  byte-identical mutation sequence on every host and toolchain (RISK-26). This runs on the full
  GCC/Clang CI matrix precisely because libc-level differences are what would break it.
- **Instrumented-vs-uninstrumented differential test:** any behaviour counted as a finding under
  instrumentation is replayed against an uninstrumented build; a crash that vanishes without
  instrumentation is ours, and the test fails (RISK-06 backstop, §5b).
- **Dedup is tested in both directions:** thousands of inputs hitting one bug produce exactly one
  artifact, and two genuinely distinct bugs produce exactly two. Over-merging hides real bugs;
  under-merging buries them.
- **Artifact integrity under `SIGKILL` mid-write:** the fuzzer is killed repeatedly during artifact
  writes; afterwards every artifact on disk is either complete-and-valid or absent (RISK-10).

---

## 10. CI gates

Every push must pass, on both GCC and Clang:

1. Build with `-Wall -Wextra -Werror`.
2. Full test suite.
3. Full test suite under **ASan + UBSan**.
4. Banned-function grep check — including the `rand()`/`random()` ban for PRNG-related code (§3).
5. Signal-handler-safety grep check.
6. **Fuzzing-loop-invariant grep checks** (§5b): the coverage runtime's dummy-map default is
   present, and no hot-path wait lacks a deadline.
7. **`ldd`/dependency audit** on the produced binaries: the fuzzer core links libc + POSIX only.
   Any new entry fails the build and requires the §1 justification in ARCHITECTURE.md §D7 first.
8. **Campaign-determinism gate** (from M3): a fixed seed produces a byte-identical mutation
   sequence under both compilers.
9. **Fork-server differential-equivalence gate** (from M5): identical coverage maps and statuses
   vs the M1 executor over 100 000 inputs. No divergence tolerated.
10. The **cross-milestone invariants** from ROADMAP.md — no leaked children, descriptors, or shm
    segments; no corrupt artifacts; every recorded crash reproduces.

A red CI is fixed before anything else is merged. The development host is Windows without WSL
(RISK-19), so **CI is the only correctness signal** until a Linux environment exists — a broken
CI means flying blind, not merely an untidy dashboard.

---

## 11. Commits and review

- Commits are **small and single-purpose**. "M2: shm bitmap plumbing" — not "M2 work."
- The subject line is imperative and under 72 characters; the body explains *why* if it is not
  obvious.
- Never commit: crash artifacts, corpus data, build output, core dumps, anything from a real
  target. `.gitignore` covers these, but check `git status` before a broad `git add`.
- **Never commit a crash artifact for an undisclosed bug in a real target.** A public repository
  is a public disclosure — see the M6 rules in ROADMAP.md.

**Review checklist** for any change touching process handling, shared memory, or the filesystem:

- [ ] Every error path releases everything it acquired.
- [ ] Every descriptor is `O_CLOEXEC`.
- [ ] Every child is reaped on every path, including error paths.
- [ ] Every buffer operation has an explicit, checked length.
- [ ] Every allocation size is overflow-checked before allocating.
- [ ] No non-async-signal-safe call in a handler.
- [ ] Persistence is atomic (temp + `fsync` + `rename`).
- [ ] Every crash is re-verified in a fresh process before being recorded (§5b).
- [ ] The coverage runtime handles guard callbacks that fire before attach (dummy map).
- [ ] The campaign PRNG seed is recorded with the run.
- [ ] No new linked dependency without a written ARCHITECTURE.md §D7 justification.
- [ ] A test exists that fails without this change.
- [ ] Any AFL divergence is commented as deliberate.

---

## 12. Modifying the design

ARCHITECTURE.md is binding. Changing a decision means **editing that file with the new
rationale** in the same commit as the code change — not letting the code silently drift away
from the document. A design document that no longer describes the code is worse than none,
because it actively misleads the next reader.

The `[V?]` verification backlog (ARCHITECTURE.md §10) works the same way: resolving an item
means recording the confirmed value **and its source URL**, in that file, in the commit that
consumes it.

---

## 13. Working on adversarial code

Guidance for contributions to the mutation engine and the coverage runtime — the two modules
whose inputs are, by construction, hostile.

- **Assume every input byte is attacker-chosen**, because it soon will be: the corpus a mutator
  reads is the accumulated output of previous mutations, and a target's input files are
  untrusted by definition (RISK-08, RISK-17).
- **Bound every length before it is used.** A length read from input data is a claim, not a
  fact: it is validated against the actual buffer size before any indexing, copying, or
  allocation derived from it.
- **No unbounded reads.** No loop scans "until terminator" over input data; every scan has a
  hard limit derived from the mapped buffer size.
- **State the failure mode each new invariant defends.** A new rule lands naming the
  RISK_REGISTER.md entry it answers to, together with the test that fails if it regresses. An
  invariant without its threat model is one a future reader will "simplify" away — and in a
  fuzzer, the simplified-away invariants are the ones that were holding findings together.
