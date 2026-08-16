# Mini-AFL — Architecture

Status: **Phase 0 design document.** Written before implementation. Decisions here are
binding for v1; changing one requires editing this file with the new rationale, not a
silent code drift.

Target platform: Linux x86_64, C11, no third-party runtime dependencies.

---

## 0. How to read this document

Every factual claim about prior art carries a verification marker:

| Marker | Meaning |
| --- | --- |
| `[K]` | Structural/design knowledge. Stable, unlikely to be wrong, safe to design against. |
| `[V-OK]` | **Verified against upstream source or official documentation**, with the URL recorded in [§10](#10-verification-backlog). |
| `[V?]` | A **specific constant, FD number, or protocol detail** recalled from memory and **not yet verified**. Must be re-derived from upstream before any code depends on it. |

This distinction matters. A fuzzer that hardcodes a wrong file-descriptor number or a
wrong hash shift does not fail loudly — it silently produces degraded coverage and you
lose weeks before noticing. `[V?]` items are tracked in
[§10 Verification backlog](#10-verification-backlog) and are **blocking for the milestone
that consumes them**, not for this document.

The research pass resolved most of the high-value items and **corrected two recollections
that were simply wrong**: AFL++'s deterministic-stage default (it is now *on*, disabled
with `-z`, not off-with-`-D`) and its default power schedule (`fast`, not `explore`). Both
are flagged inline as `CORRECTION`. Those two errors are the justification for this whole
marker scheme — each sounded entirely plausible, and either would have produced a quietly
worse fuzzer with no error message to point at.

None of the remaining `[V?]` items are load-bearing for M1 (the execution engine), which is
why M1 can start immediately.

---

## 1. Prior art review

### 1.1 The core loop every coverage-guided fuzzer implements

`[K]` All four reference systems (AFL, AFL++, libFuzzer, honggfuzz) are the same feedback
loop with different engineering tradeoffs:

```
pick seed from queue → mutate → execute with coverage instrumentation
                                        │
                          ┌─────────────┴──────────────┐
                    new coverage?                  crashed?
                          │                            │
                  add to queue as new seed      save + triage
```

The three things that differentiate implementations are: **how fast one iteration of that
loop is**, **how coverage is measured**, and **which seed you pick next**. Everything else
is detail.

### 1.2 Fork server vs `execve`-per-input

`[K]` The naive design is `fork()` + `execve()` + `waitpid()` per input. The cost that
dominates is *not* `fork()` — it is everything `execve()` triggers afterwards:

1. Kernel tears down the address space and builds a fresh one from the ELF.
2. `ld.so` maps every shared library the target links against.
3. `ld.so` performs symbol resolution and relocation processing — for a C++ target
   linking several libraries this is thousands of relocations.
4. libc runs its own initialisation (`__libc_start_main`, locale setup, malloc arena init).
5. Every C++ static constructor and every `__attribute__((constructor))` in every DSO runs.

`[K]` **AFL's key insight**: steps 1–5 produce *identical* state on every single run,
because the input has not been read yet. So do them **once**, then clone the
already-initialised process for each input.

`[K]` The mechanism: the instrumentation injects a small **fork server** into the target.
On first execution it stops just before `main()` (after the linker and libc are done) and
blocks on a pipe from the fuzzer. Per input, the fuzzer writes a request down that pipe;
the fork server `fork()`s; the child returns from the fork server and runs `main()` with
the new input; the fork server `waitpid()`s the child and reports the status back up a
second pipe. Every child inherits a fully-relocated, fully-constructed address space via
copy-on-write.

`[V-OK]` Verified against upstream (see §10 for sources):

- Control pipe at `FORKSRV_FD = 198`; status pipe at `FORKSRV_FD + 1 = 199`. The child
  `dup2`s the pipe ends onto these fixed descriptors before `execve`, which is how the
  injected code knows where to find them without any negotiation.
- The handshake is **4 bytes in every direction**: the fork server writes a 4-byte "hello"
  to 199; per run the fuzzer writes 4 bytes to 198 to request a fork, the fork server
  replies with the 4-byte child PID on 199, then `waitpid`s and writes the 4-byte status.
  **The byte contents are ignored** — only the length matters. A read that returns fewer
  than 4 bytes is treated as the peer having died.
- Fuzzing happens in the fork server's child, i.e. afl-fuzz's *grandchild*. The direct
  child is stopped just before `main` and only ever forks.

`[V?]` Still unverified: AFL++'s extended handshake option bits (`FS_OPT_*` — map-size
negotiation, shared-memory test-case delivery, autodict), and the published speedup range
vs `execve`-per-input (recalled as ~1.5×–2×, higher for targets with heavy dynamic linking
or static initialisers).

`[K]` **Deferred fork server** (`__AFL_INIT()` in AFL/AFL++): the target author manually
places the fork-server entry point *after* expensive one-time setup that does not depend
on the input (config parsing, codec table construction, `SSL_library_init()`-style calls).
Everything before that line then executes exactly once for the whole campaign instead of
once per input. This can be a far larger win than the fork server itself, but it is
**unsafe by construction** — if the deferred region touches the input or leaves per-run
state, every child inherits corrupted state and results become nonsense.

`[K]` **Cost of the fork server**: it is a concurrency-and-signals problem living inside
someone else's process. Failure modes include desynchronised pipes (fuzzer and fork server
disagree about whose turn it is → deadlock), the fork server dying and the fuzzer blocking
forever on `read()`, and children that are forked but never reaped. Debugging it is
materially harder than debugging a plain `fork`/`exec` loop because half the state lives
in the target.

### 1.3 Compile-time instrumentation approaches

`[K]` Three families, in increasing order of implementation risk:

**(a) `-fsanitize-coverage=trace-pc-guard` (LLVM SanitizerCoverage).**
`[V-OK]` Clang (and GCC, which implements a compatible subset) inserts a **guarded**
callback on every **edge** — roughly `if (guard_variable) __sanitizer_cov_trace_pc_guard(&guard_variable)`
— and every edge gets its own `uint32_t` guard variable. It also emits a module constructor
calling the init callback. The ABI our runtime must implement:

```c
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop); /* guards are [start, stop) */
void __sanitizer_cov_trace_pc_guard(uint32_t *guard);
```

`[V-OK]` Three properties from the LLVM documentation that directly shape our design:

1. `_init` is called from a module constructor — i.e. **before `main()`**, **at least once
   per DSO** — and **may be called more than once with the same `start`/`stop` values.**
   Our ID assignment must therefore be *idempotent per range*, or a repeat call would
   renumber guards mid-flight and silently corrupt coverage. This is a correction to my
   earlier assumption of exactly one call per module, and it is now a hard requirement on
   the M2 runtime.
2. The documented intended usage is exactly what D4 specifies: populate `[start, stop)`
   with **sequential non-zero indices** for use as offsets into our own tables.
3. **Zeroing a guard makes all further calls through it no-ops.** A free, built-in
   mechanism for retiring an edge once it is saturated.

`[V-OK]` **The critical gotcha stands**: instrumented code can execute *inside other
constructors*, i.e. before our runtime has attached its shared-memory bitmap. The callback
must therefore never dereference an unattached map — it needs a valid default target from
the moment the process starts, not from the moment we attach.

`[V-OK]` `trace-pc-guard` is **not deprecated**; it and the alternatives are all current in
the LLVM docs. The alternatives: `inline-8bit-counters` (inline counter increment instead
of a call; capture via `__sanitizer_cov_8bit_counters_init(char *start, char *end)`),
`inline-bool-flag`, and `pc-table` (requires one of the other three; supplies
`__sanitizer_cov_pcs_init` mapping each counter to a PC, with bit0 of PCFlags marking a
function-entry block).

**Note for M2**: `inline-8bit-counters` is strictly faster — an inline increment versus a
real function call per edge — and `pc-table` would give us symbolisation for free. The
reason to still start with `trace-pc-guard` is that the callback makes the edge→slot
mapping explicit and debuggable, which is worth more during bring-up than the speed.
Revisit at M5 with a measurement (D3).

`[V?]` Still to verify: whether the default `-fsanitize-coverage=edge` level splits
critical edges (so that guards are genuinely per-edge rather than effectively per-block),
exactly what `no-prune` suppresses, and the measured overhead of a call-per-guard vs AFL's
inline instrumentation on a real target.

**(b) A hand-written GCC plugin.** Walks the GIMPLE CFG and emits the coverage update
inline at each edge, exactly as `afl-gcc-fast` does. This is what AFL originally did (via
assembly rewriting in `afl-as`) and gives the best possible per-edge cost because there is
no call, no spill, and the map pointer can live in a register. `[K]` The cost is that you
are now maintaining code against GCC's internal APIs, which are explicitly unstable across
major versions and carry no compatibility guarantee.

**(c) Binary-only instrumentation.** QEMU user-mode with a patched TCG that emits coverage
on block translation (AFL's `qemu_mode`), or Frida/dynamic binary translation, or hardware
tracing (Intel PT). `[K]` Necessary for closed-source targets; typically **an order of
magnitude slower** than compile-time instrumentation, and a large integration surface.

`[V-OK]` AFL++ ships two collision-free instrumentation modes, and this directly validates
D4: **PCGUARD** (LLVM 9+) assigns IDs **sequentially during compilation** so each edge gets
a unique slot within the map size — and it is the **default in AFL++'s LLVM mode**. **LTO
mode** (`afl-clang-lto`) instruments at link time, when every compilation unit is visible,
and gives the best collision-free coverage of the two.

In other words, the approach D4 specifies — sequential IDs from the guard array instead of
the `cur ^ prev` hash — is what the current AFL++ default already does. Our design is not a
novel divergence; it is the modern consensus, and the XOR hash is the legacy path retained
for cases where a global view is unavailable.

### 1.4 Coverage representation: edges, bitmaps, collisions

`[K]` **Block coverage** ("was this basic block executed?") is strictly weaker than **edge
coverage** ("did control flow take this specific branch from A to B?"). Edge coverage
distinguishes `if (a) x(); if (b) x();` reaching `x()` by two different paths, which is
exactly the kind of distinction that drives a fuzzer into new program states. Every serious
fuzzer uses edge coverage.

`[V-OK]` The exact instrumentation, confirmed against the AFL whitepaper:

```c
cur_location = <COMPILE_TIME_RANDOM>;
shared_mem[cur_location ^ prev_location]++;
prev_location = cur_location >> 1;
```

`cur_location` is a compile-time random value (chosen randomly to keep linking of complex
projects simple and to keep the XOR output uniformly distributed).

`[V-OK]` The `>> 1` is not cosmetic. Without it, `A ^ B == B ^ A`, so the edge A→B would be
indistinguishable from B→A, and a self-loop A→A would always hash to index 0. Shifting the
*previous* location by one bit breaks the symmetry and preserves direction. It also lets
the scheme distinguish A→B→C→D→E from A→B→D→C→E, which matters because vulnerabilities
correlate with unexpected *state transitions* more than with merely reaching a new block.

`[V-OK]` In binary-only/QEMU numbering, block IDs are derived from addresses instead:
`cur_location = (block_address >> 4) ^ (block_address << 8);`

`[V-OK]` The default map size is `MAP_SIZE = 65536` (64 KiB), in both AFL and AFL++. The
rationale `[K]` is a three-way tradeoff and is what actually matters: the map must fit
comfortably in **L2 cache** (it is cleared and scanned on *every* execution, so a map that
misses cache directly caps exec/sec), it must be big enough that collisions stay rare for
realistic branch counts, and clearing it must be cheap. AFL++'s own docs frame the same
tension explicitly: too large a map means fewer inputs processed per unit time.

`[V-OK]` Collisions are real and severe at scale — a 64 KiB map holding ~50 000 edges
produces roughly **18 000 collisions**. The design consequence `[K]` is that in classic AFL
**collisions are accepted, not prevented**: a collision causes a *false negative* (new
coverage misattributed to an already-seen bucket, so a genuinely interesting input is
discarded), never a false crash. The documented hazard is that a heavily-colliding program
**appears to have saturated coverage** while many paths remain unexplored — which is
exactly RISK-14.

`[V?]` AFL's full published collision-probability table (colliding tuples vs branch count at
1k/2k/5k/10k/20k/50k branches) — **do not quote specific percentages without re-reading
`technical_details.txt`.**

`[V-OK]` The thresholds are **1, 2, 3, 4–7, 8–15, 16–31, 32–127, 128+** — eight buckets.
The implementation is a 256-entry lookup table mapping each raw counter to a **single bit**:
`0→0, 1→1, 2→2, 3→4, 4–7→8, 8–15→16, 16–31→32, 32–127→64, 128–255→128`. A bucketed byte
therefore has exactly one bit set, which makes "have I seen this bucket before?" a plain
OR/AND against the accumulated virgin map rather than integer arithmetic.

`[V-OK]` Two reasons for coarsening, both worth internalising: changes *within* a bucket are
ignored while a bucket *transition* is flagged as interesting; and without it, an input that
iterates a loop a different number of times would be saved as a new path every time — path
explosion. The stated intuition: 1→2 executions is significant, 98→99 is not.

`[V-OK]` `afl-showmap` uses a variant table mapping to friendly values 1–8 instead of single
bits, which is worth mirroring in our own diagnostic tooling.

`[K]` **Counter overflow**: an 8-bit counter wraps at 256. AFL accepts the wrap. A wrapped
counter can land back in a lower bucket, which is a source of coverage instability but is
cheaper than saturating arithmetic on the hot path.

### 1.5 Persistent mode / in-process fuzzing

`[K]` The next optimisation after the fork server is to remove the fork entirely: the
target runs a loop calling the entry function repeatedly in one long-lived process
(libFuzzer's `LLVMFuzzerTestOneInput`, AFL's `__AFL_LOOP(N)`). This is the fastest possible
design — no process creation at all, often 10×+ over fork-per-input.

`[K]` It is also the design with the worst failure modes, and they are *silent*:

- **State carryover.** Globals, cached allocations, static buffers, and library-internal
  state (OpenSSL contexts, allocator free lists) persist between iterations. A crash on
  iteration 40 000 may be reproducible **only** after the exact preceding 39 999 inputs —
  producing a crash the maintainer cannot reproduce, which is worse than finding nothing.
- **Heap-layout coupling.** A use-after-free's observable effect depends on what was
  allocated into the freed chunk, which depends on history.
- **Leak accumulation** → the process OOMs and every in-flight finding is lost.
- **One crash kills the campaign.** The crashing process *is* the fuzzer loop.

`[K]` Mitigation is the `N` in `__AFL_LOOP(N)`: recycle the process every N iterations to
bound carryover. This is a bound, not a fix.

`[K]` **Design consequence for us**: persistent mode is an *opt-in throughput optimisation
for a harness the user wrote and understands*, never a default. Any crash found in
persistent mode must be **re-verified against a fresh fork-per-input process** before it is
recorded as a finding. This is a hard rule — see [ROADMAP.md](ROADMAP.md) M5.

### 1.6 Seed scheduling

`[K]` The queue grows to thousands of entries; you cannot fuzz them all equally. AFL's
approach has two independent layers:

**Layer 1 — favoured-seed selection (a greedy set cover).** For each edge in the bitmap,
track the single queue entry that covers it most cheaply, where "cheaply" is a product of
execution time and input length (fast *and* small is better). Then walk the edges, and for
each not-yet-covered edge mark its cheapest entry as **favoured** and mark all edges that
entry covers as covered. The result is a small subset of the queue that still covers every
known edge — a greedy approximation to minimum set cover. `[V?]` Verify the exact
`top_rated[]` / `cull_queue()` mechanics and the precise cost metric.

**Layer 2 — probabilistic skipping.** Non-favoured entries are skipped with high
probability rather than removed, so the fuzzer concentrates effort on the favoured set
without permanently discarding anything. `[V?]` The exact skip probabilities — recalled as
~99% when favoured work is pending, ~95% for already-fuzzed non-favoured entries, ~75% for
not-yet-fuzzed non-favoured entries. **Verify.**

`[K]` On top of that, a per-seed **score** scales how much mutation budget an entry gets,
weighted on execution speed relative to the average, coverage count relative to the
average, how late the seed was discovered, and its depth in the discovery tree.

`[V-OK] — CORRECTION.` AFL++'s current **default power schedule is `fast`**, not `explore`.
I had recalled a switch to `explore`; that is wrong. Other schedules (`explore`, `coe`,
`lin`, `quad`, `exploit`, `rare`, `seek`, `mmopt`) are selectable with `-p`. `[V?]` The
exact current list still warrants a check against the installed build's `-h` output.

### 1.7 Mutation

`[K]` AFL splits mutation into a **deterministic** phase (exhaustive, reproducible, run
once per seed) and a **havoc** phase (random stacked mutations, unbounded).

Deterministic stages, in order `[K]`: single/double/quad bit flips → byte, word, and dword
flips → add/subtract small integers at byte, word, and dword granularity (both endiannesses)
→ overwrite with "interesting" boundary values → splice in dictionary tokens.

`[V-OK]` The constants, confirmed against `google/AFL config.h`:

- `ARITH_MAX = 35` — "maximum offset for integer addition / subtraction stages", i.e. the
  arithmetic stage tries ±1…±35 at 8-, 16-, and 32-bit widths with an 8-bit stepover.
- `HAVOC_BLK_SMALL = 32`, `HAVOC_BLK_MEDIUM = 128`, `HAVOC_BLK_LARGE = 1500`,
  `HAVOC_BLK_XL = 32768`. Each of the three smaller tiers is picked with roughly equal
  probability (smaller favoured in the first two cycles); XL is selected under 5 % of the
  time. The 1500 is near the Ethernet MTU, which matters for packet-parsing targets.
- Nearby: `SPLICE_CYCLES = 15`, `SPLICE_HAVOC = 32`, and the trimmer bounds
  (`TRIM_MIN_BYTES`, `TRIM_START_STEPS`, `TRIM_END_STEPS`).

`[V-OK]` The interesting-value tables are **cumulative**:
`static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };` — so the
32-bit stage also covers every 8- and 16-bit value. `[V?]` The exact membership of each
table is only partially confirmed (8-bit includes -128…-1, 0, 1, 16, 32, 64, 100, 127;
16-bit adds -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767; 32-bit adds
INT_MIN, INT_MAX and a couple of unusual values such as ±100663045). **Transcribe every
entry from `config.h` directly and pin it with a unit test** — these encode real
accumulated knowledge about which values trip off-by-one and sign-confusion bugs.

`[V-OK]` AFL also uses `could_be_bitflip()`, `could_be_arith()`, and `could_be_interest()`
to skip mutations an earlier deterministic stage already produced. Worth implementing: it
is pure saved work, at no cost in coverage.

`[V-OK] — CORRECTION.` I recalled that AFL++ disables deterministic mutation by default.
**That is now wrong.** Per the AFL++ changelog and man page, the reworked deterministic
stage is **enabled by default**, disabled with **`-z`**, and the old `-d`/`-D` flags are
**ignored**. Older AFL++ builds and much surviving documentation describe the opposite
(off by default, `-D` to enable), so the behaviour is version-dependent — check
`afl-fuzz -h` against the installed build rather than trusting any doc.

**Consequence for our default**: run deterministic stages by default, with a flag to skip
them. That matches current upstream and is the safer default for a fuzzer whose findings
need to be reproducible.

`[K]` **Dictionaries** are the highest-leverage feature for structured formats. Random
mutation will effectively never produce the literal `<!DOCTYPE` or a valid PNG chunk tag;
a dictionary of format tokens turns an unreachable parser branch into a routine one.

`[K]` **Splicing** takes two corpus entries and joins a prefix of one to a suffix of the
other — a cheap way to escape a local optimum that bit-level mutation cannot.

### 1.8 honggfuzz and libFuzzer — what they contribute

`[K]` **honggfuzz** is worth studying for two things: it uses **`ptrace`** to capture rich
crash state (registers, backtrace, faulting instruction) rather than only a signal number,
and it supports **hardware-assisted coverage** via `perf_event_open` (Intel PT / BTS), which
gives edge coverage on uninstrumented binaries at far lower cost than emulation. `[K]` It
also does crash deduplication by hashing the top N stack frames rather than by input.
`[V?]` The default frame count, and — importantly — **whether the Intel PT/BTS paths remain
viable on current CPUs and kernels**; hardware tracing feature availability has shifted over
several CPU generations and this must not be assumed.

`[V-OK]` **libFuzzer** has been in **maintenance-only mode since late 2022** — no new
features, but still maintained and still widely used. It is not abandoned, and "deprecated"
overstates it. Its design contribution `[K]` is the in-process persistent model and the
`LLVMFuzzerTestOneInput` harness convention, which has become the de-facto standard entry
point, including for OSS-Fuzz.

`[V-OK]` Crucially, **AFL++ is compatible with libFuzzer harnesses** — migrating is
largely a matter of swapping `clang++` for `afl-clang-fast++`. That makes the convention a
genuine interoperability standard rather than one project's API, and it settles Q3 below:
**our harness convention should match `LLVMFuzzerTestOneInput`**, because it means every
existing OSS-Fuzz harness for a real-world library becomes a target we can consume for
free. That is a significant strategic advantage for the M6 CVE-hunting phase and it costs
us nothing now.

### 1.9 Operational environment hazards

`[K]` These bite every fuzzer and are worth checking at startup with a loud, actionable
error rather than debugging later:

- **`/proc/sys/kernel/core_pattern` beginning with `|`** means the kernel pipes every core
  dump to a userspace handler (`systemd-coredump`, `apport`). At crash rates of hundreds per
  minute this adds seconds of latency per crash, so crashes get misclassified as **hangs**,
  and the disk fills with cores. This is the single most common "my fuzzer is inexplicably
  slow" cause.
- **CPU frequency governor** set to `powersave`/`ondemand` produces unstable timing, which
  poisons timeout calibration.
- **Memory limits.** `[V-OK]` AFL++ does **not** enforce a memory limit by default —
  "memory limits are not enforced by afl-fuzz by default and the system may run out of
  memory." Its guidance nonetheless *recommends setting* one via `-m`, for a reason I had
  not considered: besides preventing host OOM, a limit **surfaces missing `malloc()` failure
  handling in the target**. A memory cap is a bug-finding tool, not merely a safety belt.
  `[V?]` AFL's historical hard default (recalled as ~50 MB) and the specific
  ASan-shadow-reservation interaction are **not** confirmed by the sources checked — AFL++'s
  fuzzing guide links sanitizers to memory only as RAM/CPU *cost*, not address-space
  reservation. Treat "`RLIMIT_AS` breaks ASan" as **plausible but unverified**: it is widely
  repeated and mechanically sensible, but must be confirmed in AFL++'s sanitizer notes or by
  direct experiment before being stated as fact.
- **SysV shared memory limits** (`/proc/sys/kernel/shmmni`) and, more importantly, the fact
  that a SysV segment **survives the death of the process that created it** — a crashing
  fuzzer leaks segments until reboot or manual `ipcrm`. `[V?]` My assumption that this drove
  AFL++'s migration to `shm_open`/`mmap` is **partially contradicted**: a historical
  afl-users thread argues the *opposite* preference, that `shmget`/`shmat` is the nicer API
  because sharing across `execve` needs `shm_open` *and* `mmap`. AFL++ does carry a
  `USEMMAP` build option, default-on for macOS/Android. **Verify against
  `src/afl-sharedmem.c` before citing any rationale.** Our own choice (D4) stands regardless
  — it rests on kernel-reclaim-on-kill semantics, which we can verify directly, not on an
  appeal to AFL++'s reasoning.

### 1.10 Timeouts

`[V?]` AFL's mechanism — recalled as `setitimer(ITIMER_REAL)` + a `SIGALRM` handler that
kills the child, with `waitpid()` interrupted via `EINTR`. **Verify.** `[V?]` Its
auto-calibration heuristic — recalled as roughly 5× the measured average execution time,
rounded to a 20 ms granularity and capped at 1 s. **Verify.**

`[K]` A modern alternative exists that AFL predates: **`pidfd_open(2)`** (Linux 5.3) yields
a file descriptor that becomes readable when the process exits, so child-exit can be waited
on with `ppoll(2)` **with no signal handler at all**. This is strictly better for our
purposes: no global signal state, no `EINTR` dance across the whole program, no
async-signal-safety constraints on the timeout path, and it composes with an event loop
later. Its pitfalls `[K]`: `pidfd` readability means *terminated*, not *reaped* — you must
still `waitpid()`; and glibc did not expose a `pidfd_open()` wrapper until a relatively
recent version, so the raw `syscall(2)` form is required for portability across supported
distributions.

### 1.11 Input minimisation

`[K]` Textbook **ddmin** delta debugging works but is not what AFL ships. `afl-tmin` uses a
cheaper, format-aware-ish sequence: block deletion passes at geometrically decreasing block
sizes, then **alphabet minimisation** (replace every occurrence of a given byte value with a
fixed filler and keep the change if behaviour is preserved), then **character
minimisation** (per-byte). `[V?]` Verify the pass order, the starting block size, and the
filler byte.

`[K]` The correctness precondition is the same in every scheme and is the part that
actually breaks in practice: minimisation assumes the oracle ("does this still crash the
same way?") is **deterministic**. Heap-layout-dependent and timing-dependent crashes
violate this and minimisation will happily produce an input that does not reproduce.
Handling this requires re-running the oracle N times and requiring unanimity — which costs
N× and must be a deliberate, configurable choice.

---

## 2. Decisions for v1

Each decision states the choice, the reasoning, and — where it matters — what would make us
revisit it.

### D1. Scope: source-available targets only in v1

**Decision.** v1 supports **only targets we can rebuild ourselves** with our instrumentation
pass. No binary-only / black-box mode.

**Rationale.** Binary-only support (QEMU mode, Frida, Intel PT) is a large, separate
subsystem with its own failure modes, and it is *orthogonal* to the four subsystems this
project is actually about. Every target in the stated M6 goal — image parsers, JSON/XML
decoders, compression libraries, packet parsers — is open source and buildable from a public
repository. Binary-only support would buy zero additional targets for the actual end goal
while roughly doubling the surface area.

**Revisit if.** A specific high-value target cannot be rebuilt. Slot it as a post-M6
subsystem behind a stable `coverage_source` interface, which D3 keeps open.

### D2. Naive `fork`/`exec` in M1; fork server in M5

**Decision.** M1 ships `fork()` + `execve()` + `waitpid()` per input. The fork server is a
**deliberately deferred M5 optimisation**.

**Rationale.**

1. The fork server is a distributed protocol between two processes, one of which is under
   test and may be actively corrupting its own memory. Its bugs (pipe desync, deadlock,
   unreaped children) are the hardest class in this project. Building it first means
   debugging it *without* a known-good baseline to compare against.
2. `fork`/`exec` is a *correctness reference implementation*. Once the fork server exists,
   the acceptance test is "for the same seed, both executors produce identical coverage maps
   and identical exit statuses over N inputs." That test is only possible if the simple path
   was built and trusted first.
3. The claimed win is `[V?]` ~1.5×–2×. Real, but not the difference between a working and a
   non-working fuzzer — whereas a subtly broken fork server *is*.
4. `fork`/`exec` is required permanently regardless: crash re-verification, minimisation,
   and triage all need clean, isolated, uncontaminated single executions. It is not throwaway
   scaffolding.

**Consequence accepted.** M1–M4 run at roughly half the achievable throughput. This is fine;
throughput is an M5 concern by design.

### D3. Coverage via `trace-pc-guard`, not a hand-written GCC plugin

**Decision.** Instrumentation rides on `-fsanitize-coverage=trace-pc-guard`. We write the
runtime (`__sanitizer_cov_trace_pc_guard*`) that maps guards to bitmap slots and updates the
shared-memory map. A custom GCC plugin is an explicit **stretch goal**, not a milestone.

**Rationale.** This puts effectively all of the educational and engineering value — the
shared-memory bitmap, edge-ID assignment, hit-count bucketing, the new-coverage decision,
the attach-before-first-callback race — in *our* code, while delegating the one part with
genuinely unbounded risk (compiler internals, unstable across GCC major versions) to a
maintained, documented, stable compiler feature that both Clang and GCC implement.

The guard array also gives us something AFL's random compile-time IDs do not: guards are
**dense and sequential per module**, so we can assign collision-free IDs directly (see D4)
rather than accepting hash collisions.

**Isolation requirement.** All coverage acquisition sits behind one internal interface
(`coverage_source`) with exactly one v1 implementation. A GCC plugin, LTO-style link-time IDs,
or a future binary-only backend then becomes a second implementation rather than a rewrite.

**Revisit if.** The per-guard function call proves to be the throughput bottleneck after M5
optimisation — measure before acting; the fork server and the map-clearing cost are both
likely to dominate first.

### D4. Bitmap: 64 KiB, sequential collision-free IDs, saturating 8-bit counters

**Decision.**

- **Size**: 65536 bytes (`1 << 16`), configurable at build time via `MAFL_MAP_SIZE_POW2`,
  negotiated between fuzzer and target at startup so a mismatch is a loud error rather than
  silent corruption.
- **ID assignment**: sequential from a counter in `__sanitizer_cov_trace_pc_guard_init`,
  across all modules, so IDs are **collision-free** while the total guard count fits the map.
  If it does not fit, IDs wrap modulo the map size and we **log an explicit, prominent
  warning** stating the guard count and the resulting collision rate.
- **Counters**: 8-bit, **saturating at 255** rather than wrapping.
- **Comparison**: bucketed (1, 2, 3, 4–7, 8–15, 16–31, 32–127, 128+, `[V?]` pending
  verification) before any new-coverage decision.

**Rationale.**

- 64 KiB is L2-resident on every plausible host. The map is cleared before and scanned after
  *every* execution, so its cache behaviour is directly multiplied by the exec rate. This is
  the dominant consideration, and it is why "just make the map bigger" is wrong.
- Sequential IDs are *free* here — the guard array already gives us dense indices — and
  collisions are the single largest source of silently-lost coverage. Taking a strictly better
  option at zero cost is not premature optimisation.
- Saturating counters diverge deliberately from AFL's wrapping behaviour. Wrapping means a
  hot loop can wrap 255→0 and land in a *lower* bucket than a colder loop, producing
  non-monotonic, unstable coverage. Saturation costs one predictable compare-and-branch on the
  hot path and removes a real source of flakiness. **This is a knowing divergence from AFL and
  it must be benchmarked in M5**; if the branch measurably hurts, revisit.

**Explicitly rejected.** Hash-based IDs (`cur ^ prev`, `prev >>= 1`). It is the right design
when IDs are assigned independently at compile time with no global view — which is AFL's
constraint, not ours. We have a global view via `_init`, so accepting collisions would be
choosing a worse outcome for no reason. The scheme is documented in §1.4 because a future
binary-only backend, which *does* have AFL's constraint, will need it.

### D5. Process isolation and resource control: `rlimit`-based, not cgroups

**Decision.** Per-child, applied between `fork()` and `execve()`:

| Control | Mechanism | Default |
| --- | --- | --- |
| Core dumps | `setrlimit(RLIMIT_CORE, 0)` | **On** |
| Address space | `setrlimit(RLIMIT_AS, N)` | **Off** (opt-in) |
| Orphan prevention | `prctl(PR_SET_PDEATHSIG, SIGKILL)` | **On** |
| Process-tree kill | `setpgid(0, 0)` + `kill(-pgid, SIGKILL)` | **On** |
| ASLR | `personality(ADDR_NO_RANDOMIZE)` | **On** |
| stdio | redirect to `/dev/null` | **On** |
| PATH resolution | none — `execve` with explicit path | Always |

**Rationale, per control:**

- **`RLIMIT_CORE = 0`** is non-negotiable. At hundreds of crashes per minute, core dumps fill
  the disk and — if `core_pattern` pipes to a handler — add seconds of latency per crash,
  causing crashes to be misclassified as hangs. We also detect and warn about a piped
  `core_pattern` at startup, because the rlimit does not prevent the handler being invoked in
  all configurations.
- **`RLIMIT_AS` off by default.** `[V-OK]` This matches AFL++, which does not enforce a
  memory limit by default. Note that AFL++ nonetheless *recommends* setting one, partly
  because a cap **surfaces missing `malloc()` failure handling in the target** — a
  bug-finding benefit, not just OOM protection. We therefore expose `-m` prominently and
  document it as a recommended-but-opt-in setting.
  The commonly-cited reason for keeping it off — that ASan's multi-terabyte shadow
  reservation is counted by `RLIMIT_AS` and so makes sanitizer builds fail instantly — is
  `[V?]` **unverified** (see §1.9). It is mechanically plausible and widely repeated, but it
  is not the load-bearing argument here. The argument that *is* load-bearing: a
  virtual-address-space cap is the wrong instrument for bounding *real* memory use, and
  getting it wrong presents as a forkserver-connection failure rather than a clear error.
  `RLIMIT_DATA`, cgroups, or simply the timeout are better tools for runaway RSS. **Confirm
  or drop the ASan claim during M2** rather than letting it persist as folklore in our docs.
- **Minimal constructed environment (M1 hardening addendum).** The child receives a small,
  explicitly-constructed environment, not the fuzzer's full `environ`. The M0/M1 code inherited
  `environ` verbatim while this section claimed the opposite; the addendum closes that gap,
  adds an `inherit_env` escape hatch for targets that genuinely need `LD_LIBRARY_PATH` or
  locale variables, and makes the constructed set carry exactly one fuzzer-controlled variable
  (`MAFL_SHM_ID`, D8) so M2 drops in without an exec API break. The NOTES row in the D5 table is
  thereby completed rather than aspirational.
- **`PR_SET_PDEATHSIG`** guarantees children die with the fuzzer rather than becoming orphans.
  It has a documented race (if the parent dies between `fork()` and the `prctl()`, no signal
  is ever delivered), so the child **re-checks `getppid()`** immediately afterwards and exits
  if it changed. This is a genuine race, not defensive padding.
- **Process group per child** so a target that spawns helpers can be killed as a tree. A
  target that forks and hangs is otherwise an unkillable resource leak that accumulates over
  an unattended overnight run.
- **`ADDR_NO_RANDOMIZE`** buys reproducibility, which is the whole point of a crash artifact.
  Without it, a heap-layout-dependent crash may reproduce only occasionally, and minimisation
  (§1.11) breaks. It is best-effort: some container configurations block `personality()`, in
  which case we **warn and continue** rather than fail, since it degrades reproducibility
  rather than correctness.
- **No `PATH` search.** `execvp` semantics in a security tool that will be pointed at
  attacker-influenced directory trees is a needless foot-gun.

**Cgroups v2 rejected for v1.** It would give real (not virtual) memory accounting and clean
process-tree kill via `cgroup.kill`, but it requires either root or a pre-delegated cgroup —
an installation burden that makes the tool harder to run in exactly the CI and container
environments where it should be easiest. Revisit at M6 if `RLIMIT` proves insufficient.

### D6. Crash triage: two layers, fast inline and rich offline

**Decision.** **Layer 1 (inline, in the fuzzing loop):** classification from the signal number
plus the bucketed coverage map, with **zero** external process invocations. **Layer 2
(offline, separate tool):** `gdb -batch`-scripted post-mortem over *saved* crash artifacts
only, extracting registers, backtrace, faulting address, and the faulting instruction.

**Rationale.** The two layers have incompatible cost budgets. Layer 1 runs at fuzzing speed
and must cost microseconds; spawning GDB costs on the order of a second, which at even a
modest crash rate would collapse throughput. Layer 2 runs once per *unique* crash, offline,
where a second is free. Conflating them means either a slow fuzzer or a shallow report.

The two layers also differ in dependency posture: Layer 1 must work with nothing but libc,
so the core fuzzer has no external runtime dependency. GDB is optional tooling — its absence
degrades report quality, never the fuzzer.

**Deduplication.** Layer 1 buckets on `(signal, bucketed-coverage-map fingerprint)`. Input
hashing is wrong (a thousand inputs, one bug). Full-map hashing is too sensitive (irrelevant
early-parse differences split one bug into many buckets). Stack-hash deduplication, as
honggfuzz does `[K]`, is more precise but needs a backtrace — so it is applied in **Layer 2**,
where the backtrace already exists, to merge Layer-1 buckets that turn out to be one bug.

### D7. Language, toolchain, and baseline

| Item | Decision | Rationale |
| --- | --- | --- |
| Language | **C11** (`-std=c11` + `_GNU_SOURCE`) | Required by the brief. C11 for `_Static_assert`, `stdatomic.h`, anonymous unions. C17 is a defect-fix release only, so nothing is gained; C11 is available on older toolchains. |
| Minimum kernel | **Linux 5.10** (LTS, 2020) | Covers `pidfd_open` (5.3) and `waitid(P_PIDFD)` (5.4). 5.10 is the oldest LTS with a realistic remaining support tail; every current distribution exceeds it. |
| Minimum glibc | **2.31** (Ubuntu 20.04) | `pidfd_open` has no wrapper at this version, so we call it via `syscall(2)` with a local `__NR_pidfd_open` fallback definition. This is a real portability need, not speculation. |
| libc assumption | glibc primary; **no glibc-only APIs on the hot path** | Keeps musl/Alpine viable without a compatibility layer. |
| Build system | **GNU Make** | Justified below. |
| Dependencies | **libc + POSIX only** for the fuzzer core | Justified below. |
| Compilers | **GCC ≥ 9 and Clang ≥ 10**, both in CI | Both must work: Clang is the reference for `trace-pc-guard`, GCC is the reference for the stretch-goal plugin. |

**Make over CMake.** CMake earns its complexity on multi-platform builds, generator
selection, and third-party dependency discovery. This project is single-platform, has no
third-party dependencies, and has a dependency graph of a few dozen files. CMake would add a
bootstrap step and a generated-build-directory indirection while solving nothing we have.
Make is present on every Linux system, and a plain Makefile is directly auditable — which
matters for a security tool that others will need to trust and reproduce. Revisit only if the
target-instrumentation toolchain forces multi-configuration builds.

**No third-party dependencies (fuzzer core).** A fuzzer runs unattended for hours against
hostile input while holding the only copy of its findings; every dependency is code that can
crash *us* and lose them. libc + POSIX is sufficient for everything in the four subsystems.
Permitted exceptions, requiring explicit justification in review: **GDB** (optional, Layer-2
triage only, invoked as a subprocess and never linked), and **test-only** tooling. Anything
else needs a written case in this file.

---

### D8. Coverage runtime and shared-memory transport (extends D3/D4)

**Decision.** The M2 coverage path is `-fsanitize-coverage=trace-pc-guard` with our own
`mafl_rt` runtime implementing the documented ABI (`__sanitizer_cov_trace_pc_guard_init` /
`__sanitizer_cov_trace_pc_guard`), communicating with the fuzzer over a `shm_open` + `mmap`
segment whose name reaches the target via a dedicated `MAFL_SHM_ID` environment variable.

- A **static dummy fallback map** inside `mafl_rt` is the write target from process start; the
  real shared map replaces the pointer **atomically** once the attach handshake completes.
  Guard callbacks fire from third-party constructors before our attach, and a callback that
  dereferences an unattached pointer is a wild write *inside the target* — the exact mechanism
  behind RISK-06. The dummy map is mandatory, not defensive padding.
- IDs are assigned **sequentially** in `_init` from a per-module counter, collision-free while
  the total guard count fits the map; the `_init` call is **idempotent per `[start, stop)`
  range**, because the ABI allows it to repeat. On guard count exceeding the map, IDs wrap
  modulo the map size and we emit a loud, numbered warning.
- 64 KiB map default, configurable at build time via `MAFL_MAP_SIZE_POW2`; the fuzzer and the
  runtime negotiate the size at startup, and a mismatch is a hard error.
- Counters saturate at 255 (deliberate divergence from AFL's wrap; see D4). The map is
  `shm_unlink`ed immediately after mapping so the kernel reclaims it on `SIGKILL` — RISK-05 is
  structurally impossible, not handled.

**Rationale.** This collects the four hardest M2 facts into one binding decision: the
constructor race, the idempotent-`_init` ABI, the collision-free sequential IDs the guard array
makes free, and the kernel-reclaim property of unlinked POSIX shm. Each corresponds to a silent
failure mode (RISK-05, RISK-06, RISK-14).

**Revisit if.** `inline-8bit-counters` measurement shows the per-edge call costs more than the
fork-server and map-clearing costs combined (D3), or the target's guard count so routinely
exceeds the map that wrap-around warnings become the norm.

---

### D9. Deterministic, pure, total mutation engine

**Decision.** The M3 mutation engine is built from **pure functions of `(input bytes, PRNG
state)`** — no globals, no I/O, no hidden state — over a self-contained deterministic PRNG
(splitmix64/xoshiro256** class) whose seed is recorded per campaign and accepted as a CLI flag.

- `rand()`/`random()` are banned for anything PRNG-related (RISK-26): their sequences vary
  across libc implementations and machines, which makes campaigns irreproducible.
- Every mutator is **total**: it terminates for every input including the empty and
  maximum-length cases, and never produces a length outside configured bounds. Totality is what
  makes the M3 10⁶-inputs-under-ASan property test meaningful (RISK-25).
- Deterministic stages follow AFL's documented order — bit flips (1/2/4), byte/word/dword
  flips, arithmetic ±, interesting-value overwrites — with constants (`ARITH_MAX = 35`,
  `INTERESTING_8/16/32`, `HAVOC_BLK_* = 32/128/1500/32768`) **transcribed from upstream source
  and pinned by a unit test**, not recalled (RISK-18).
- Dictionaries use the AFL file format so existing per-format dictionaries drop in unmodified;
  splicing and trimming are part of the minimum closed loop, not stretch goals.

**Rationale.** Purity plus a recorded seed is what makes a campaign replayable and every finding
reproducible — the property the whole project's trust rests on. Totality is a correctness
constraint disguised as a testing convenience: a partial mutator is exactly where the
fuzzer-self-crash lives.

**Revisit if.** A mutation schedule that needs wall-clock or profiling feedback (e.g. a MOpt
variant) is proposed; the internal state must then be reconstructed deterministically from the
corpus and seed, never from the clock, or this decision is being silently weakened.

---

### D10. Seed scheduling: favoured set, probabilistic skipping, power schedules

**Decision.** M5 implements AFL-style scheduling in three layers: a greedy favoured-set
selection (`top_rated[]` over edges, cheapest-covering seed per edge), **probabilistic
skipping** of non-favoured entries (never a hard drop), and per-seed **energy scoring** scaling
each seed's mutation budget.

- The default power schedule is **`fast`** (matching AFL++'s current default — the CORRECTION of
  §1.6/V8a stands: it is not `explore`). `explore`, `coe`, `lin`, `quad`, `exploit`, `rare`,
  `seek`, `mmopt` are selectable but not the default.
- The exact skip probabilities and `calculate_score()` weights are resolved from V8b before
  implementation, not recalled.
- A MOpt-style per-operator yield-statistics variant is a documented stretch behind this
  interface, seeded from corpus state so the recorded-seed invariant survives (D9).

**Rationale.** The favoured set concentrates effort where coverage is cheapest to extend, which
is what separates a fuzzer that plateaus from one that does not (RISK-22). Probabilistic
skipping rather than removal keeps a fallback path open when the greedy set cover is fooled.

**Revisit if.** On a benchmark target, favoured-set scheduling does not beat round-robin in
executions-to-coverage over a long run — measured, per M5 exit criterion 6, not asserted.

---

### D11. Crash triage: sanitizer-aware classification and mandatory dual-build re-verification

**Decision.** D6's two-layer design is kept and extended in two directions.

- **Layer 1** classification consumes **parsed sanitizer reports** (ASan/UBSan error class, top
  frames, faulting access size/address) when the target is sanitizer-built, captured over a
  dedicated child-stderr side channel. The parser is tolerant: an unparsable report degrades to
  signal+bucket classification, never to a failed run. Sanitizer targets change the observable
  crash behaviour (RISK-24), so sanitizer-derived signals are flagged, never silently trusted.
- **Layer 2** dedup merges Layer-1 buckets by stack hash, but a merge is **confirmed against the
  uninstrumented faulting address and parsed sanitizer class** before collapsing: two buckets
  may share a signal and a fingerprint and still be two bugs. Over-merge is tested, not assumed
  against (RISK-29).
- **Every crash is re-verified in a fresh `fork`/`exec` process** before recording, and against
  an **uninstrumented build** before any disclosure: a crash that only reproduces with our
  instrumentation is *ours*, quarantined, never reported (RISK-06/RISK-15/RISK-28). This
  re-verification always uses the M1 executor, which is why that executor is permanent (D2).
- Minimisation (`mafl-tmin`) follows V13's verified pass order, with `--oracle-runs N`
  **unanimity** for unstable targets and an `UNSTABLE` artifact flag recording the observed
  reproduction rate when unanimity is not achieved (RISK-07).

**Rationale.** This decision operationalises the "six risks that matter most" summary: RISK-04,
RISK-06, RISK-07, RISK-15, RISK-28, and RISK-29 all close here, and every one of them produces
a wrong finding rather than a broken tool if it slips.

**Revisit if.** GDB becomes unacceptable as the Layer-2 dependency for a target environment.
Layer 2 is the replaceable layer; Layer 1 and re-verification are not.

---

### D12. Fork server: the verified handshake, hardened

**Decision.** M5 ships an AFL-lineage fork server with the **verified** wire facts of §1.2
(`FORKSRV_FD = 198` control, `FORKSRV_FD + 1 = 199` status; 4-byte messages whose contents are
ignored; fuzzing runs in the fork server's child, our grandchild), hardened for the failure
modes of §1.2.

- The protocol carries a **version field in the hello**; a version or option-set mismatch is a
  hard startup error, never a silent desync.
- **Every** pipe read has a deadline (`ppoll`); there is no unbounded blocking read anywhere
  (RISK-23, CONTRIBUTING.md §5b).
- The extended `FS_OPT_*` negotiation bits (map size, shared-memory test-case delivery,
  autodict) are implemented **only after V1b is resolved from upstream source**, never from
  recall (RISK-18).
- On any protocol violation the fork server is killed and restarted, and the event is logged
  loudly.
- Shipment is gated on the M5 differential-equivalence test over 100 000 inputs against the M1
  executor — identical coverage maps and statuses — which reruns whenever this path changes.

**Rationale.** The fork server is a concurrency-and-signals protocol inside someone else's
process, and its bugs look like "the campaign got slow" until they are deadlocks. The M1
executor exists so this one has a trusted reference to be validated against, permanently.

**Revisit if.** The measured speedup over the M1 baseline is below 1.5× on a target with
non-trivial dynamic linking — at that point the complexity is not paying for itself and the
persistent-mode/differential gate work moves.

---

### D13. Parallel fuzzing: many processes, one logical campaign

**Decision.** Parallelism is N independent fuzzer *processes* over a shared corpus directory
(the AFL model), never threads in the core. Instances stay independent; **import** of peers'
new queue entries is a periodic sync-window merge with atomic writes.

- All corpus writes are atomic (temp + `fsync` + `rename` + dir `fsync`, §3/persistence), so a
  peer reads a complete file or no file; a torn write can never become a seed (RISK-27).
- Each instance writes under its own queue and findings namespaces; imports are validated and
  checksummed where artifacts carry a checksum, and a corrupted import is quarantined.
- A stalled instance (exec/sec → 0 for a configured window) is reported as an error, not merely
  displayed, because a stalled instance is indistinguishable from a deadlock from the outside.

**Rationale.** Threads would import an entire class of data-race failure into a program whose
correctness properties are already the hardest part of the project; independent processes gain
the parallelism without that class.

**Revisit if.** Single-host parallelism reaches a saturation point measured on real campaigns,
at which point the M7 distributed-controller item — not a hot-path change — is the answer.

---

### D14. Honest containment: what we do and do not sandbox

**Decision.** v1 containment is **rlimit + process-group kill + PDEATHSIG + `/dev/null`
redirection + a minimal constructed child environment** (D5 plus the M1 `inherit_env` addendum).
We do **not** claim seccomp, mount namespaces, network isolation, or syscall filtering.

- cgroups v2 is a documented **post-v1 candidate** (real memory accounting, clean tree kill
  via `cgroup.kill`) gated on a delegation story that does not require root on the hosts we
  target.
- Seccomp/namespace hardening is an M7 candidate behind the executor interface, never implied
  to exist in v1.
- Every document that mentions containment states this division explicitly (M6 criterion
  7's honest-statement requirement).

**Rationale.** An overstated guarantee is worse than a stated limitation: a user who believes
the target is sandboxed will feed it things they would otherwise isolate. Saying plainly what is
not contained — and recommending a container or VM — is the mitigation for RISK-17 that actually
holds under scrutiny.

**Revisit if.** A specific high-value target class demands containment v1 cannot express, at
which point a scoped seccomp-bpf filter is the next candidate, explicitly as a new milestone.

---

## 3. v1 component architecture

```
                              ┌──────────────────────────────┐
                              │        CLI / config          │
                              │  argv, env, limits, paths    │
                              └──────────────┬───────────────┘
                                             │
                              ┌──────────────▼───────────────┐
                              │       Campaign driver        │  ← owns the loop,
                              │   (main fuzzing loop, stats) │    stats, shutdown,
                              └──┬────────┬────────┬─────────┘    recorded seed
                                 │        │        │
              ┌──────────────────▼───┐ ┌──▼──────────────────┐ ┌──▼────────────────────┐
              │  Scheduler / queue   │ │   Mutator           │ │  Crash manager        │
              │  favoured set,       │ │  (pure, total fns)  │ │  bucketing, dedup     │
              │  skipping, scoring,  │ │  det stages, havoc, │ │  (signal + parsed     │
              │  power schedules     │ │  splice, dictionary,│ │   ASan/UBSan report), │
              │  (D10)               │ │  trimming, seeded   │ │  artifact writing,    │
              └──────────┬───────────┘ │  PRNG  (D9)         │ │  re-verify (D11)      │
                         │             └─────────┬───────────┘ └───────────▲───────────┘
                         │  seed bytes           │ mutated bytes           │ crash + status
                         └──────────────┬────────┘                         │
                                        │                                  │
                      ┌─────────────────▼──────────────────────────────────┴─────────────┐
                      │                          Executor                                │
                      │   fork + execve + waitpid   (M1; the permanent reference)        │
                      │   fork server               (M5, same interface, D12)            │
                      │   persistent-mode backend   (M5/M7, opt-in, re-verified)         │
                      │   rlimits, pgroup, PDEATHSIG, ASLR off, pidfd timeout            │
                      │   minimal constructed env with MAFL_SHM_ID (M1 addendum)         │
                      └───────┬──────────────────┬───────────────────┬────────────────────┘
                              │ spawns           │ attaches via      │ reads back
                              │                  │ MAFL_SHM_ID       │
                   ┌──────────▼───────────┐      │      ┌────────────▼──────────────┐
                   │   Target process     │      │      │  mafl_rt coverage runtime │
                   │  (instrumented with  │──────┼─────▶│  dummy map → real shm map │
                   │   trace-pc-guard;    │ writes      │  sequential IDs, saturate │
                   │   env carries        │      │      │  bucket, new-coverage     │
                   │   MAFL_SHM_ID)       │      │      │  decision  (D4, D8)       │
                   └──────────────────────┘      │      └───────────────────────────┘
                                                 │
                                        ┌────────▼───────────────────────────┐
                                        │  Coverage source interface (D3/D8) │
                                        │  one implementation in v1; the     │
                                        │  socket the M5 fork-server and M7  │
                                        │  advanced backends plug into       │
                                        └────────────────────────────────────┘

  Offline (separate binaries, not in the hot loop):
      mafl-tmin   : input minimisation      (block del → alphabet → character)
      mafl-triage : gdb -batch post-mortem  (registers, backtrace, stack-hash dedup)
      mafl-cmin   : corpus minimisation     (greedy set cover over the queue)
```

**Data flow for one iteration (M2 onward):**

1. Campaign driver seeds the deterministic PRNG (D9), records the seed in the campaign header,
   and selects a seed and energy budget via the scheduler (D10 — the M1 slice wired the
   queue directly; M5 swaps in favoured-set scheduling behind the same interface).
2. The mutator produces a candidate; it is a pure function of (seed bytes, PRNG state).
3. Campaign driver hands the bytes to the Executor, which clears the shared bitmap, spawns the
   target (M1 `fork`/`exec` by default; M5 fork server behind the same interface), applies
   limits, waits with a deadline, reaps, and returns a status.
4. The coverage source buckets the map and decides new-coverage against the global accumulated
   map; guard callbacks in the target write to the dummy map until attach completes, then to
   the real shm map (D8).
5. If **new coverage** → scheduler/queue adds the input as a new seed. If **crash** → the
   crash manager buckets on `(signal, bucketed-map fingerprint)` enriched by any parsed
   sanitizer report, and re-verifies the crash in a fresh M1 executor run — instrumented and
   uninstrumented — before writing the artifact (D11).
6. Statistics update; loop. The recorded seed makes the whole sequence replayable bit-for-bit.

**Boundary rules** (these are what keep the subsystems independently testable):

- The Executor knows nothing about coverage or mutation. It takes bytes and an argv, returns
  a status. `[M1 testable in isolation.]`
- The Coverage source knows nothing about processes. It takes a raw map and returns a verdict.
  `[M2 testable in isolation with a synthetic map.]`
- The Mutator is a pure function of `(input bytes, RNG state)`. No I/O, no globals.
  `[M3 testable in isolation, and deterministic under a fixed seed.]`
- The Crash manager takes `(status, map, input)` and owns all filesystem writes to
  `crashes/`. `[M4 testable in isolation.]`
- **All persistence is `write` to a temp file + `fsync` + `rename` into place**, so a fuzzer
  killed mid-write never leaves a truncated crash artifact. This directly answers the "trusted
  not to corrupt its own findings" requirement in the brief.

---

## 4. Concurrency and signal model

**The fuzzer core is single-threaded.** Parallelism is achieved the way AFL does it — by
running multiple independent fuzzer *processes* over a shared corpus directory — not with
threads. This is a deliberate decision: it removes an entire class of data races from a
program whose correctness properties are already hard, and it scales just as well in practice.

**No signal handlers on the execution hot path.** Timeouts use `pidfd_open` + `ppoll`, so
child-exit detection needs no `SIGCHLD` handler and no `SIGALRM`. This is the main practical
payoff of D-choice §1.10.

The only handlers we install are for **graceful shutdown** (`SIGINT`, `SIGTERM`). They obey
strict async-signal-safety: they set a `volatile sig_atomic_t` flag and return. Nothing else.
No `malloc`, no `printf`, no filesystem access inside a handler — the loop polls the flag and
performs the actual shutdown in normal context.

`SIGCHLD` is explicitly reset to `SIG_DFL` at executor creation, because an inherited
`SIG_IGN` disposition makes `waitpid()` fail with `ECHILD` and would break child reaping in a
way that is extremely confusing to diagnose.

---

## 5. Error-handling model

One convention, applied everywhere (see [CONTRIBUTING.md](CONTRIBUTING.md)):

- Functions that can fail return `mafl_err_t` — `0` for success, negative enum for failure.
- Results are returned via out-parameters.
- The **only** exceptions are trivial accessors and `*_destroy()` functions, which return
  `void` and must accept `NULL`.
- `errno` is never propagated across a module boundary; it is captured and logged at the
  point of failure, because any intervening call may have clobbered it.
- A failure in the *fuzzer* is always distinguished from a failure in the *target*. `SPAWN_FAIL`
  (we could not start the target) and `CRASH` (the target died) are different statuses. This
  matters: a mount going read-only must not be silently recorded as a thousand crashes.

---

## 6. Testing model

| Layer | What it covers | Runs in CI |
| --- | --- | --- |
| Unit | Pure logic: mutators, bucketing, ID assignment, argv handling | Every push |
| Integration | Real `fork`/`exec` against purpose-built targets in `tests/targets/` (clean exit, each crash signal, hang, fork-and-hang, spawn failure) | Every push |
| Resource-leak | N iterations, then assert **zero** unreaped children and a **stable** open-fd count | Every push |
| Sanitizer | Whole suite under ASan + UBSan | Every push |
| Differential | Same seed → `fork`/`exec` executor and fork-server executor must produce identical maps and statuses | From M5 |
| End-to-end | Full campaign against a deliberately buggy toy program; must find the planted bug within a time bound | From M3 |

**Test targets are always built without sanitizers**, in a separate compiler invocation from
the fuzzer itself. This is not incidental: ASan installs its own `SIGSEGV` handler and exits
with a normal *exit code* instead of dying by signal, so a sanitized test target would
invalidate every signal-classification assertion.

---

## 7. What v1 deliberately does not do

Listed so that "missing" is distinguishable from "forgotten":

- Binary-only / black-box targets (D1; an M7 hardware-tracing candidate behind
  `coverage_source`, gated on V6).
- Multi-core within one **process** — N processes over a shared corpus **is** v1 scope, at M5
  (D13); it is excluded in-process and included cross-process.
- Network-protocol / stateful-sequence fuzzing.
- Grammar / structure-aware mutation beyond token dictionaries (an M7 stretch with explicit
  entry criteria).
- Symbolic or concolic execution in the v1 core (a separate-binary M7 hybrid integration point
  behind `coverage_source`).
- Non-Linux and non-x86_64 platforms.
- Persistent mode before M5, and never as a default (§1.5) — in scope from M5 behind the
  re-verification gate, never as a campaign default.
- **False containment claims.** v1 ships no seccomp, mount-namespace, or network-namespace
  hardening, and says so plainly; see D14.

---

## 8. Open questions to resolve before the milestone that needs them

| # | Question | Needed by |
| --- | --- | --- |
| Q1 | Input delivery default: file argument (`@@`) or stdin? Both are needed; which is the default, and does shared-memory delivery (AFL++ style) come at M5? | M2 |
| Q2 | Corpus on-disk format: AFL-compatible flat directory (interoperable with existing tooling), or an indexed format with metadata? | M3 |
| Q3 | ~~Do we adopt `LLVMFuzzerTestOneInput` as the harness convention?~~ **Resolved: yes.** AFL++ is harness-compatible with libFuzzer, making the convention an interoperability standard — every existing OSS-Fuzz harness becomes a usable target. | ~~M5~~ |
| Q4 | Stability metric: do we detect and quantify non-deterministic targets (AFL's "stability" percentage) in M2, or defer to M5? | M2 |

---

## 9. Assumptions recorded

- **Development host is Windows without WSL**; Linux compilation and execution are performed
  in CI (`ubuntu-latest`) and/or a Linux VM. The scaffold is therefore written to be
  CI-verified rather than locally-verified, and CI is a hard gate from the first commit rather
  than an afterthought. Installing WSL2 or a Linux VM locally is strongly recommended before
  M2 — iterating on `fork`/`shm`/signal code through CI alone will be painfully slow.
- No root access is assumed. Anything requiring root (cgroup delegation, `core_pattern`
  modification, governor changes) is **detected and reported as advice**, never required.

---

## 10. Verification backlog

Status as of the Phase 0 research pass. Resolved items carry their source; open items are
**blocking for the milestone that consumes them** and must be settled by reading upstream
source or official documentation, not by recall.

### Resolved

| # | Item | Confirmed value | Source |
| --- | --- | --- | --- |
| V1a | Fork-server FDs and handshake | Control `198`, status `199`; 4 bytes each way (hello / request / child PID / status); **contents ignored, length is what matters**; fuzzing happens in the *grandchild* | [AFL++ under the hood](https://blog.ritsec.club/posts/afl-under-hood/), [AFL reading notes](https://mem2019.github.io/jekyll/update/2019/08/09/AFL-Fuzzer-Notes-1.html) |
| V2a | `MAP_SIZE` | `65536` (64 KiB), AFL and AFL++ | [AFL technical details](https://lcamtuf.coredump.cx/afl/technical_details.txt), [AFL++ coverage](https://www.mintlify.com/AFLplusplus/AFLplusplus/concepts/coverage) |
| V2b | Edge hash and the `>>1` | `shared_mem[cur ^ prev]++; prev = cur >> 1;` — the shift preserves direction (A→B ≠ B→A), kills the self-loop degeneracy, and distinguishes reordered traces | [AFL technical details](https://lcamtuf.coredump.cx/afl/technical_details.txt) |
| V2c | Collision severity | ~18 000 collisions for ~50 000 edges in a 64 KiB map; a heavily-colliding target **looks saturated while paths remain unexplored** | [AFL++ coverage](https://www.mintlify.com/AFLplusplus/AFLplusplus/concepts/coverage) |
| V4 | AFL++ collision-free modes | **PCGUARD** (LLVM 9+) assigns sequential IDs at compile time and is the **LLVM-mode default**; **LTO mode** is best-of-breed. Validates D4. | [AFL++ coverage](https://www.mintlify.com/AFLplusplus/AFLplusplus/concepts/coverage) |
| V5 | `trace-pc-guard` ABI and status | Guarded callback **per edge**, one `uint32_t` guard each; `_init` runs pre-`main`, **≥once per DSO and may repeat with the same range**; sequential non-zero IDs are the intended usage; **zeroing a guard disables it**; not deprecated — `inline-8bit-counters` / `inline-bool-flag` / `pc-table` are the faster alternatives | [Clang SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html) |
| V7 | libFuzzer status | **Maintenance-only since late 2022**, still maintained; AFL++ is **harness-compatible** with it | [Testing Handbook](https://appsec.guide/docs/fuzzing/c-cpp/libfuzzer/), [AFL++ fuzzing in depth](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md) |
| V8a | AFL++ default power schedule | **`fast`** (not `explore` — my recollection was wrong) | [afl-fuzz approach](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/afl-fuzz_approach.md) |
| V9a | `ARITH_MAX`, `HAVOC_BLK_*` | `35`; `32 / 128 / 1500 / 32768`; also `SPLICE_CYCLES 15`, `SPLICE_HAVOC 32` | [google/AFL config.h](https://github.com/google/AFL/blob/master/config.h) |
| V9b | Deterministic-stage default | **CORRECTION**: current AFL++ runs deterministic stages **by default**, disabled with **`-z`**; `-d`/`-D` are **ignored**. Version-dependent — older builds are the opposite. | [AFL++ changelog](https://aflplus.plus/docs/changelog/), [afl-fuzz(8)](https://manpages.debian.org/unstable/afl++/afl-fuzz.8.en.html) |

### Open

| # | Item | Source to consult | Blocking |
| --- | --- | --- | --- |
| V1b | AFL++ `FS_OPT_*` extended handshake bits; published fork-server speedup range | AFL++ `src/afl-forkserver.c` | M5 |
| V2d | Full collision-probability table (per branch count) | AFL `technical_details.txt` | M2 |
| V3 | Hit-count bucket thresholds | AFL `afl-fuzz.c` (`classify_counts`) | **M2** |
| V5b | Whether `edge` splits critical edges; what `no-prune` suppresses; call-vs-inline overhead | Clang docs + measurement | **M2** |
| V6 | honggfuzz stack-hash frame count; current viability of Intel PT / BTS | honggfuzz source + docs | M5 |
| V8b | `top_rated[]`/`cull_queue()` mechanics; skip probabilities; `calculate_score()` weights | AFL `afl-fuzz.c` | M5 |
| V9c | Exact `INTERESTING_8/16/32` membership (transcribe and pin with a test) | AFL `config.h` | **M3** |
| V10 | AFL/AFL++ default memory limit and the reason for the change | AFL++ `docs/`, `config.h` | M2 |
| V11 | SysV `shmmni` default; rationale for the `shm_open` migration | `proc(5)`, AFL++ source | M2 |
| V12 | AFL timeout mechanism and auto-calibration heuristic | AFL `afl-fuzz.c` | M2 |
| V13 | `afl-tmin` pass order, starting block size, filler byte | AFL `afl-tmin.c` | M4 |
| V14 | MOpt per-operator selection probabilities and the pilot/vs-exploitation split | AFL++ `src/afl-fuzz-mopt.c` | M5 (stretch) |
| V15 | AFL++ `FS_OPT_*` numeric bit values and ordering guarantees beyond "contents ignored, length matters" | AFL++ `include/forkserver.h`, `src/afl-forkserver.c` | M5 (D12) |
| V16 | Confirmed `RLIMIT_AS` behaviour against ASan/Terabyte shadow on our supported glibc versions (resolves the §1.9 folklore question one way or the other) | AFL++ sanitizer notes + direct experiment on the CI matrix | M2 |
| V17 | AFL bitmap dependency-weights / edge-relationship metadata, if any, that we should mirror in the M2 runtime | AFL / AFL++ source | M2 |

---

## Appendix A — Decision log

| ID | Decision | Alternative rejected | Primary reason |
| --- | --- | --- | --- |
| D1 | Source-available targets only | Binary-only via QEMU | Zero additional targets for the stated goal; doubles surface area |
| D2 | `fork`/`exec` first, fork server at M5 | Fork server from day one | Need a trusted baseline to validate the hard concurrent path against |
| D3 | `trace-pc-guard` runtime | Hand-written GCC plugin | Unbounded compiler-internals risk for no additional learning on the parts that matter |
| D4 | Sequential collision-free IDs, saturating counters | AFL's `cur ^ prev` hash, wrapping counters | Guard array gives a global view AFL lacked; collisions and counter wrap are avoidable losses |
| D5 | `rlimit` + `pgroup` + `PDEATHSIG`, minimal constructed child env | cgroups v2, inherited `environ` | Needs root or delegation; a full inherited env leaks the fuzzer's context into a hostile-input process |
| D6 | Two-layer triage (signal inline, GDB offline) | GDB inline | Incompatible cost budgets; keeps the core dependency-free |
| D7 | C11, GNU Make, libc-only | C17, CMake, helper libraries | Nothing gained; each dependency is code that can lose our findings |
| D8 | shm_open+mmap+immediate unlink; dummy map; sequential ids; saturate | SysV shm; attached-map-first; hash ids; wrapping counters | Kernel reclaims on SIGKILL; constructor-race safety; collisions are pure silent loss |
| D9 | Pure/total mutators over a seeded, self-contained PRNG | libc `rand()`; I/O-doing, stateful mutators | Replayable campaigns and 10⁶-input property tests are the only workable correctness story |
| D10 | Favoured set + probabilistic skipping + `fast` default schedule | Round-robin; `explore`-default recall | RISK-22 plateaus; V8b correction changes the default; measured comparison gates any change |
| D11 | ASan/UBSan-aware Layer 1, confirmed Layer-2 merges, dual-build re-verify | Signal-number-only dedup; single-build verify | Sanitizer signals invert classification (RISK-24); over-merge hides bugs (RISK-29); instrumentation artifacts fake findings (RISK-28) |
| D12 | Verified 198/199 handshake, versioned, deadlines on every read | Recalled constants; unbounded reads | RISK-18 and RISK-23; permanent M1 differential gate forbids ad-hoc shipping |
| D13 | N independent processes over a shared atomic corpus | Threads in the core | Imports a whole data-race class into our hardest correctness problem |
| D14 | Honest non-sandbox containment statement | Claiming seccomp/namespaces v1 lacks | An overstated guarantee is worse than a stated limitation (RISK-17) |

---

## 11. Evolution map: M0 → M6 (+ M7)

Where each decision lands and what consumes it.

| Milestone | Lands | Consumes / built on |
| --- | --- | --- |
| M0 | Scaffold, CI, docs (this file, ROADMAP, RISK_REGISTER, CONTRIBUTING) | — |
| M1 | Executor: D2, D5 (+ `inherit_env` / `MAFL_SHM_ID` hardening addendum), pidfd timeouts, RISK-01/03/04/11 guarantees | M0 |
| M2 | Coverage runtime: D3, D4, D8 (bitmap, runtime, `mafl-cc`, stability probe) | M1, V2/V3/V5/V10/V11/V16/V17 |
| M3 | Mutation engine: D9 (pure/total, seeded PRNG, dictionaries, splicing, trimming) | M2, V9 |
| M4 | Triage: D6 + D11 (sanitizer-aware classification, minimisation, dual-build re-verification) | M1–M3, V13 |
| M5 | Throughput/scheduling: D2 fork-server side of D12, D10 scheduling, D13 parallelism | M1 reference, M2–M4; gates everything above on differential equivalence |
| M6 | Hardening + real-target validation: D14 containment statement, resume, packaging, the 10 disclosure rules | M1–M5 |
| M7 * | Optional advanced methodologies (persistent beyond N, concolic hybrid, grammar-aware, Intel PT, distributed controller); each has explicit entry criteria, and **none is required for "production-ready"** | M6, explicit entry criteria per item |

*M7 items land behind the `coverage_source` and executor interfaces D3/D14 keep open, so they are
insertions rather than rewrites.
