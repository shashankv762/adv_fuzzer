# Mini-AFL

A lightweight, coverage-guided fuzzer for Linux x86_64, written in C11 with no dependencies
beyond libc and POSIX. In the architectural lineage of AFL / AFL++ / libFuzzer / honggfuzz.

**Status: M0 — scaffold and design.** The execution engine's vertical slice works; coverage,
mutation, and triage are not built yet. See [docs/ROADMAP.md](docs/ROADMAP.md) for what
exists and what is next.

---

## Why this exists

Building a fuzzer from scratch is the fastest way to learn how coverage feedback, process
isolation, and crash triage actually work. The end goal is concrete: point this at real
open-source C/C++ libraries, find genuine memory-safety bugs, and report them through the
projects' own disclosure processes.

That goal shapes the engineering. The tool must run unattended for hours, and it must never
produce a finding it cannot reproduce — a bug report that does not reproduce wastes an
unpaid maintainer's time and is worse than no report at all. Most of the design decisions in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) fall out of that single constraint.

## The four subsystems

| # | Subsystem | Status |
| --- | --- | --- |
| 1 | **Target execution engine** — fork/exec/waitpid, signal classification, timeouts | M1, vertical slice working |
| 2 | **Shared-memory coverage tracker** — edge bitmap fed by compile-time instrumentation | M2, not started |
| 3 | **Input mutation engine** — bit/byte/arith mutation, splicing, dictionaries | M3, not started |
| 4 | **Crash sanitizer / triage** — minimisation, classification, reproducible artifacts | M4, not started |

## Requirements

- Linux x86_64, kernel **5.10+** (`pidfd_open` needs 5.3+)
- glibc 2.31+ (musl should work; not yet tested)
- GCC 9+ or Clang 10+
- GNU Make
- Optional: GDB, for offline deep triage from M4 onward

## Build and test

```sh
make            # build
make test       # full suite (unit + integration + smoke)
make test-quick # reduced loop counts, for the dev loop
make asan       # whole suite under ASan + UBSan
make check      # everything CI runs
```

## Try the vertical slice

`mafl-run` is not the fuzzer — it has no mutation, no coverage, and no corpus. It exists to
prove the execution engine works and to make the M1 exit criteria observable by hand.

```sh
make

# 1000 clean executions, reporting throughput
./build/mafl-run -n 1000 -t 500 -- ./build/tests/target exit0

# a crashing target: classified as crash, with the signal
./build/mafl-run -n 10 -- ./build/tests/target segv

# a hanging target: classified as TIMEOUT, never as a crash
./build/mafl-run -n 5 -t 100 -- ./build/tests/target hang

# input delivered on stdin; the magic value crashes the target
printf 'CRASH' > /tmp/in
./build/mafl-run -n 1 -i /tmp/in -- ./build/tests/target echo-crash

# input delivered as a file argument; @@ is replaced by the staged path
./build/mafl-run -n 1 -i /tmp/in -f -- ./build/tests/target file-crash @@
```

That last distinction — hangs reported as `timeout` and not `crash` — is the single most
important behaviour in the current code. Getting it wrong records every hang as a finding
and makes the entire crash directory worthless. See RISK-04.

## Repository layout

```
include/mafl/   public headers
src/            fuzzer implementation
tests/
  unit/         pure-logic tests, no process spawning
  integration/  real fork/exec against purpose-built targets
  targets/      deliberately crashing/hanging test programs
tools/          offline tooling (mafl-tmin, mafl-triage — from M4)
corpus/         seed inputs (not committed)
crashes/        findings (not committed — see below)
docs/           design documents
```

## Documentation

| Document | What it covers |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Prior-art review, every v1 decision with its rationale, component diagram, and the verification backlog |
| [docs/ROADMAP.md](docs/ROADMAP.md) | M1–M6 plus the optional M7 advanced track, with concrete exit criteria, failure modes, and the standing disclosure rules |
| [docs/RISK_REGISTER.md](docs/RISK_REGISTER.md) | 31 risks with mitigations and — more importantly — how each one would be detected |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Coding style, error-handling convention, memory-safety discipline, per-milestone test expectations |

Start with ARCHITECTURE.md §2 (the decisions) and RISK_REGISTER.md's closing section (the
six risks that produce wrong findings rather than merely a broken tool).

## Responsible use

This is a bug-finding tool. From M6 onward the project operates under binding rules recorded
in [docs/ROADMAP.md](docs/ROADMAP.md):

- Only real open-source targets, **built locally, on hardware we control**. Never live,
  hosted, shared, or production systems.
- Every crash goes through the project's own security/disclosure process **before** any
  public write-up.
- Coordinated disclosure timelines are respected, including a maintainer's request for more
  time.
- No exploit development beyond what is needed to demonstrate impact in the report itself.
- Minimised, deduplicated, high-quality reports only. No CVE farming.

Crash artifacts are `.gitignore`d. A public repository is a public disclosure; do not commit
a reproducer for an undisclosed bug.

## License

Not yet chosen. Decide before the first public commit.
