# Seed corpus

Seed inputs live here, one file per input. Contents are **not committed** (see
`.gitignore`): corpora are large, often consist of sample files that are not ours to
redistribute, and for a real target should be fetched from that project's own test suite.

## What makes a good seed corpus

It matters more than any mutator refinement. A fuzzer starting from a single zero byte will
spend its entire budget rediscovering the target's file format; one starting from real,
valid files begins at the parser's interesting code.

- **Valid** files the target accepts without error.
- **Small** — under a few KB where possible. Execution time scales with input size, and
  throughput is the whole game.
- **Diverse** — one file per distinct feature (each colour depth, each compression method,
  each optional chunk type), not fifty variations of the same photo.
- **Deduplicated** by coverage, not by content. `mafl-cmin` (M5) will do this.

Good sources: the target project's own `tests/` or `fixtures/` directory, its regression
suite, and any existing OSS-Fuzz corpus for it.

## Dictionaries

Token dictionaries go in `dicts/` (AFL-compatible format). For any structured format they
are the highest-leverage feature available: random mutation will effectively never produce
the literal `<!DOCTYPE` or a valid PNG chunk tag, so a dictionary turns an unreachable
parser branch into a routine one.

Dictionary support arrives in M3.
