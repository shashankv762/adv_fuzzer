# Mini-AFL — build system
#
# GNU Make, deliberately (docs/ARCHITECTURE.md D7): single platform, no third-party
# dependencies, a few dozen files. CMake would add a bootstrap step and a generated-build
# indirection while solving nothing this project has.
#
# Common targets:
#   make              build everything
#   make test         build and run the full suite
#   make test-quick   same, with reduced loop counts for the dev loop
#   make asan         build and test under ASan + UBSan
#   make check        everything CI runs
#   make clean

CC      ?= cc
AR      ?= ar

BUILD   ?= build
SRCDIR   = src
INCDIR   = include
TESTDIR  = tests

WARNINGS = -Wall -Wextra -Werror \
           -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align \
           -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
           -Wredundant-decls -Wwrite-strings -Wformat=2 -Wundef \
           -Wvla -Wswitch-enum

# _GNU_SOURCE is required for pipe2, mkostemp, personality, W_EXITCODE and ppoll.
# _FORTIFY_SOURCE needs an optimisation level to have any effect, hence -O2 in the
# base flags rather than only in a release configuration.
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -I$(INCDIR) $(WARNINGS) \
           -fstack-protector-strong -fno-omit-frame-pointer
CPPFLAGS += -D_FORTIFY_SOURCE=2
LDFLAGS ?=

LIB_SRCS  = $(SRCDIR)/common.c $(SRCDIR)/exec.c $(SRCDIR)/env_audit.c
LIB_OBJS  = $(patsubst $(SRCDIR)/%.c,$(BUILD)/obj/%.o,$(LIB_SRCS))
LIB       = $(BUILD)/libmafl.a

BIN_RUN   = $(BUILD)/mafl-run

# Test targets are built WITHOUT sanitizers and WITHOUT the hardening flags, and at -O0.
# ASan installs its own SIGSEGV handler and exits with a normal exit code instead of dying
# by signal, which would invalidate every signal-classification assertion. -O0 keeps the
# deliberate faults from being optimised away. See docs/ARCHITECTURE.md §6.
TEST_TARGET     = $(BUILD)/tests/target
TEST_TARGET_SRC = $(TESTDIR)/targets/target.c
TEST_TARGET_CFLAGS = -std=c11 -D_GNU_SOURCE -O0 -g -Wall -Wextra

UNIT_SRCS = $(wildcard $(TESTDIR)/unit/test_*.c)
UNIT_BINS = $(patsubst $(TESTDIR)/unit/%.c,$(BUILD)/tests/unit_%,$(UNIT_SRCS))

INTEG_SRCS = $(wildcard $(TESTDIR)/integration/test_*.c)
INTEG_BINS = $(patsubst $(TESTDIR)/integration/%.c,$(BUILD)/tests/integ_%,$(INTEG_SRCS))

.PHONY: all clean test test-quick asan check fmt-check lint help
.DEFAULT_GOAL := all

all: $(LIB) $(BIN_RUN)

$(BUILD)/obj/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(BIN_RUN): $(BUILD)/obj/main_run.o $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_TARGET): $(TEST_TARGET_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_TARGET_CFLAGS) $< -o $@

$(BUILD)/tests/unit_%: $(TESTDIR)/unit/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LIB) -o $@ $(LDFLAGS)

$(BUILD)/tests/integ_%: $(TESTDIR)/integration/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LIB) -o $@ $(LDFLAGS)

# Every test runs under `timeout` so a hang fails the suite instead of hanging CI
# (docs/CONTRIBUTING.md §9). A deadlock is the expected failure mode of this subsystem, so
# this is load-bearing, not decoration.
TEST_TIMEOUT ?= 300

# Exported explicitly rather than relying on Make's command-line-variable export rule, so
# `make test MAFL_QUICK_TESTS=1` reliably reaches the test binaries.
export MAFL_QUICK_TESTS

test: all $(UNIT_BINS) $(INTEG_BINS) $(TEST_TARGET)
	@echo "== unit tests =="
	@set -e; for t in $(UNIT_BINS); do echo "-> $$t"; timeout $(TEST_TIMEOUT) $$t; done
	@echo "== integration tests =="
	@set -e; for t in $(INTEG_BINS); do echo "-> $$t"; timeout $(TEST_TIMEOUT) $$t $(abspath $(TEST_TARGET)); done
	@echo "== vertical slice smoke =="
	@timeout 60 $(BIN_RUN) -n 50 -t 200 -- $(abspath $(TEST_TARGET)) exit0
	@timeout 60 $(BIN_RUN) -n 20 -t 200 -- $(abspath $(TEST_TARGET)) segv
	@timeout 60 $(BIN_RUN) -n 5  -t 100 -- $(abspath $(TEST_TARGET)) hang
	@echo "ALL TESTS PASSED"

test-quick:
	@$(MAKE) test MAFL_QUICK_TESTS=1

# ASan + UBSan over the whole suite. detect_leaks is on by default on Linux; halt_on_error
# makes UBSan findings fail the build rather than merely print.
asan:
	@$(MAKE) clean
	@$(MAKE) test \
		BUILD=build-asan \
		CFLAGS="-O1 -g -std=c11 -D_GNU_SOURCE -I$(INCDIR) $(WARNINGS) -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all" \
		CPPFLAGS="" \
		LDFLAGS="-fsanitize=address,undefined"

# Banned functions (docs/CONTRIBUTING.md §3). Checked textually: cheap, and it catches the
# reintroduction that a code review misses. Excludes the test-target sources, which are
# deliberately unsafe by design.
BANNED_RE = \b(strcpy|strcat|sprintf|vsprintf|gets|alloca)[[:space:]]*\(
lint:
	@echo "== banned-function check =="
	@! grep -rInE '$(BANNED_RE)' $(SRCDIR) $(INCDIR) \
		|| (echo "ERROR: banned function used; see docs/CONTRIBUTING.md §3" && false)
	@echo "== signal-handler safety check =="
	@! grep -rInE 'on_shutdown|sig_handler' $(SRCDIR) --after-context=6 \
		| grep -E '(printf|malloc|free|fopen)[[:space:]]*\(' \
		|| (echo "ERROR: non-async-signal-safe call in a signal handler" && false)
	@echo "== no tabs in sources =="
	@! grep -rInP '\t' $(SRCDIR) $(INCDIR) $(TESTDIR) --include='*.c' --include='*.h' \
		|| (echo "ERROR: tab character in source; use 4 spaces" && false)
	@echo "lint OK"

check: lint test asan

clean:
	rm -rf build build-asan

help:
	@echo "targets: all test test-quick asan lint check clean"
