# AegisFuzz Enterprise - Build System
# 
# This Makefile builds the AegisFuzz core library and example targets.
# Supports multiple build modes: debug, release, asan, ubsan.
#
# Usage:
#   make              - Build default (release)
#   make debug        - Build with debug symbols
#   make asan         - Build with AddressSanitizer (requires clang)
#   make ubsan        - Build with UndefinedBehaviorSanitizer (requires clang)
#   make clean        - Clean build artifacts
#   make test         - Run example target in standalone mode

# Auto-detect compiler: prefer clang for sanitizers, fallback to gcc
CC := $(shell command -v clang 2>/dev/null || command -v gcc 2>/dev/null || echo gcc)
CFLAGS_COMMON = -Wall -Wextra -Werror -fPIC
CFLAGS_DEBUG = -g -O0 -DAEGIS_DEBUG
CFLAGS_RELEASE = -O2 -DNDEBUG
CFLAGS_ASAN = -g -fsanitize=address -fno-omit-frame-pointer -D_AEGIS_ASAN
CFLAGS_UBSAN = -g -fsanitize=undefined -D_AEGIS_UBSAN

LDFLAGS_COMMON = -ldl
LDFLAGS_ASAN = -fsanitize=address
LDFLAGS_UBSAN = -fsanitize=undefined

# AFL++ specific flags (use gcc if afl-clang-fast not available)
AFL_CC := $(shell command -v afl-clang-fast 2>/dev/null || command -v afl-gcc 2>/dev/null || echo gcc)
AFL_CFLAGS = -g -O2
AFL_LDFLAGS = 

# Check if compiler supports sanitizers
SANITIZER_CHECK := $(shell echo 'int main(){return 0;}' | $(CC) -fsanitize=address -x c - -o /dev/null 2>/dev/null && echo yes || echo no)

# Directories
SRC_DIR = src/core
EXAMPLES_DIR = examples
BUILD_DIR = build
OUTPUT_DIR = output

# Source files
CORE_SRCS = $(SRC_DIR)/aegis_main.c \
            $(SRC_DIR)/signal_handler.c \
            $(SRC_DIR)/coverage_hooks.c

CORE_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(CORE_SRCS))

# Library name
LIB_NAME = libaegis_core.so
LIB_STATIC = libaegis_core.a

# Example targets
EXAMPLE_TARGET = $(BUILD_DIR)/packet_parser_example

# Default target
.PHONY: all
all: release

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	mkdir -p $(OUTPUT_DIR)/crashes
	mkdir -p $(OUTPUT_DIR)/hangs
	mkdir -p $(OUTPUT_DIR)/corpus
	mkdir -p $(OUTPUT_DIR)/logs

# ============================================================================
# RELEASE BUILD
# ============================================================================
.PHONY: release
release: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_RELEASE)
release: LDFLAGS = $(LDFLAGS_COMMON)
release: $(BUILD_DIR) $(LIB_NAME) $(EXAMPLE_TARGET)
	@echo "Release build complete"

# ============================================================================
# DEBUG BUILD
# ============================================================================
.PHONY: debug
debug: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_DEBUG)
debug: LDFLAGS = $(LDFLAGS_COMMON)
debug: $(BUILD_DIR) $(LIB_NAME) $(EXAMPLE_TARGET)
	@echo "Debug build complete"

# ============================================================================
# ADDRESSSANITIZER BUILD
# ============================================================================
.PHONY: asan
ifeq ($(SANITIZER_CHECK),yes)
asan: CC = $(CC)
asan: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_ASAN)
asan: LDFLAGS = $(LDFLAGS_COMMON) $(LDFLAGS_ASAN)
asan: $(BUILD_DIR) $(LIB_NAME) $(EXAMPLE_TARGET)
	@echo "ASan build complete (using $(CC))"
else
asan:
	@echo "Warning: Compiler does not support AddressSanitizer"
	@echo "Falling back to debug build..."
	$(MAKE) debug
endif

# ============================================================================
# UNDEFINED BEHAVIOR SANITIZER BUILD
# ============================================================================
.PHONY: ubsan
ifeq ($(SANITIZER_CHECK),yes)
ubsan: CC = $(CC)
ubsan: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_UBSAN)
ubsan: LDFLAGS = $(LDFLAGS_COMMON) $(LDFLAGS_UBSAN)
ubsan: $(BUILD_DIR) $(LIB_NAME) $(EXAMPLE_TARGET)
	@echo "UBSan build complete (using $(CC))"
else
ubsan:
	@echo "Warning: Compiler does not support UndefinedBehaviorSanitizer"
	@echo "Falling back to debug build..."
	$(MAKE) debug
endif

# ============================================================================
# AFL++ BUILD
# ============================================================================
.PHONY: afl
afl: CC = $(AFL_CC)
afl: CFLAGS = $(AFL_CFLAGS)
afl: LDFLAGS = $(AFL_LDFLAGS)
afl: $(BUILD_DIR) $(EXAMPLE_TARGET)_afl
	@echo "AFL++ build complete: $(EXAMPLE_TARGET)_afl"

$(BUILD_DIR)/%_afl.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(EXAMPLE_TARGET)_afl: $(BUILD_DIR)/aegis_main_afl.o $(BUILD_DIR)/signal_handler_afl.o $(BUILD_DIR)/coverage_hooks_afl.o $(EXAMPLES_DIR)/target_example.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

# ============================================================================
# LIBRARY BUILD RULES
# ============================================================================

# Shared library
$(LIB_NAME): $(CORE_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)
	@echo "Built shared library: $@"

# Static library
$(LIB_STATIC): $(CORE_OBJS)
	ar rcs $@ $^
	@echo "Built static library: $@"

# Object file compilation
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# ============================================================================
# EXAMPLE TARGET
# ============================================================================

$(EXAMPLE_TARGET): $(CORE_OBJS) $(EXAMPLES_DIR)/target_example.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@
	@echo "Built example target: $@"

# ============================================================================
# CLEAN
# ============================================================================
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(LIB_NAME)
	rm -f $(LIB_STATIC)
	rm -rf $(OUTPUT_DIR)/crashes/*
	rm -rf $(OUTPUT_DIR)/hangs/*
	rm -rf $(OUTPUT_DIR)/logs/*
	@echo "Clean complete"

# ============================================================================
# TEST
# ============================================================================
.PHONY: test
test: release
	@echo "Running standalone test..."
	@mkdir -p $(OUTPUT_DIR)/test_corpus
	@echo -n "AEGI\x01\x00\x01\x00\x40\x00\x00\x00" > $(OUTPUT_DIR)/test_corpus/test1.bin
	@echo -n "AEGI\x02\x00\x03\x00\xFF\x00\x00\x00" > $(OUTPUT_DIR)/test_corpus/test2.bin
	$(EXAMPLE_TARGET) $(OUTPUT_DIR)/test_corpus/test1.bin
	@echo "Test complete"

# ============================================================================
# INSTALL
# ============================================================================
.PHONY: install
install: release
	install -d /usr/local/lib
	install -d /usr/local/include/aegisfuzz
	install -m 644 $(LIB_NAME) /usr/local/lib/
	install -m 644 $(LIB_STATIC) /usr/local/lib/
	install -m 644 $(SRC_DIR)/aegis_types.h /usr/local/include/aegisfuzz/
	@echo "Installation complete"

# ============================================================================
# HELP
# ============================================================================
.PHONY: help
help:
	@echo "AegisFuzz Enterprise Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build release version (default)"
	@echo "  release   - Build with optimizations"
	@echo "  debug     - Build with debug symbols"
	@echo "  asan      - Build with AddressSanitizer"
	@echo "  ubsan     - Build with UndefinedBehaviorSanitizer"
	@echo "  afl       - Build with AFL++ compiler"
	@echo "  clean     - Remove build artifacts"
	@echo "  test      - Run basic test"
	@echo "  install   - Install to /usr/local"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make asan                    # Build with ASan for vulnerability detection"
	@echo "  make afl                     # Build for AFL++ fuzzing"
	@echo "  ./build/packet_parser_example corpus/  # Run with LibFuzzer"
	@echo "  afl-fuzz -i corpus -o output -- ./build/packet_parser_example  # Run with AFL++"
