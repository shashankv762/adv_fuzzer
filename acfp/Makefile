# ACFP Makefile - Main Build System

.PHONY: all clean test install docs

# Compiler settings
CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -g -O2 -I$(INCDIR)
LDFLAGS = 

# Directories
SRCDIR = src
INCDIR = include
BINDIR = bin
OBJDIR = obj

# Source files
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Main target
TARGET = $(BINDIR)/acfp-fuzzer

# Default build
all: dirs $(TARGET)

# Create directories
dirs:
	@mkdir -p $(BINDIR) $(OBJDIR)

# Link final binary
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "[*] Built $(TARGET)"

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# AFL++ build
afl-build:
	@if command -v afl-clang-fast >/dev/null 2>&1; then \
		echo "[*] Building with AFL++ compiler..."; \
		make CC=afl-clang-fast CFLAGS="-std=c11 -Wall -Wextra -g -O2 -I$(INCDIR)"; \
	else \
		echo "[!] AFL++ compiler not found. Install AFL++ first."; \
		exit 1; \
	fi

# Sanitizer builds
asan-build:
	make CFLAGS="$(CFLAGS) -fsanitize=address -g" LDFLAGS="$(LDFLAGS) -fsanitize=address"

ubsan-build:
	make CFLAGS="$(CFLAGS) -fsanitize=undefined -g" LDFLAGS="$(LDFLAGS) -fsanitize=undefined"

full-san-build:
	make CFLAGS="$(CFLAGS) -fsanitize=address,undefined -g" LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined"

# Clean build artifacts
clean:
	rm -rf $(OBJDIR) $(BINDIR)
	@echo "[*] Cleaned build artifacts"

# Install to system
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "[*] Installed to /usr/local/bin/"

# Run tests
test: $(TARGET)
	@echo "[*] Running smoke tests..."
	@./scripts/run_smoke_test.sh

# Build demo target
demo: 
	$(MAKE) -C targets/demo

# Run demo fuzzing
run-demo: $(TARGET) demo
	@echo "[*] Running fuzzer against demo target..."
	./$(TARGET) -n 1000 ./targets/demo/bin/demo_target ./targets/seeds

# Generate documentation
docs:
	@echo "[*] Generating documentation..."
	doxygen docs/Doxyfile 2>/dev/null || echo "Doxygen not installed, skipping..."

# Help
help:
	@echo "ACFP Build System"
	@echo "================="
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build the fuzzer (default)"
	@echo "  clean         - Remove build artifacts"
	@echo "  test          - Run smoke tests"
	@echo "  install       - Install to /usr/local/bin"
	@echo "  afl-build     - Build with AFL++ compiler"
	@echo "  asan-build    - Build with AddressSanitizer"
	@echo "  ubsan-build   - Build with UndefinedBehaviorSanitizer"
	@echo "  full-san-build- Build with both ASan and UBSan"
	@echo "  demo          - Build demo vulnerable target"
	@echo "  run-demo      - Run fuzzer against demo target"
	@echo "  docs          - Generate documentation"
	@echo "  help          - Show this help message"
