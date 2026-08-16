# Demo Target Makefile

CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -g -O0
LDFLAGS =

# Sanitizer flags for crash detection
SAN_CFLAGS = -fsanitize=address,undefined -g -fno-omit-frame-pointer
SAN_LDFLAGS = -fsanitize=address,undefined

SRCDIR = .
BINDIR = bin
TARGET_NAME = demo_target
TARGET = $(BINDIR)/$(TARGET_NAME)
SAN_TARGET = $(BINDIR)/$(TARGET_NAME)_san

.PHONY: all clean san install

all: dirs $(TARGET)

dirs:
	@mkdir -p $(BINDIR)

# Normal build (no sanitizers)
$(TARGET): $(SRCDIR)/$(TARGET_NAME).c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[*] Built $(TARGET)"

# Sanitizer build for crash detection
san: dirs $(SAN_TARGET)

$(SAN_TARGET): $(SRCDIR)/$(TARGET_NAME).c
	$(CC) $(CFLAGS) $(SAN_CFLAGS) -o $@ $< $(SAN_LDFLAGS)
	@echo "[*] Built sanitizer-enabled $(SAN_TARGET)"

clean:
	rm -rf $(BINDIR)
	@echo "[*] Cleaned demo target"

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/$(TARGET_NAME)

# Test targets
test-copy: $(TARGET)
	@echo "Testing stack buffer overflow..."
	echo "COPY:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | ./$(TARGET) /dev/stdin || true

test-uaf: $(TARGET)
	@echo "Testing use-after-free..."
	echo "UAF:test_data" | ./$(TARGET) /dev/stdin || true

test-double: $(TARGET)
	@echo "Testing double free..."
	echo "DOUBLE:1" | ./$(TARGET) /dev/stdin || true

test-oob: $(TARGET)
	@echo "Testing out-of-bounds read..."
	echo "OOB:100" | ./$(TARGET) /dev/stdin || true

test-null: $(TARGET)
	@echo "Testing null dereference..."
	echo "NULL:0" | ./$(TARGET) /dev/stdin || true

test-divide: $(TARGET)
	@echo "Testing divide by zero..."
	echo "DIVIDE:0" | ./$(TARGET) /dev/stdin || true

test-all: test-copy test-uaf test-double test-oob test-null test-divide
	@echo "[*] All tests completed"
