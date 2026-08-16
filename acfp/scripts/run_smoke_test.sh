#!/bin/bash
# ACFP Smoke Test Script
# Verifies basic functionality of the fuzzer

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTS_DIR="$PROJECT_ROOT/tests"
OUTPUT_DIR="$PROJECT_ROOT/test_output"

echo "=========================================="
echo "ACFP Smoke Test Suite"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((pass_count++))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((fail_count++))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Setup
echo "[*] Setting up test environment..."
mkdir -p "$OUTPUT_DIR"
rm -rf "$OUTPUT_DIR"/*

# Test 1: Check fuzzer binary exists and is executable
echo ""
echo "Test 1: Fuzzer binary check"
if [ -x "$PROJECT_ROOT/bin/acfp-fuzzer" ]; then
    pass "Fuzzer binary exists and is executable"
else
    fail "Fuzzer binary not found or not executable"
    echo "    Attempting to build..."
    cd "$PROJECT_ROOT" && make all || fail "Build failed"
fi

# Test 2: Check demo target exists
echo ""
echo "Test 2: Demo target check"
if [ -f "$PROJECT_ROOT/targets/demo/bin/demo_target" ]; then
    pass "Demo target exists"
else
    warn "Demo target not found, building..."
    cd "$PROJECT_ROOT/targets/demo" && make all || fail "Demo build failed"
fi

# Test 3: Run fuzzer with help flag
echo ""
echo "Test 3: Fuzzer help output"
if "$PROJECT_ROOT/bin/acfp-fuzzer" --help | grep -q "ACFP"; then
    pass "Fuzzer help output works"
else
    fail "Fuzzer help output failed"
fi

# Test 4: Run short fuzzing campaign
echo ""
echo "Test 4: Short fuzzing campaign"
if timeout 30 "$PROJECT_ROOT/bin/acfp-fuzzer" \
    -n 500 \
    -o "$OUTPUT_DIR/fuzz_results" \
    "$PROJECT_ROOT/targets/demo/bin/demo_target" \
    "$PROJECT_ROOT/targets/seeds" 2>&1 | tee "$OUTPUT_DIR/fuzz.log"; then
    pass "Fuzzing campaign completed"
else
    warn "Fuzzing campaign had issues (may be expected)"
fi

# Test 5: Check output directory was created
echo ""
echo "Test 5: Output directory check"
if [ -d "$OUTPUT_DIR/fuzz_results" ]; then
    pass "Output directory created"
else
    warn "Output directory not created (may be expected if no crashes)"
fi

# Test 6: Verify demo target runs
echo ""
echo "Test 6: Demo target execution"
if echo "COPY:test" | "$PROJECT_ROOT/targets/demo/bin/demo_target" /dev/stdin 2>&1 | grep -q "Copied:"; then
    pass "Demo target executes correctly"
else
    fail "Demo target execution failed"
fi

# Cleanup
echo ""
echo "[*] Cleaning up test artifacts..."
# Keep output for inspection
# rm -rf "$OUTPUT_DIR"

# Summary
echo ""
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
echo -e "Passed: ${GREEN}$pass_count${NC}"
echo -e "Failed: ${RED}$fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${YELLOW}Some tests failed. Check output above.${NC}"
    exit 1
fi
