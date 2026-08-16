#!/bin/bash
# Mini-AFL CI/CD Integration Script
# 
# This script integrates the fuzzer with CI/CD pipelines for automated vulnerability assessment.
# Supports GitHub Actions, GitLab CI, Jenkins, and other CI systems.

set -e

# Configuration
MAFL_DIR="${MAFL_DIR:-$(pwd)}"
OUTPUT_DIR="${MAFL_OUTPUT_DIR:-./fuzz_output}"
CORPUS_DIR="${MAFL_CORPUS_DIR:-./corpus}"
TIMEOUT="${MAFL_TIMEOUT:-3600}"
TARGET_BIN="${MAFL_TARGET_BIN}"
FUZZ_DURATION="${MAFFUZZ_DURATION:-300}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if [ ! -f "$MAFL_DIR/build/mafl-run" ]; then
        log_error "mafl-run not found. Please run 'make' first."
        exit 1
    fi
    
    if [ -z "$TARGET_BIN" ]; then
        log_error "MAFL_TARGET_BIN environment variable not set"
        exit 1
    fi
    
    if [ ! -x "$TARGET_BIN" ]; then
        log_error "Target binary not found or not executable: $TARGET_BIN"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Setup fuzzing environment
setup_environment() {
    log_info "Setting up fuzzing environment..."
    
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR/crashes"
    mkdir -p "$OUTPUT_DIR/hangs"
    mkdir -p "$OUTPUT_DIR/corpus"
    
    # Copy seed corpus if available
    if [ -d "$CORPUS_DIR" ] && [ "$(ls -A $CORPUS_DIR 2>/dev/null)" ]; then
        cp -r "$CORPUS_DIR"/* "$OUTPUT_DIR/corpus/" 2>/dev/null || true
        log_info "Seed corpus copied"
    else
        log_warn "No seed corpus found, starting from scratch"
    fi
    
    log_info "Environment setup complete"
}

# Run the fuzzer
run_fuzzer() {
    log_info "Starting fuzzing session..."
    log_info "Target: $TARGET_BIN"
    log_info "Duration: ${FUZZ_DURATION}s"
    log_info "Output: $OUTPUT_DIR"
    
    # Export environment variables for dashboard
    export MAFL_OUTPUT_DIR="$OUTPUT_DIR"
    
    # Start dashboard in background
    if command -v python3 &> /dev/null; then
        log_info "Starting dashboard server..."
        # Dashboard would be started here if implemented in Python
        # For now, we'll just note that it's available
    fi
    
    # Run mafl-run with appropriate parameters
    # Note: This is a placeholder - actual implementation depends on mafl-run CLI
    timeout "$FUZZ_DURATION" "$MAFL_DIR/build/mafl-run" \
        -n 10000 \
        -t 1000 \
        -i "$OUTPUT_DIR/corpus" \
        -o "$OUTPUT_DIR" \
        -- "$TARGET_BIN" @@ 2>&1 | tee "$OUTPUT_DIR/fuzz.log" || true
    
    log_info "Fuzzing session complete"
}

# Analyze results
analyze_results() {
    log_info "Analyzing fuzzing results..."
    
    CRASH_COUNT=$(find "$OUTPUT_DIR/crashes" -type f 2>/dev/null | wc -l)
    HANG_COUNT=$(find "$OUTPUT_DIR/hangs" -type f 2>/dev/null | wc -l)
    
    log_info "Crashes found: $CRASH_COUNT"
    log_info "Hangs found: $HANG_COUNT"
    
    if [ "$CRASH_COUNT" -gt 0 ]; then
        log_warn "Crashes detected! Generating report..."
        generate_report "$CRASH_COUNT" "$HANG_COUNT"
        
        # Fail CI if crashes found (configurable)
        if [ "${MAFL_FAIL_ON_CRASH:-true}" = "true" ]; then
            log_error "CI failed due to crashes found"
            exit 1
        fi
    else
        log_info "No crashes found - target appears stable"
    fi
}

# Generate vulnerability report
generate_report() {
    local crash_count=$1
    local hang_count=$2
    local report_file="$OUTPUT_DIR/vulnerability_report.json"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat > "$report_file" << EOF
{
  "report_type": "vulnerability_assessment",
  "timestamp": "$timestamp",
  "target": "$TARGET_BIN",
  "fuzz_duration_seconds": $FUZZ_DURATION,
  "results": {
    "crashes_found": $crash_count,
    "hangs_found": $hang_count,
    "status": "$([ $crash_count -gt 0 ] && echo "VULNERABLE" || echo "PASS")"
  },
  "crashes": [
EOF
    
    # Add crash details
    local first=true
    for crash_dir in "$OUTPUT_DIR/crashes"/id_*; do
        if [ -d "$crash_dir" ]; then
            if [ "$first" = false ]; then
                echo "," >> "$report_file"
            fi
            first=false
            
            crash_id=$(basename "$crash_dir")
            cat >> "$report_file" << EOF
    {
      "id": "$crash_id",
      "path": "$crash_dir",
      "reproducer": "$crash_dir/input.bin"
    }
EOF
        fi
    done
    
    cat >> "$report_file" << EOF

  ],
  "ci_metadata": {
    "ci_system": "${CI_NAME:-unknown}",
    "job_url": "${CI_JOB_URL:-}",
    "commit": "${GIT_COMMIT:-${GITHUB_SHA:-}}",
    "branch": "${GIT_BRANCH:-${GITHUB_REF:-}}"
  }
}
EOF
    
    log_info "Report generated: $report_file"
    
    # Also generate human-readable summary
    local summary_file="$OUTPUT_DIR/summary.txt"
    cat > "$summary_file" << EOF
Mini-AFL Vulnerability Assessment Report
=========================================
Timestamp: $timestamp
Target: $TARGET_BIN
Duration: ${FUZZ_DURATION}s

Results:
- Crashes: $crash_count
- Hangs: $hang_count
- Status: $([ $crash_count -gt 0 ] && echo "VULNERABLE" || echo "PASS")

EOF
    
    if [ "$crash_count" -gt 0 ]; then
        echo "Crash Details:" >> "$summary_file"
        ls -la "$OUTPUT_DIR/crashes/" >> "$summary_file" 2>/dev/null || true
    fi
    
    log_info "Summary generated: $summary_file"
}

# Upload artifacts to cloud storage
upload_artifacts() {
    log_info "Uploading artifacts..."
    
    # AWS S3
    if [ -n "$AWS_BUCKET" ] && command -v aws &> /dev/null; then
        log_info "Uploading to AWS S3: $AWS_BUCKET"
        aws s3 cp "$OUTPUT_DIR" "s3://$AWS_BUCKET/fuzz-results/$(date +%Y%m%d_%H%M%S)/" --recursive || \
            log_warn "Failed to upload to S3"
    fi
    
    # Azure Blob Storage
    if [ -n "$AZURE_CONTAINER" ] && command -v az &> /dev/null; then
        log_info "Uploading to Azure Blob: $AZURE_CONTAINER"
        az storage blob upload-batch -s "$OUTPUT_DIR" -d "$AZURE_CONTAINER" || \
            log_warn "Failed to upload to Azure"
    fi
    
    # Google Cloud Storage
    if [ -n "$GCS_BUCKET" ] && command -v gsutil &> /dev/null; then
        log_info "Uploading to GCS: $GCS_BUCKET"
        gsutil -m cp -r "$OUTPUT_DIR" "gs://$GCS_BUCKET/fuzz-results/$(date +%Y%m%d_%H%M%S)/" || \
            log_warn "Failed to upload to GCS"
    fi
}

# Send notifications
send_notifications() {
    local status=$1
    
    # Slack notification
    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        local color="good"
        local text="Fuzzing passed"
        
        if [ "$status" != "PASS" ]; then
            color="danger"
            text="🚨 Vulnerabilities found!"
        fi
        
        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d "{
                \"attachments\": [{
                    \"color\": \"$color\",
                    \"title\": \"Mini-AFL Fuzzing Report\",
                    \"text\": \"$text\",
                    \"fields\": [
                        {\"title\": \"Target\", \"value\": \"$TARGET_BIN\", \"short\": true},
                        {\"title\": \"Status\", \"value\": \"$status\", \"short\": true}
                    ]
                }]
            }" 2>/dev/null || log_warn "Failed to send Slack notification"
    fi
    
    # GitHub PR comment
    if [ -n "$GITHUB_TOKEN" ] && [ -n "$GITHUB_PR_NUMBER" ]; then
        local body="## Mini-AFL Fuzzing Results\n\n"
        body+="**Target:** $TARGET_BIN\n"
        body+="**Status:** $status\n"
        
        curl -X POST \
            -H "Authorization: token $GITHUB_TOKEN" \
            -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/repos/$GITHUB_REPOSITORY/issues/$GITHUB_PR_NUMBER/comments" \
            -d "{\"body\": \"$body\"}" 2>/dev/null || log_warn "Failed to post GitHub comment"
    fi
}

# Cleanup
cleanup() {
    log_info "Cleaning up..."
    # Kill any background processes
    pkill -f "mafl-" 2>/dev/null || true
}

trap cleanup EXIT

# Main execution
main() {
    log_info "=========================================="
    log_info "Mini-AFL CI/CD Integration"
    log_info "=========================================="
    
    case "${1:-run}" in
        setup)
            check_prerequisites
            setup_environment
            ;;
        run)
            check_prerequisites
            setup_environment
            run_fuzzer
            analyze_results
            upload_artifacts
            send_notifications "$([ -f "$OUTPUT_DIR/vulnerability_report.json" ] && grep -q '"status": "PASS"' "$OUTPUT_DIR/vulnerability_report.json" && echo "PASS" || echo "FAIL")"
            ;;
        analyze)
            analyze_results
            ;;
        report)
            generate_report 0 0
            ;;
        *)
            echo "Usage: $0 {setup|run|analyze|report}"
            exit 1
            ;;
    esac
    
    log_info "=========================================="
    log_info "Mini-AFL CI/CD Complete"
    log_info "=========================================="
}

main "$@"
