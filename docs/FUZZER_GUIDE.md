# Mini-AFL Advanced Fuzzer - Comprehensive Documentation

## Overview

Mini-AFL is an advanced coverage-guided fuzzer designed for finding CVEs and security vulnerabilities in open-source software. It integrates with AFL++ and LibFuzzer instrumentation while providing enterprise-grade features including:

- **Real-time Dashboard**: Web-based monitoring of fuzzing campaigns
- **CI/CD Integration**: Automated vulnerability assessment in pipelines
- **Cloud Deployment**: Support for AWS, Azure, and GCP
- **AFL++ Compatibility**: Uses trace-pc-guard instrumentation
- **LibFuzzer Integration**: Compatible with LLVM SanitizerCoverage

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Mini-AFL Fuzzer                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Coverage  │  │  Mutation   │  │   Execution Engine  │ │
│  │   Tracker   │  │   Engine    │  │   (fork/exec/wait)  │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                     │            │
│         └────────────────┼─────────────────────┘            │
│                          │                                  │
│              ┌───────────▼───────────┐                      │
│              │   Crash Triage &      │                      │
│              │   Deduplication       │                      │
│              └───────────┬───────────┘                      │
│                          │                                  │
│              ┌───────────▼───────────┐                      │
│              │   Real-time Dashboard │                      │
│              │   (Port 8080)         │                      │
│              └───────────────────────┘                      │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  CI/CD Pipe-  │   │  Cloud Deploy │   │  Vulnerability│
│  lines        │   │  (AWS/Azure/  │   │  Reports      │
│  (GitHub,     │   │   GCP)        │   │  (CVE-ready)  │
│   Jenkins)    │   │               │   │               │
└───────────────┘   └───────────────┘   └───────────────┘
```

## Quick Start

### Building

```bash
# Build the fuzzer
make

# Run tests
make test

# Build with sanitizers
make asan
```

### Basic Usage

```bash
# Simple fuzzing run
./build/mafl-run -n 1000 -t 500 -- ./target_binary @@

# With input directory
./build/mafl-run -i ./corpus -o ./output -n 10000 -- ./target_binary @@

# Start dashboard for monitoring
./build/mafl-dashboard &
```

### Accessing the Dashboard

Once started, access the dashboard at:
- **Web UI**: http://localhost:8080
- **API Stats**: http://localhost:8080/api/stats
- **API Crashes**: http://localhost:8080/api/crashes

## Features

### 1. Coverage Tracking

The fuzzer uses LLVM's SanitizerCoverage with trace-pc-guard instrumentation:

```bash
# Compile target with instrumentation
clang -fsanitize-coverage=trace-pc-guard -g target.c -o target_instrumented
```

Coverage features:
- Collision-free edge coverage using sequential guard IDs
- 64KB shared memory bitmap (AFL-compatible)
- Hit-count bucketing for efficient comparison
- Real-time coverage statistics via dashboard

### 2. Mutation Strategies

Implemented mutations (AFL-compatible):
- **Bit flips**: Single bit, two bits, four bits
- **Byte flips**: XOR with 0xFF
- **Arithmetic**: ±1 to ±35 on 8/16/32-bit values
- **Interesting values**: Common boundary values
- **Havoc**: Random combination of mutations
- **Splicing**: Combine two inputs
- **Trimming**: Reduce input size while preserving coverage

### 3. Crash Analysis

Automatic crash classification:
- SIGSEGV (segmentation fault)
- SIGABRT (assertion failure)
- SIGBUS (bus error)
- SIGFPE (floating-point exception)
- SIGILL (illegal instruction)

Each crash includes:
- Minimized reproducer
- Stack hash for deduplication
- Classification and signal info
- Reproduction script

### 4. CI/CD Integration

```bash
# In your CI pipeline
export MAFL_TARGET_BIN="./vulnerable_app"
export MAFL_DURATION=300
./cicd/ci_fuzzer.sh run

# Generate report
./cicd/ci_fuzzer.sh report
```

Supported CI systems:
- GitHub Actions
- GitLab CI
- Jenkins
- CircleCI
- Travis CI

### 5. Cloud Deployment

See `cloud/DEPLOYMENT.md` for detailed instructions on:
- AWS EC2 and EKS
- Azure VM Scale Sets and ACI
- Google Compute Engine and GKE
- Multi-cloud orchestration with Terraform

## Finding CVEs

### Best Practices

1. **Target Selection**: Choose well-maintained open-source projects with:
   - Active user base
   - Clear security disclosure process
   - History of accepting bug reports

2. **Instrumentation**: Always compile with:
   ```bash
   clang -fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard target.c
   ```

3. **Seed Corpus**: Use realistic inputs:
   ```bash
   # Download existing test files
   wget -O corpus.tar.gz https://example.com/test_files.tar.gz
   tar xzf corpus.tar.gz -C corpus/
   ```

4. **Long Runs**: Run for extended periods:
   ```bash
   # Run for 24 hours
   timeout 86400 ./build/mafl-run -i corpus -o output -- target @@
   ```

5. **Crash Verification**: Before reporting:
   - Verify crash reproduces consistently
   - Minimize the input
   - Check for duplicates in project's issue tracker
   - Review project's security policy

### CVE Report Template

```markdown
## Vulnerability Report

**Date**: [DATE]
**Product**: [PRODUCT NAME]
**Version**: [AFFECTED VERSIONS]
**Severity**: [CRITICAL/HIGH/MEDIUM/LOW]

### Description
[Brief description of the vulnerability]

### Impact
[What an attacker could achieve]

### Reproduction
1. Build the target: [BUILD INSTRUCTIONS]
2. Run with attached input: ./target < poc.bin
3. Observe: [CRASH DETAILS]

### Technical Details
- **Crash Type**: [e.g., heap-buffer-overflow]
- **Location**: [FILE:LINE or FUNCTION]
- **Root Cause**: [Explanation]

### Proof of Concept
Attached: poc.bin (minimized crashing input)

### Timeline
- [DATE]: Reported to maintainer
- [DATE]: Acknowledged
- [DATE]: Fixed
- [DATE]: Public disclosure

### Credits
Discovered using Mini-AFL fuzzer
```

## API Reference

### Dashboard API

#### GET /api/stats

Returns current fuzzing statistics:

```json
{
  "total_executions": 1000000,
  "crashes_found": 15,
  "unique_crashes": 3,
  "edges_discovered": 5432,
  "total_edges": 8765,
  "execs_per_sec": 2500.50,
  "crash_rate": 0.0015,
  "uptime_seconds": 3600,
  "last_update": 1699999999
}
```

#### GET /api/crashes

Returns list of unique crashes:

```json
{
  "crashes": [
    {
      "id": "id_000001",
      "signal": 11,
      "classification": "SIGSEGV",
      "stack_hash": "a1b2c3d4",
      "first_seen": 1699999000,
      "last_seen": 1699999900,
      "occurrences": 42,
      "minimized": true,
      "verified": true
    }
  ]
}
```

## Troubleshooting

### Common Issues

**No coverage detected:**
- Verify target was compiled with `-fsanitize-coverage=trace-pc-guard`
- Check that runtime library is linked
- Ensure shared memory is available (`/dev/shm`)

**Dashboard not starting:**
- Port 8080 may be in use
- Check firewall settings
- Verify pthread support

**High crash false positives:**
- Enable ASan/UBSan in target build
- Increase timeout value
- Check for non-deterministic behavior in target

**Low execution speed:**
- Use fork server mode (M5)
- Enable persistent mode for suitable targets
- Reduce timeout if safe

## Contributing

See `docs/CONTRIBUTING.md` for contribution guidelines.

## License

To be determined before first public release.

## Responsible Disclosure

Always follow responsible disclosure practices:
1. Report to maintainer first
2. Allow reasonable time for fix
3. Coordinate public disclosure
4. Never fuzz production systems
5. Respect project policies

For security issues in Mini-AFL itself, contact: security@example.com
