# CVE-FINDER: Advanced Fuzzing Framework

## Overview
CVE-FINDER is a production-grade C fuzzing harness designed for vulnerability discovery in open-source software. It provides seamless integration with **AFL++** and **LibFuzzer**, automated crash triage, and CI/CD compatibility.

## Features
- **Dual Engine Support**: Works with AFL++ (coverage-guided) and LibFuzzer (in-process).
- **Automated Crash Triage**: Captures stack traces, signal info, and input samples on crash.
- **CI/CD Integration**: `--ci` mode exits immediately on crash for pipeline failures.
- **Cloud Ready**: Designed for deployment on AWS, Azure, and GCP (stateless design).
- **Real-time Logging**: Structured logs with severity levels.

## Directory Structure
```
/workspace
├── cve_finder_core.h       # Core header with API definitions
├── cve_finder_core.c       # Core implementation (init, signals, logging)
├── fuzz_target_example.c   # Example target harness
├── Makefile                # Build system
└── README_CVE_FINDER.md    # This file
```

## Quick Start

### 1. Build Standalone (for testing)
```bash
make standalone
./fuzz_standalone < test_input.bin
```

### 2. Build for AFL++
```bash
make afl
# Run with AFL++
afl-fuzz -i seeds -o output ./fuzz_afl @@
```

### 3. Build for LibFuzzer
```bash
make libfuzzer
./fuzz_libfuzzer seeds/
```

## Usage in Bug Bounty / CVE Research

1. **Identify Target**: Choose a library with complex parsing logic (image, network, file formats).
2. **Write Harness**: Replace `target_function` in `fuzz_target_example.c` with your parser call.
3. **Compile**: Use the appropriate Make target based on your fuzzer engine.
4. **Run**: Execute with a seed corpus relevant to the file format.
5. **Analyze**: Check `output/crashes/` for triaged crash reports.

## CI/CD Integration

Add to your `.gitlab-ci.yml` or GitHub Actions:

```yaml
fuzz_test:
  script:
    - make afl
    - timeout 60s afl-fuzz -i seeds -o output ./fuzz_afl @@ || EXIT_CODE=$?
    - if [ $EXIT_CODE -eq 1 ]; then echo "CRASH DETECTED"; exit 1; fi
```

Or use the built-in CI mode:
```bash
./fuzz_standalone --ci < malicious_input.bin
```

## Architecture

### Core Components
- **Signal Handlers**: Intercept SIGSEGV, SIGABRT, etc., to capture state before termination.
- **Coverage Map**: Shared memory region for AFL++ coordination.
- **Logger**: Thread-safe(ish) logging with severity filtering.
- **Crash Saver**: Writes detailed reports including backtraces (`execinfo.h`).

### Integration Points
- **AFL++**: Detects `AFL_SHM_ID` env var to attach to coverage map. Uses `__AFL_LOOP` for persistence.
- **LibFuzzer**: Implements `LLVMFuzzerTestOneInput` as the entry point.

## Safety & Ethics
**WARNING**: This tool is for authorized security research only. 
- Only fuzz software you own or have explicit permission to test.
- Do not use on production systems.
- Responsible disclosure is required for any discovered vulnerabilities.

## Building on Cloud Providers

### AWS EC2
```bash
# Launch Ubuntu instance
sudo apt-get install llvm clang make
git clone <repo>
make afl
```

### Google Cloud Platform (GCP)
Use Container-Optimized OS with Docker:
```dockerfile
FROM ubuntu:latest
RUN apt-get update && apt-get install -y clang llvm make
COPY . /fuzzer
WORKDIR /fuzzer
CMD ["make", "libfuzzer"]
```

### Azure
Similar to AWS, use VM Scale Sets for parallel fuzzing instances.

## Extending the Framework

### Adding Custom Sanitizers
Compile with `-fsanitize=address,undefined` to catch memory errors that don't crash immediately.

### Adding Network Fuzzing
Modify `fuzz_target_example.c` to accept input and send it via socket to a local daemon.

## License
MIT License - See LICENSE file.

## Contributing
Submit PRs for new features, bug fixes, or improved triage logic.
