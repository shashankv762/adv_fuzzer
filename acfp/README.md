# Advanced C Fuzzing Platform (ACFP)

An advanced, production-grade, cloud-compatible, C-focused fuzzing platform that integrates with AFL++ and LibFuzzer for comprehensive target analysis. Designed for authorized defensive security research, CVE-ready vulnerability discovery, bug bounty use, academic coursework, and responsible disclosure.

## ⚠️ Authorization Notice

**This platform is designed for authorized security research only.**

- You must be the authorized owner or have explicit permission to test all targets
- All fuzzing activities must comply with applicable laws and regulations
- This tool is for defensive security purposes: finding bugs, producing CVE-ready evidence, supporting patching, and managing vulnerability lifecycle responsibly
- Do not use this platform against systems without explicit written permission

## Features

- **Core Fuzzing Engine**: Coverage-guided, mutation-based fuzzing in C11/C17
- **AFL++ Integration**: Deep integration with AFL++ as a fuzzing backend
- **LibFuzzer Integration**: In-process coverage-guided fuzzing support
- **Crash Triage**: Automated crash deduplication, classification, and exploitability assessment
- **CVE-Ready Reports**: Generate complete vulnerability reports with CWE mapping, CVSS estimation, and disclosure timelines
- **Real-Time Dashboard**: Monitor fuzzing jobs, crashes, and vulnerability trends
- **Lifecycle Management**: Track vulnerabilities from discovery through disclosure
- **Cloud Deployment**: AWS, Azure, and GCP compatible deployment templates
- **CI/CD Integration**: GitHub Actions, GitLab CI, Jenkins templates

## Quick Start

### Prerequisites

```bash
# Ubuntu 22.04/24.04
sudo apt update
sudo apt install -y build-essential clang llvm python3 python3-pip nodejs npm git curl wget

# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make distrib-install
cd ..

# Install Python dependencies
pip3 install -r requirements.txt

# Install Node.js dependencies
cd dashboard/ui && npm install && cd ../..
```

### Build the Platform

```bash
cd /workspace/acfp
make all
```

### Run the Demo

```bash
# Build the demo vulnerable target
make -C targets/demo

# Start the dashboard API
python3 -m dashboard.api.main &

# Start the UI (in another terminal)
cd dashboard/ui && npm run dev

# Run a short fuzzing campaign
./bin/acfp-fuzzer ./targets/demo/bin/demo_target ./targets/seeds
```

### Access the Dashboard

Open your browser to `http://localhost:3000`

Default API Key: `admin-key-12345` (change in production!)

## Architecture

```
acfp/
├── src/                    # Core C fuzzing engine
├── include/                # Header files
├── backend/                # AFL++ and LibFuzzer integrations
├── dashboard/              # Dashboard API and UI
│   ├── api/                # FastAPI REST API
│   └── ui/                 # React frontend
├── scripts/                # Build and utility scripts
├── deploy/                 # Deployment configurations
│   ├── docker/             # Dockerfiles
│   ├── k8s/                # Kubernetes manifests
│   └── terraform/          # IaC for AWS, Azure, GCP
├── ci/                     # CI/CD templates
├── tests/                  # Automated tests
├── targets/                # Example vulnerable targets
├── corpus/                 # Seed corpora
├── reports/                # Generated reports
└── docs/                   # Documentation
```

## Core Components

1. **Fuzzing Engine** (`src/fuzzer.c`): Modular C-based fuzzer with coverage guidance
2. **Backend Adapters**: AFL++ and LibFuzzer integration layers
3. **Crash Collector**: Captures and stores crash artifacts
4. **Triage Engine**: Deduplicates and classifies crashes
5. **Report Generator**: Creates CVE-ready vulnerability reports
6. **REST API**: Manages jobs, crashes, and lifecycle states
7. **Dashboard UI**: Real-time monitoring and reporting

## Security Features

- Role-based access control (Admin, Researcher, Viewer)
- API key authentication
- Secure artifact storage with path traversal prevention
- Input validation on all API endpoints
- Audit logging of user actions
- Sandboxed execution via containers

## Documentation

- [User Guide](docs/user-guide.md)
- [Administrator Guide](docs/admin-guide.md)
- [API Reference](docs/api-reference.md)
- [Deployment Guide](docs/deployment.md)
- [Responsible Disclosure Policy](docs/disclosure-policy.md)

## License

Apache License 2.0 - See LICENSE file for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

*Built for authorized security research and education.*
