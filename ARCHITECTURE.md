# Advanced C Fuzzing Platform (ACFP)

## Architecture Overview

This is a production-grade, cloud-compatible, C-focused fuzzing platform for authorized defensive security research, CVE-ready vulnerability discovery, bug bounty use, academic coursework, and responsible disclosure.

### Core Components

1. **Core Fuzzing Engine** (`/src`, `/include`)
   - Coverage-guided fuzzing in C11/C17
   - Mutation-based and structure-aware fuzzing
   - Crash detection, deduplication, and triage
   - Corpus management and minimization

2. **Backend Adapters** (`/backend`)
   - AFL++ integration
   - LibFuzzer integration
   - Native engine

3. **Target Analysis** (`/scripts`, `/backend`)
   - Static attack-surface discovery
   - Harness generation scaffolding
   - Sanitizer orchestration

4. **Crash Triage Engine** (`/src/triage.c`)
   - Crash classification
   - Deduplication using stack hashes
   - Exploitability assessment
   - CWE/CVSS mapping

5. **Dashboard** (`/dashboard`)
   - Real-time monitoring
   - Crash logs and trends
   - CVE workflow panel
   - Lifecycle management

6. **REST API** (`/dashboard/api`)
   - Job, target, crash, report management
   - WebSocket for real-time updates
   - Export endpoints

7. **Storage Layer** (`/src/storage.c`)
   - SQLite for local development
   - PostgreSQL adapter for production
   - Object storage for artifacts

8. **Cloud Deployment** (`/deploy`, `/terraform`)
   - Docker, Kubernetes, Helm
   - AWS, Azure, GCP Terraform modules

## Repository Layout

```
/workspace
├── src/                    # Core C source files
├── include/                # Header files
├── backend/                # Backend adapters
├── afl_integration/        # AFL++ scripts and examples
├── libfuzzer_integration/  # LibFuzzer harnesses
├── dashboard/
│   ├── api/                # REST API (Python/FastAPI)
│   └── frontend/           # Web UI (HTML/JS/CSS)
├── scripts/                # Build and utility scripts
├── deploy/
│   ├── docker/             # Dockerfiles
│   ├── k8s/                # Kubernetes manifests
│   └── helm/               # Helm charts
├── terraform/
│   ├── aws/                # AWS IaC
│   ├── azure/              # Azure IaC
│   └── gcp/                # GCP IaC
├── ci/                     # CI/CD templates
├── tests/                  # Automated tests
├── examples/               # Example harnesses
├── docs/                   # Documentation
├── targets/                # Demo vulnerable targets
├── corpus/
│   ├── seeds/              # Seed corpus
│   └── dictionaries/       # Fuzzing dictionaries
├── reports/                # Generated reports
├── Makefile                # Build system
├── CMakeLists.txt          # CMake build
├── docker-compose.yml      # Local stack
└── README.md               # Quickstart guide
```

## Security Boundaries

- All fuzzing targets must be local, owned, or authorized
- No remote exploitation capabilities
- Crash artifacts treated as potentially dangerous
- Role-based access control for dashboard
- API key authentication
- Secure file storage with path validation

## Supported Fuzzing Backends

1. **Native Engine**: Custom C fuzzer with coverage guidance
2. **AFL++**: Full integration with afl-fuzz, persistent mode, dictionaries
3. **LibFuzzer**: In-process fuzzing with sanitizers

## Workflow

1. **Target Selection**: Identify C/C++ entrypoints for fuzzing
2. **Harness Generation**: Create fuzzing harnesses
3. **Build with Sanitizers**: Compile with ASan, UBSan, LSan
4. **Fuzzing Campaign**: Run parallel fuzzing jobs
5. **Crash Collection**: Detect and store crashes
6. **Triage**: Deduplicate and classify crashes
7. **Report Generation**: Create CVE-ready reports
8. **Lifecycle Management**: Track findings through disclosure

## Authorization Model

- **Owner/Admin**: Full access to all features
- **Researcher**: Can create jobs, view crashes, generate reports
- **Viewer**: Read-only access to dashboard and reports

All users must be authenticated. API keys are hashed before storage.
