# container-security-scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/barry-oyoung/container-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/barry-oyoung/container-security-scanner/actions/workflows/ci.yml)

**Docker image CVE scanner with automated CI blocking and SARIF reporting — wraps Trivy with smarter policies.**

---

## Background / Why I Built This

After a security audit found 47 critical CVEs in production images, I built this to catch them before they shipped. Now runs on every PR.

At the time, our Docker images were built and pushed with no automated vulnerability scanning. We only discovered the problem when an external auditor ran a scan during a quarterly review. Forty-seven critical CVEs — some dating back two years — sitting in images that were actively serving production traffic. The post-mortem was uncomfortable. The remediation sprint lasted three weeks and delayed two features.

The existing options I evaluated were either too noisy (Trivy alone flags everything including transitive junk you can't control) or too opaque (commercial tools that just say "blocked" with no actionable output). What I needed was:

- A wrapper that understands *context*: a CVE in a base image that has no fix available is different from a CVE in a package you could upgrade today.
- Output that developers could act on immediately — not a wall of JSON piped to /dev/null.
- CI integration that blocks the right things and only the right things.
- Reports the security team could file and track.

I built the first version in a weekend. It ran via a pre-push hook. Then I wired it into GitHub Actions, added SARIF reporting so findings show up inline on PRs, and added a policy engine so teams could manage exceptions without editing pipeline YAML.

It has now caught **200+ critical CVEs before they reached production** across our fleet of ~60 services. The tool pays for the time I put into it every time a developer sees a scan annotation on their PR and fixes the dependency before the code ships.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   container-security-scanner             │
│                                                          │
│  ┌──────────┐    ┌──────────┐    ┌────────────────────┐ │
│  │  CLI     │───▶│  Trivy   │───▶│  Result Parser     │ │
│  │ (main.py)│    │ (subprocess)  │  (JSON → Findings) │ │
│  └──────────┘    └──────────┘    └────────┬───────────┘ │
│                                           │             │
│                                           ▼             │
│                                  ┌────────────────┐     │
│                                  │  Policy Engine  │     │
│                                  │  (policies.py)  │     │
│                                  │                 │     │
│                                  │  • ignore list  │     │
│                                  │  • severity     │     │
│                                  │  • exceptions   │     │
│                                  └────────┬───────┘     │
│                                           │             │
│                     ┌─────────────────────┴──────────┐  │
│                     │                                │  │
│                     ▼                                ▼  │
│           ┌──────────────────┐           ┌──────────────┐│
│           │  Report Generator│           │  CI Adapter  ││
│           │  (report.py)     │           │  (ci.py)     ││
│           │                  │           │              ││
│           │  • HTML          │           │  • GitHub    ││
│           │  • SARIF         │           │  • Jenkins   ││
│           │  • JSON          │           │  • GitLab    ││
│           └──────────────────┘           └──────────────┘│
└─────────────────────────────────────────────────────────┘
```

### Data Flow

| Step | Component | Description |
|------|-----------|-------------|
| 1 | `main.py` | Accepts image name/tag, loads config, invokes Trivy |
| 2 | Trivy | Runs scan, outputs raw JSON vuln data |
| 3 | Parser | Normalises Trivy JSON into `Finding` dataclasses |
| 4 | `policies.py` | Filters findings through ignore lists, exceptions, thresholds |
| 5 | `report.py` | Renders HTML, SARIF, and summary JSON from filtered findings |
| 6 | `ci.py` | Emits CI-native output (GHA annotations, Jenkins warnings) |
| 7 | Exit code | Non-zero if CRITICAL findings remain after policy filtering |

---

## Quick Start

### Prerequisites

- Docker or Python 3.11+
- [Trivy](https://github.com/aquasecurity/trivy) installed and on `$PATH` (or use the Docker image which bundles it)

### Install from source

```bash
git clone https://github.com/barry-oyoung/container-security-scanner
cd container-security-scanner
pip install -r requirements.txt
# Run a scan
python -m scanner.main scan nginx:latest
```

### Docker (recommended)

```bash
# Pull the image
docker pull ghcr.io/barry-oyoung/container-security-scanner:latest

# Scan an image (mounts Docker socket so Trivy can pull the target)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/reports:/reports \
  ghcr.io/barry-oyoung/container-security-scanner:latest \
  scan nginx:latest --output /reports
```

### GitHub Actions (one-liner integration)

```yaml
- uses: barry-oyoung/container-security-scanner@v1
  with:
    image: myapp:${{ github.sha }}
    fail-on: CRITICAL
    sarif-upload: true
```

---

## Usage Examples

### 1. Basic scan — fail on CRITICAL

```bash
python -m scanner.main scan nginx:1.25-alpine
```

Output:
```
Scanning nginx:1.25-alpine...
✓ Trivy scan complete (2.3s)

Summary
───────────────────────────────
  CRITICAL   0
  HIGH       3
  MEDIUM    11
  LOW       22
  UNKNOWN    1

No CRITICAL vulnerabilities found. Scan passed.
Exit code: 0
```

### 2. Scan with HTML + SARIF report output

```bash
python -m scanner.main scan myapp:latest \
  --output ./reports \
  --format html,sarif,json
```

Writes:
- `./reports/scan-myapp-latest.html` — human-readable HTML report
- `./reports/scan-myapp-latest.sarif` — SARIF for GitHub Security tab upload
- `./reports/scan-myapp-latest.json` — machine-readable summary

### 3. Use a policy file to manage exceptions

```bash
python -m scanner.main scan myapp:latest \
  --policy ./policies/production.yaml
```

`policies/production.yaml`:
```yaml
severity_threshold: CRITICAL
ignore_unfixed: true
exceptions:
  - cve_id: CVE-2023-45853
    reason: "zlib in base image, no fix available, mitigated by WAF rule #412"
    expires: "2026-09-01"
    approved_by: "security@example.com"
```

### 4. CI mode — GitHub Actions annotations

```bash
python -m scanner.main scan myapp:latest \
  --ci github \
  --fail-on CRITICAL,HIGH
```

Emits `::error` and `::warning` annotations that appear inline on the PR diff.

### 5. Scan a tarball (air-gapped / offline)

```bash
# Save image to tar first
docker save myapp:latest -o myapp.tar

python -m scanner.main scan-tar ./myapp.tar \
  --image-name myapp:latest \
  --output ./reports
```

---

## Configuration

All options can be set via CLI flags, environment variables, or a YAML config file. CLI flags take highest precedence.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_SEVERITY_THRESHOLD` | `CRITICAL` | Minimum severity that causes a non-zero exit (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `SCANNER_IGNORE_UNFIXED` | `false` | Skip CVEs with no available fix |
| `SCANNER_POLICY_FILE` | `./policy.yaml` | Path to policy YAML (exceptions, ignore list) |
| `SCANNER_OUTPUT_DIR` | `./reports` | Directory to write report files |
| `SCANNER_OUTPUT_FORMAT` | `json` | Comma-separated: `json`, `html`, `sarif` |
| `SCANNER_CI_MODE` | `` | CI adapter: `github`, `jenkins`, `gitlab` |
| `SCANNER_TRIVY_BIN` | `trivy` | Path to Trivy binary |
| `SCANNER_TRIVY_TIMEOUT` | `300` | Trivy scan timeout in seconds |
| `SCANNER_TRIVY_CACHE_DIR` | `~/.cache/trivy` | Trivy vulnerability DB cache dir |
| `SCANNER_FAIL_ON` | `CRITICAL` | Severities that trigger exit code 1 (comma-separated) |
| `SCANNER_REPORT_TITLE` | `Container Security Scan` | Title used in HTML/SARIF reports |

### Policy YAML

```yaml
# policy.yaml
severity_threshold: CRITICAL    # minimum severity to report
ignore_unfixed: true             # skip CVEs with no fix available
fail_on:
  - CRITICAL
  - HIGH

# Permanent ignores — use sparingly, prefer exceptions with expiry
ignore_cves:
  - CVE-2022-37434  # zlib, no impact, WAF mitigated

# Time-boxed exceptions with audit trail
exceptions:
  - cve_id: CVE-2023-45853
    reason: "zlib in base image, upstream fix not yet released"
    expires: "2026-09-01"
    approved_by: "security@example.com"
    ticket: "SEC-1042"

# Ignore entire packages in specific locations
ignore_paths:
  - /usr/share/doc
  - /usr/lib/debug
```

---

## What I Would Do Differently

Looking back after running this in production for 18+ months, a few things I'd change:

**1. The policy engine should be remote, not file-based.**
Having policy YAML in each repo means exceptions drift out of sync across services. I'd build a central policy API that all scanner instances query. This would let the security team approve an exception once and have it apply fleet-wide, with full audit logging.

**2. SARIF was an afterthought — it should have been the primary format.**
I bolted on SARIF support six months in. Designing the internal data model around SARIF from day one would have made the report generator much cleaner and the GitHub integration trivial.

**3. I underestimated the importance of "no fix available" filtering.**
Early versions flagged unfixed CVEs, which trained developers to dismiss scan output. Adding `ignore_unfixed` made the signal-to-noise ratio actually actionable. I wish I had done this in week one.

**4. Caching the Trivy DB in CI should have been the default.**
Re-downloading the vulnerability DB on every PR run added 30–60 seconds per scan and hammered the Trivy update server. CI DB caching should be enabled by default, not opt-in.

**5. I should have instrumented scan duration and CVE trends from the start.**
I added metrics two years in. Having a time-series of "CVEs found per scan" from the beginning would have made it much easier to demonstrate the tool's value to management and catch regression patterns earlier.

---

## Contributing

Contributions are welcome. This is a tool I built to solve a real problem; if it solves yours too, I am glad for the help making it better.

### Setup

```bash
git clone https://github.com/barry-oyoung/container-security-scanner
cd container-security-scanner
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
make test
```

### Running the tests

```bash
make test          # unit tests
make test-e2e      # end-to-end tests (requires Docker + Trivy)
make lint          # ruff + mypy
```

### Submitting a PR

1. Open an issue describing the problem or improvement.
2. Branch from `main`: `git checkout -b fix/short-description`
3. Add tests for any new behaviour.
4. Run `make lint test` before pushing.
5. Reference the issue in your PR description.

I review PRs within a few days. For security-sensitive changes, please use GitHub's private vulnerability reporting rather than opening a public issue.

---

## License

MIT — see [LICENSE](LICENSE).

Built by Barry O Young. If this has saved you from a bad day, I am glad.






