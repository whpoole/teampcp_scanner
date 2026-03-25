# teampcp-scanner

A comprehensive, zero-dependency detection tool for the **TeamPCP / Trivy supply chain attack** (CVE-2026-33634).

On March 19, 2026, threat actor **TeamPCP** compromised Aqua Security's Trivy vulnerability scanner, cascading into a multi-ecosystem supply chain attack affecting GitHub Actions, Docker Hub, 66+ npm packages (via a self-replicating worm called CanisterWorm), and the LiteLLM Python package on PyPI. Over 1,000 cloud environments have been impacted.

This scanner goes beyond dependency checking. It detects compromised binaries by SHA256 hash, identifies active system persistence artifacts, scans for C2 domain references in your codebase, checks Kubernetes clusters for wiper DaemonSets, and verifies whether credential files were exposed. Every IOC has been verified character-for-character against published sources (GHSA-69fq-xp46-6x23, CrowdStrike, StepSecurity, Datadog, Microsoft, Wiz, Snyk, Endor Labs, JFrog, Socket.dev).

## Quick Start

There are two distinct modes. Run both for full coverage.

Every run (with or without `--system`) always includes:
- **Recursive file scan** of the target directory — source code, dependency files, workflow files, manifests, git history
- **Host persistence checks** — fixed OS-level paths for known TeamPCP implants (`~/.config/sysmon.py`, systemd services, `/tmp` staging artifacts, etc.), running processes, and systemd/launchd service names

Each module only counts the files relevant to its check (e.g. the GitHub Actions module counts `.yml` workflow files; the C2 module counts all text files scanned). The scanner excludes `.git/`, `__pycache__/`, and itself automatically.

```bash
# Scan current working directory + host persistence checks
python3 teampcp_scanner.py

# Scan a specific repository + host persistence checks
python3 teampcp_scanner.py --scan-path /path/to/repo
```

**`--system`** adds deeper host-level checks on top of the above: Trivy binary hash verification (PATH/Homebrew), installed LiteLLM package inspection, pulled Docker image digest matching, shell history scanning, Windows DNS cache, live Kubernetes cluster query, and system-wide credential file inventory. Run this if you suspect the machine itself is infected:

```bash
python3 teampcp_scanner.py --system
```

**Run both together** (recommended for a thorough assessment):

```bash
python3 teampcp_scanner.py --scan-path /path/to/repo --system
```

**Verify the scanner works correctly:**

```bash
python3 teampcp_scanner.py --self-test
```

### Requirements

- Python 3.8+
- Zero external dependencies (stdlib only)
- macOS, Linux, or Windows

## What It Detects

The scanner runs **10 detection modules** covering every known attack vector:

| # | Module | What It Checks | Severity |
|---|--------|----------------|----------|
| 1 | **GitHub Actions** | `trivy-action` and `setup-trivy` references in workflow files. Identifies mutable tag refs in the compromised range (0.0.1-0.34.2), known malicious commit SHAs, and whether refs are safely SHA-pinned. | CRITICAL |
| 2 | **Trivy Binary** | Scans PATH, Homebrew, and common install locations for Trivy binaries. Matches SHA256 against 32 known-malicious hashes. Scans binary contents for the embedded C2 typosquat domain. Detects versions 0.69.4-6. | CRITICAL |
| 3 | **npm CanisterWorm** | Checks `package.json`, `package-lock.json`, and `node_modules` for 66+ compromised packages across 7 npm scopes. Detects CanisterWorm behavioral patterns: `postinstall` hooks, `findNpmTokens`, ICP canister C2 references, and large base64 payloads. | CRITICAL |
| 4 | **LiteLLM PyPI** | Scans Python dependency files for LiteLLM versions 1.82.7/1.82.8. Checks installed packages for the malicious `litellm_init.pth` auto-execute file and compromised `proxy_server.py` by hash. Scans all `.pth` files for suspicious exec/eval/base64 patterns. | CRITICAL |
| 5 | **Docker / Containers** | Scans Dockerfiles, compose files, and K8s manifests for `aquasec/trivy` image references. Checks local Docker images against 15 known-malicious digests. Flags versions 0.69.4-6 and `latest` tag usage. | CRITICAL |
| 6 | **System Persistence** | Checks platform-specific persistence paths: Linux systemd services (`sysmon.service`, `pgmon.service`, `internal-monitor.service`, `pgmonitor.service`), persistence scripts (`sysmon.py`, `service.py`, `runner.py`), staging artifacts (`/tmp/pglog`, `/tmp/.pg_state`), exfiltration bundles (`tpcp.tar.gz`). Verifies file content for TeamPCP indicators. Checks running processes. macOS LaunchAgent and Windows %APPDATA% equivalents included. | CRITICAL |
| 7 | **C2 / Network IOCs** | Scans every readable text file in the scan path for 14 known C2 domains and IPs — including the typosquat `scan.aquasecurtiy.org`, ICP blockchain C2, Cloudflare tunnel endpoints, and LiteLLM exfiltration domain. With `--system`: also checks shell history and Windows DNS cache. Note: the "Scanned" count reflects text files examined; a hit in documentation or the scanner itself is expected and not necessarily evidence of compromise. | CRITICAL/HIGH |
| 8 | **Kubernetes IOCs** | Scans YAML/JSON manifests for TeamPCP DaemonSet names (`host-provisioner-iran`, `host-provisioner-std`), wiper container names (`kamikaze`), and lateral movement pods (`node-setup-*`). Optionally live-queries clusters via `kubectl`. | CRITICAL |
| 9 | **Git History** | Checks git remotes for `tpcp-docs` repositories (TeamPCP's fallback exfiltration method). Searches commit history during the attack window (Mar 19-24) for trivy-related changes. | CRITICAL |
| 10 | **Credential Exposure** | Identifies credential files (`.npmrc` with tokens, `.env` files, AWS credentials, Docker configs) that would have been harvested if the system was compromised. Risk assessment, not confirmation of theft. | MEDIUM |

## Output Formats

### Terminal (default)

Color-coded output with severity badges, per-category status, and a findings summary:

```
  TeamPCP / Trivy Supply Chain Scanner
  CVE-2026-33634 | v1.0.0
  --------------------------------------------------
  Target: /path/to/repo
  System: basic

  Scanning...

                 CLEAR  GitHub Actions Workflows  1ms
                 CLEAR  Trivy Binary Installation  2ms
                 CLEAR  npm CanisterWorm Packages  15ms
                 CLEAR  LiteLLM PyPI Compromise  3ms
                 CLEAR  Docker / Container Images  8ms
                 CLEAR  System Persistence Artifacts  35ms
                 CLEAR  C2 / Network IOCs  120ms
                 CLEAR  Kubernetes IOCs  5ms
                 CLEAR  Git History & Exfiltration  12ms
                 CLEAR  Credential Exposure Assessment  2ms

======================================================================
  TeamPCP / Trivy Supply Chain Exposure Report
  CVE-2026-33634 | teampcp-scanner v1.0.0
======================================================================

  Scan time:   2026-03-25T14:54:36Z
  Platform:    Darwin 25.0.0 (arm64)
  Target:      /path/to/repo
  System scan: No

  GitHub Actions Workflows  CLEAR
  Trivy Binary Installation  CLEAR
  npm CanisterWorm Packages  CLEAR  (12 items)
  LiteLLM PyPI Compromise  CLEAR
  Docker / Container Images  CLEAR
  System Persistence Artifacts  CLEAR
  C2 / Network IOCs  CLEAR  (4521 items)
  Kubernetes IOCs  CLEAR
  Git History & Exfiltration  CLEAR  (1 items)
  Credential Exposure Assessment  CLEAR

======================================================================
  SUMMARY
======================================================================

  Total findings: 0
    CRITICAL: 0
    HIGH:     0
    MEDIUM:   0
    LOW:      0
    INFO:     0

======================================================================
```

When findings are detected, each includes the severity, title, evidence, file path, and remediation:

```
  npm CanisterWorm Packages  2 finding(s)  (14 items)
    [CRITICAL] Compromised npm package: @emilgroup/auth-sdk@1.25.2
      This exact version was published by the CanisterWorm.
      File: package.json
      Evidence: "@emilgroup/auth-sdk": "^1.25.2"
      Fix: Remove or downgrade @emilgroup/auth-sdk. Delete node_modules and reinstall with --ignore-scripts.
```

### JSON (`--json`)

Machine-readable output for CI/CD integration, SIEM ingestion, or automated processing:

```json
{
  "timestamp": "2026-03-25T14:53:55Z",
  "scanner_version": "1.0.0",
  "platform": "Darwin 25.0.0 (arm64)",
  "scan_target": "/path/to/repo",
  "system_scan": false,
  "categories": [
    {
      "name": "github_actions",
      "display_name": "GitHub Actions Workflows",
      "status": "FINDINGS",
      "findings": [
        {
          "category": "github_actions",
          "severity": "CRITICAL",
          "title": "trivy-action using compromised tag range",
          "detail": "Tag v0.34.0 was force-pushed to malicious code...",
          "file_path": ".github/workflows/ci.yml",
          "evidence": "uses: aquasecurity/trivy-action@v0.34.0",
          "remediation": "Pin to v0.35.0 or commit SHA 57a97c7e..."
        }
      ],
      "scan_duration_ms": 1,
      "items_scanned": 1
    }
  ],
  "summary": {
    "total_findings": 7,
    "by_severity": {
      "INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 2, "CRITICAL": 5
    }
  }
}
```

### Markdown (`--markdown`)

Stakeholder-ready report suitable for sharing in incident reports, Slack, or email:

```markdown
# TeamPCP / Trivy Supply Chain Exposure Report

**CVE:** CVE-2026-33634 | **Scanner:** teampcp-scanner v1.0.0

## Findings Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 2 |
| **Total** | **7** |

## [FAIL] GitHub Actions Workflows

| Severity | Finding | Detail |
|----------|---------|--------|
| **CRITICAL** | trivy-action using compromised tag range | Tag v0.34.0 was force-pushed... |

**Remediation:**
- Pin to v0.35.0 or commit SHA 57a97c7e...
```

## Interpreting Results

### Severity Levels

| Severity | Meaning | Example |
|----------|---------|---------|
| **CRITICAL** | Confirmed compromised component or active malware detected | Compromised Trivy binary hash match, malicious `litellm_init.pth` found, CanisterWorm package installed |
| **HIGH** | Strong indicator requiring investigation | C2 domain in source code, Trivy `latest` tag used during attack window, known-targeted npm package present |
| **MEDIUM** | Potential exposure, review recommended | LiteLLM dependency without pinned version, mutable GitHub Actions tag, Trivy referenced but version unknown |
| **LOW** | Minor risk item | Environment files present in repo, safe but mutable tag used |
| **INFO** | Informational note | SHA-pinned Actions reference (verify not compromised), system credential files exist |

### Exit Codes

| Code | Meaning | Use in CI/CD |
|------|---------|--------------|
| `0` | Clean | Pipeline passes |
| `1` | Non-critical findings (HIGH/MEDIUM/LOW) | Pipeline warns |
| `2` | CRITICAL findings | Pipeline fails |

### What To Do If Findings Are Detected

**CRITICAL findings:**
1. **Rotate ALL secrets** accessible to compromised components immediately — cloud provider keys, SSH keys, API tokens, database passwords, npm tokens, Docker registry credentials, Kubernetes service account tokens
2. **Search your GitHub org** for repositories named `tpcp-docs` (indicates successful credential exfiltration)
3. **Remove compromised components** — delete malicious binaries, downgrade packages, pin Actions to safe SHAs
4. **Check for persistence** on all CI runners and developer machines: look for `sysmon.py`, `pgmon.service`, `/tmp/pglog`
5. **Block C2 infrastructure** at network egress: `scan.aquasecurtiy.org`, `45.148.10.212`, `45.148.10.122`, `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`
6. **Audit Kubernetes clusters** for DaemonSets `host-provisioner-iran` and `host-provisioner-std` in `kube-system`

**HIGH findings:**
1. Investigate the specific finding
2. Determine if the component was active during the attack window (March 19-24, 2026)
3. If exposure is confirmed, follow the CRITICAL remediation steps above

## IOC Database

The scanner embeds a comprehensive, source-verified IOC database:

| Category | Count | Primary Source |
|----------|-------|----------------|
| Malicious Trivy binary SHA256 hashes | 32 | GHSA-69fq-xp46-6x23 (26), Wiz (6) |
| Malicious Docker image digests | 15 | GHSA-69fq-xp46-6x23 |
| Malicious Git commit SHAs | 9 | GHSA + StepSecurity + CrowdStrike |
| C2 domains and IPs | 14 | CrowdStrike, StepSecurity, Datadog, Microsoft, Wiz, Aikido, SafeDep |
| Compromised npm packages | 66+ | Endor Labs, JFrog, Socket.dev, Datadog |
| LiteLLM file hashes | 3 | Snyk |
| Entrypoint.sh hashes | 2 | CrowdStrike |
| System persistence paths | 10 (Linux) | CrowdStrike, StepSecurity, Datadog, Aikido |
| Kubernetes IOC names | 5 | StepSecurity, Datadog, Aikido |

Every IOC is annotated with its source in the code. See the inline `[GHSA]`, `[CS]`, `[SS]`, `[DD]`, `[AK]`, `[WZ]`, `[MS]`, `[SafeDep]` tags throughout the IOC database section.

## CLI Reference

```
usage: teampcp-scanner [-h] [--scan-path SCAN_PATH] [--system] [--json]
                       [--markdown] [--verbose] [--self-test] [--version]

Detect exposure to the TeamPCP/Trivy supply chain attack (CVE-2026-33634).

options:
  -h, --help            show this help message and exit
  --scan-path SCAN_PATH
                        Path to scan (default: current directory)
  --system              Enable deep system checks (binaries, processes,
                        installed packages, Docker images, K8s clusters)
  --json                Output results as JSON
  --markdown            Output results as Markdown report
  --verbose, -v         Show detailed progress and informational findings
  --self-test           Run built-in test with synthetic fixtures to verify
                        scanner accuracy
  --version             show program's version number and exit
```

### Examples

```bash
# Scan a monorepo with JSON output for CI integration
python3 teampcp_scanner.py --scan-path /workspace --system --json > scan_results.json

# Generate a markdown report for stakeholders
python3 teampcp_scanner.py --scan-path /workspace --system --markdown > exposure_report.md

# Quick check of a single project
python3 teampcp_scanner.py --scan-path ./my-project

# Full system audit (checks installed binaries, running processes, Docker images, K8s)
python3 teampcp_scanner.py --system

# Verify scanner is working correctly
python3 teampcp_scanner.py --self-test
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: TeamPCP Exposure Check
  run: |
    python3 teampcp_scanner.py --scan-path . --json > teampcp_results.json
    exit_code=$?
    if [ $exit_code -eq 2 ]; then
      echo "::error::CRITICAL TeamPCP exposure detected"
      exit 1
    fi
```

## Attack Background

**CVE-2026-33634** | **GHSA-69fq-xp46-6x23** | CVSS 10.0

TeamPCP (also tracked as DeadCatx3) exploited a misconfigured `pull_request_target` GitHub Actions workflow in the Trivy repository to steal a Personal Access Token. After an incomplete credential rotation, the attacker retained access and executed a multi-phase attack:

1. **GitHub Actions** (Mar 19): Force-pushed 76 of 77 `trivy-action` tags and all 7 `setup-trivy` tags to malicious commits containing a credential stealer that read CI runner process memory
2. **Trivy Binary** (Mar 19): Published malicious v0.69.4 via Aqua's own release automation
3. **Docker Hub** (Mar 22): Published malicious images v0.69.5 and v0.69.6; defaced 44 Aqua Security repositories
4. **npm CanisterWorm** (Mar 20-22): Using stolen npm tokens, deployed a self-replicating worm across 66+ packages that harvests credentials and auto-publishes malicious updates to every reachable npm namespace
5. **LiteLLM PyPI** (Mar 24): Compromised versions 1.82.7 and 1.82.8 of the popular LLM proxy library (3.4M downloads/day), including a `.pth` file that executes on every Python interpreter startup
6. **Kubernetes Wiper** (ongoing): Second-stage payloads include a geopolitically-targeted wiper that destroys Iranian-configured systems and installs persistence on all others

The attack uses an **ICP blockchain canister** for C2 — a decentralized infrastructure that cannot be taken down via conventional methods.

## References

- [GHSA-69fq-xp46-6x23 — Official Advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- [CrowdStrike — From Scanner to Stealer](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/)
- [StepSecurity — Trivy Compromised a Second Time](https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release)
- [StepSecurity — CanisterWorm Analysis](https://www.stepsecurity.io/blog/canisterworm-how-a-self-propagating-npm-worm-is-spreading-backdoors-across-the-ecosystem)
- [Datadog Security Labs — LiteLLM Compromised](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)
- [Microsoft — Detection and Defense Guidance](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)
- [Wiz — Trivy Compromised by TeamPCP](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack)
- [Snyk — Poisoned Scanner Backdooring LiteLLM](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/)
- [Endor Labs — CanisterWorm Package List](https://www.endorlabs.com/learn/canisterworm)
- [JFrog — CanisterWorm Research](https://research.jfrog.com/post/canister-worm/)
- [Aikido — Kubernetes Wiper Targeting Iran](https://www.aikido.dev/blog/teampcp-stage-payload-canisterworm-iran)

## License

MIT
