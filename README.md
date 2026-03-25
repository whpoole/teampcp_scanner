# TeamPCP / Trivy Compromise Scanner
### Detect exposure to the TeamPCP / Trivy supply chain attack — CVE-2026-33634

On 19 March 2026, threat actor **TeamPCP** compromised Aqua Security's Trivy vulnerability scanner and triggered a cascading supply chain attack across GitHub Actions, Docker Hub, 66+ npm packages, and the LiteLLM Python library. Over 1,000 cloud environments have been impacted.

This tool gives security teams and developers a single command to determine whether their infrastructure, codebases, or machines were exposed — going far beyond dependency scanning to detect compromised binaries by hash, active persistence on disk, C2 domain references in code, malicious Kubernetes workloads, and credential harvesting risk.

**Zero external dependencies. Python 3.8+. Runs on macOS, Linux, and Windows.**

---

## The Attack at a Glance

| Date | Vector | What Happened |
|------|--------|---------------|
| Mar 19 | GitHub Actions | 76 of 77 `trivy-action` tags and all 7 `setup-trivy` tags force-pushed to a credential stealer |
| Mar 19 | Trivy Binary | Malicious v0.69.4 published via Aqua's own release pipeline |
| Mar 20–22 | npm / CanisterWorm | Self-replicating worm deployed across 66+ packages using stolen npm tokens; harvests credentials and auto-publishes to every reachable namespace |
| Mar 22 | Docker Hub | Malicious images v0.69.5 and v0.69.6 published; 44 Aqua repositories defaced |
| Mar 24 | LiteLLM (PyPI) | Versions 1.82.7 and 1.82.8 backdoored; a `.pth` file executes on every Python startup |
| Ongoing | Kubernetes wiper | Second-stage payload destroys Iranian-configured systems and installs persistence on all others |

C2 is routed through an **ICP blockchain canister** — decentralised infrastructure that cannot be taken down via conventional means.

---

## Who Should Run This

- **Security teams** responding to or assessing exposure from the TeamPCP incident
- **DevOps and platform engineers** who use Trivy in CI/CD pipelines, Docker builds, or Kubernetes clusters
- **Developers** who have LiteLLM, Trivy, or any of the 66+ compromised npm packages in their projects
- **Any organisation** that ran a GitHub Actions workflow using `trivy-action` or `setup-trivy` between 19–20 March 2026

---

## Quick Start

```bash
python3 teampcp_scanner.py
```

That's it. By default the scanner checks the current directory recursively **and** inspects the host machine for active persistence artifacts, running malicious processes, and systemd/launchd service names.

### Running Against a Specific Repository

```bash
python3 teampcp_scanner.py --scan-path /path/to/repo
```

### Adding Deep System Checks (`--system`)

The `--system` flag extends the scan to include checks that require access to the wider host environment:

| What gets added | Why it matters |
|----------------|----------------|
| Trivy binary SHA256 verification (PATH, Homebrew, common paths) | Detects the compromised v0.69.4 binary by hash even if renamed |
| Installed LiteLLM package inspection | Finds the malicious `.pth` auto-execute file in site-packages |
| Pulled Docker image digest matching | Identifies compromised images already present locally |
| Shell history scanning | Finds past connections to known C2 domains |
| Windows DNS cache | Reveals whether C2 domains have been recently resolved |
| Live Kubernetes cluster query via `kubectl` | Detects active wiper DaemonSets in running clusters |
| System-wide credential file inventory | Assesses what credentials would have been at risk |

```bash
# Deep system check only (no repo scan)
python3 teampcp_scanner.py --system

# Full coverage — recommended for incident response
python3 teampcp_scanner.py --scan-path /path/to/repo --system
```

> **Note:** Persistence paths (`~/.config/sysmon.py`, systemd services, `/tmp` staging artifacts, etc.) are **always** checked regardless of whether `--system` is used. This is by design — you should always know if malware is resident on the machine you're scanning from.

### Output Formats

```bash
# Human-readable terminal output (default)
python3 teampcp_scanner.py --scan-path /path/to/repo --system

# Machine-readable JSON — pipe to SIEM, jq, or CI tooling
python3 teampcp_scanner.py --scan-path /path/to/repo --system --json > results.json

# Markdown report — share with stakeholders, paste into incident tickets
python3 teampcp_scanner.py --scan-path /path/to/repo --system --markdown > report.md
```

### Verify the Scanner is Working

```bash
python3 teampcp_scanner.py --self-test
```

Creates synthetic IOC fixtures in a temp directory and validates all 10 detection modules fire correctly. Exit code 2 (CRITICAL findings from the test fixtures) confirms the scanner is functioning.

---

## What Gets Checked

The scanner runs **10 detection modules** in parallel, each targeting a specific attack vector from the TeamPCP campaign.

### 1 — GitHub Actions Workflows
Recursively walks `.github/workflows/` for all `.yml`/`.yaml` files and scans for `trivy-action` and `setup-trivy` references. For each reference found it checks:

- Is the ref a **known malicious commit SHA**? → CRITICAL
- Is it a **tag in the compromised range** (trivy-action v0.0.1–v0.34.2, setup-trivy v0.0.1–v0.2.5)? → CRITICAL
- Is it an **unknown SHA pin** (40 hex chars, not in the known-bad list)? → INFO (manual verification needed)
- Is it a **mutable tag outside** the compromised range? → MEDIUM
- Does the workflow use `pull_request_target` alongside any Trivy reference? → MEDIUM (original attack vector)

### 2 — Trivy Binary Installation
*(Requires `--system` or a scan path)*

Checks PATH, Homebrew (`/opt/homebrew/bin`, `/usr/local/bin`), and common install locations for any Trivy binary. For each binary found:
- Computes SHA256 and matches against **32 known-malicious hashes** (v0.69.4 across all platforms and architectures)
- Scans the binary's byte content for the embedded C2 typosquat string `aquasecurtiy`
- Checks the version string for 0.69.4, 0.69.5, 0.69.6

### 3 — npm / CanisterWorm Packages
Checks `package.json`, `package-lock.json`, and `node_modules` for **66+ compromised packages** across 7 scopes (`@emilgroup`, `@solarfusion`, `@codingeco`, `@designcraft`, `@techvault`, `@cloudbridge`, `@devstream`) and 8 standalone packages. Also scans for CanisterWorm behavioural patterns inside package files:
- `postinstall` hooks that run external scripts
- `findNpmTokens` function (credential harvesting)
- ICP canister ID references (C2 beacon)
- Large base64-encoded payloads

### 4 — LiteLLM PyPI Backdoor
Scans Python dependency files (`requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile`, etc.) for LiteLLM versions 1.82.7 and 1.82.8. With `--system`, also checks installed site-packages for:
- `litellm_init.pth` — the auto-execute `.pth` file (verified by SHA256)
- `proxy_server.py` — the backdoored proxy module (verified by SHA256)
- Any `.pth` file containing `exec(`, `eval(`, `base64.b64decode`, or `compile(` (generic `.pth` backdoor detection)

### 5 — Docker / Container Images
Scans Dockerfiles, compose files, and Kubernetes manifests for `aquasec/trivy` image references, flagging versions 0.69.4–0.69.6 and `latest` tag usage. With `--system`, runs `docker images --digests` and matches all local image digests against **15 known-malicious image digests** from GHSA.

### 6 — System Persistence Artifacts
Always runs. Checks platform-specific paths for known TeamPCP implants:

**Linux:** `~/.config/sysmon/sysmon.py`, `~/.config/sysmon.py`, `~/.config/systemd/user/sysmon.service`, `~/.config/systemd/user/pgmon.service`, `~/.local/share/pgmon/service.py`, `/etc/systemd/system/internal-monitor.service`, `/etc/systemd/system/pgmonitor.service`, `/var/lib/svc_internal/runner.py`, `/var/lib/pgmon/pgmon.py`

**All platforms:** `/tmp/pglog`, `/tmp/.pg_state`, `/tmp/tpcp.tar.gz` (exfiltration bundle)

**macOS:** LaunchAgent paths and equivalent Python implant locations

**Windows:** `%APPDATA%\sysmon\sysmon.py`, `%APPDATA%\pgmon\service.py`, `%LOCALAPPDATA%` equivalents

For any file found, content is verified for TeamPCP markers (ICP canister ID, C2 domains, `tpcp` strings) to reduce false positives. Running processes and systemd/launchd service names are also checked.

### 7 — C2 / Network IOCs
Scans every readable text file in the scan path for **14 known C2 domains and IPs**:

| IOC | Type | Source |
|-----|------|--------|
| `scan.aquasecurtiy.org` | Domain (typosquat) | CrowdStrike, StepSecurity, Datadog, Microsoft, Wiz |
| `45.148.10.212` | IP | Wiz |
| `45.148.10.122` | IP | Microsoft |
| `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` | ICP C2 | Multiple |
| `models.litellm.cloud` | Exfil domain | Datadog, Snyk |
| `checkmarx.zone` | C2 domain | CrowdStrike, StepSecurity |
| `recv.hackmoltrepeat.com` | C2 domain | CrowdStrike |
| Cloudflare tunnel endpoints (6) | Tunnel C2 | CrowdStrike, StepSecurity, SafeDep |

A C2 hit in documentation or scanning tools is expected and noted in the remediation text. A hit in application code, configuration, or shell history is a strong indicator of active compromise. With `--system`, shell history and Windows DNS cache are also scanned.

### 8 — Kubernetes IOCs
Scans YAML and JSON manifests for TeamPCP wiper components by name: DaemonSets `host-provisioner-iran` and `host-provisioner-std`, container `kamikaze`, pods matching `node-setup-*`. With `--system`, live-queries the active cluster via `kubectl get all --all-namespaces`.

### 9 — Git History & Exfiltration
Finds all git repositories under the scan path and checks:
- Remotes for `tpcp-docs` repository names (TeamPCP's credential exfiltration repo pattern)
- Commit history during the attack window (Mar 19–24, 2026) for Trivy-related changes that may indicate a compromised workflow ran and pushed

### 10 — Credential Exposure Assessment
Identifies credential files that would have been in scope for harvesting: `.npmrc` files with auth tokens, `.env` files, AWS credential files, SSH private keys, `.pypirc`, Docker config with registry credentials. Reports as MEDIUM — this is a risk assessment of what was exposed, not confirmation that theft occurred. With `--system`, extends to system-wide locations (`~/.npmrc`, `~/.aws/credentials`, `~/.ssh/`, etc.).

---

## Reading the Output

### The Scan Overview Table

Every scan produces a table showing all 10 modules at a glance:

```
  ┌────────────────────────────────────┬──────────────────┬────────────┐
  │ Module                             │      Status      │    Scanned │
  ├────────────────────────────────────┼──────────────────┼────────────┤
  │ GitHub Actions Workflows           │      CLEAR       │    3 items │
  │ Trivy Binary Installation          │      CLEAR       │          — │
  │ npm CanisterWorm Packages          │      CLEAR       │   14 items │
  │ LiteLLM PyPI Compromise            │      CLEAR       │    2 items │
  │ Docker / Container Images          │      CLEAR       │    1 items │
  │ System Persistence Artifacts       │      CLEAR       │          — │
  │ C2 / Network IOCs                  │    1 finding     │  412 items │
  │ Kubernetes IOCs                    │      CLEAR       │          — │
  │ Git History & Exfiltration         │      CLEAR       │    1 items │
  │ Credential Exposure Assessment     │      CLEAR       │    2 items │
  └────────────────────────────────────┴──────────────────┴────────────┘
```

**Scanned** shows the number of relevant items each module examined (workflow files, npm packages, text files, repos, etc.) — not the total files walked. Modules that don't apply to the current scan (e.g. Trivy Binary without `--system`) show `—`.

### Findings

Each finding is presented as a labelled card:

```
  ┌────────────────────────────────────────────────────────────────────┐
  │ CRITICAL  trivy-action using compromised tag range                  │
  ├────────────────────────────────────────────────────────────────────┤
  │ Detail    Tag v0.28.0 was force-pushed to malicious code. If this  │
  │           workflow ran 2026-03-19 17:43 – 2026-03-20 05:40 UTC,   │
  │           secrets were stolen.                                      │
  │ File      .github/workflows/ci.yml                                  │
  │ Evidence  uses: aquasecurity/trivy-action@v0.28.0                  │
  │ Action    Pin to v0.35.0 or SHA 57a97c7e... Rotate ALL secrets.    │
  └────────────────────────────────────────────────────────────────────┘
```

### Severity Levels

| Severity | Meaning |
|----------|---------|
| **CRITICAL** | Confirmed compromised component or active malware. Immediate action required. |
| **HIGH** | Strong indicator that warrants urgent investigation — e.g. C2 domain in source code, compromised version range used |
| **MEDIUM** | Potential exposure requiring review — e.g. mutable Actions tag, LiteLLM dependency without pinned version |
| **LOW** | Minor risk item — e.g. safe tag used but still mutable |
| **INFO** | Informational — e.g. SHA-pinned Actions reference that should be manually verified |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Findings at HIGH, MEDIUM, or LOW severity |
| `2` | CRITICAL findings — confirmed compromised components |

Use exit code `2` as a hard CI/CD gate; exit code `1` as a warning that requires human review.

---

## What Organisations Should Do

### If you get CRITICAL findings

1. **Rotate all secrets immediately.** Any credentials accessible to the compromised component — cloud provider keys, npm tokens, Docker registry credentials, SSH keys, API tokens, Kubernetes service account tokens — must be treated as stolen.
2. **Search your GitHub organisation** for repositories named `tpcp-docs`. This is where TeamPCP staged exfiltrated credentials.
3. **Remove compromised components** — delete malicious binaries, downgrade affected packages, pin GitHub Actions to safe commit SHAs.
4. **Check every CI runner and developer machine** for persistence artifacts: `sysmon.py`, `pgmon.service`, `/tmp/pglog`, `/tmp/.pg_state`.
5. **Block TeamPCP C2 infrastructure** at your network perimeter: `scan.aquasecurtiy.org`, `45.148.10.212`, `45.148.10.122`, `checkmarx.zone`, `recv.hackmoltrepeat.com`, and the ICP canister endpoint.
6. **Audit Kubernetes clusters** for DaemonSets `host-provisioner-iran` and `host-provisioner-std` in `kube-system`.

### If you get HIGH findings

Investigate the specific finding. Determine whether the flagged component was active during the attack window (19–24 March 2026). If it was, treat it as a CRITICAL and follow the steps above.

### If you are clear

No indicators of exposure were found for the checks run. Consider running with `--system` if you haven't already, and scanning any developer machines and CI runners that were active during the attack window.

---

## CI/CD Integration

Add the scanner to your pipeline to gate deployments while the incident is active:

```yaml
# GitHub Actions
- name: TeamPCP Exposure Check
  run: |
    python3 teampcp_scanner.py --scan-path . --json > teampcp_results.json
    if [ $? -eq 2 ]; then
      echo "::error::CRITICAL TeamPCP exposure detected — pipeline halted"
      exit 1
    fi
```

```bash
# Pre-commit or pre-push hook
python3 teampcp_scanner.py --scan-path . || exit 1
```

---

## IOC Database

Every IOC is verified against published primary sources and annotated inline with its provenance (`[GHSA]`, `[CS]`, `[SS]`, `[DD]`, `[AK]`, `[WZ]`, `[MS]`, `[SafeDep]`).

| Category | Count | Sources |
|----------|-------|---------|
| Trivy binary SHA256 hashes | 32 | GHSA (26), Wiz (6) |
| Docker image digests | 15 | GHSA |
| Malicious Git commit SHAs | 9 | GHSA, StepSecurity, CrowdStrike |
| C2 domains and IPs | 14 | CrowdStrike, StepSecurity, Datadog, Microsoft, Wiz, Aikido, SafeDep |
| Compromised npm packages | 66+ | Endor Labs, JFrog, Socket.dev, Datadog |
| LiteLLM file hashes | 3 | Snyk |
| System persistence paths | 10+ | CrowdStrike, StepSecurity, Datadog, Aikido |
| Kubernetes IOC names | 5 | StepSecurity, Datadog, Aikido |

---

## References

- [GHSA-69fq-xp46-6x23 — Official GitHub Security Advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- [CrowdStrike — From Scanner to Stealer](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/)
- [StepSecurity — Trivy Compromised a Second Time](https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release)
- [StepSecurity — CanisterWorm Analysis](https://www.stepsecurity.io/blog/canisterworm-how-a-self-propagating-npm-worm-is-spreading-backdoors-across-the-ecosystem)
- [Datadog Security Labs — LiteLLM Compromised](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)
- [Microsoft — Detection and Defence Guidance](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)
- [Wiz — Trivy Compromised by TeamPCP](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack)
- [Snyk — Poisoned Scanner Backdooring LiteLLM](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/)
- [Endor Labs — CanisterWorm Package List](https://www.endorlabs.com/learn/canisterworm)
- [JFrog — CanisterWorm Research](https://research.jfrog.com/post/canister-worm/)
- [Aikido — Kubernetes Wiper Targeting Iran](https://www.aikido.dev/blog/teampcp-stage-payload-canisterworm-iran)

---

## License

MIT

---

## Need Help?

**[Strand Intelligence](https://strandintelligence.com)** builds DFIR automation for security teams. If your organisation needs hands-on incident response support, deeper forensic investigation of potential TeamPCP exposure, or purpose-built detection and response tooling, get in touch:

**will@strandintelligence.com**

We build software to support incident response across business email compromise, ransomware, infostealer, and cloud compromise cases.
