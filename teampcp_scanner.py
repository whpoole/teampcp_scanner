#!/usr/bin/env python3
"""
teampcp-scanner: Detect exposure to the TeamPCP/Trivy supply chain attack (CVE-2026-33634)

A comprehensive, zero-dependency scanner that checks for all known attack vectors from the
March 2026 TeamPCP campaign: compromised Trivy binaries, GitHub Actions poisoning,
CanisterWorm npm worm, LiteLLM PyPI backdoor, system persistence artifacts, C2 IOCs,
Kubernetes wiper components, and credential exposure.

Usage:
    python3 teampcp_scanner.py                          # Scan current directory + system
    python3 teampcp_scanner.py --scan-path /my/repo     # Scan specific path
    python3 teampcp_scanner.py --system                 # Include deep system checks
    python3 teampcp_scanner.py --json                   # JSON output
    python3 teampcp_scanner.py --markdown               # Markdown report
    python3 teampcp_scanner.py --self-test              # Verify scanner with test fixtures

References:
    - CVE-2026-33634 / GHSA-69fq-xp46-6x23
    - CrowdStrike: From Scanner to Stealer
    - StepSecurity: CanisterWorm Analysis
    - Datadog Security Labs: LiteLLM Compromise
    - Microsoft Security Blog: Detection Guidance

License: MIT
"""

from __future__ import annotations

import abc
import argparse
import concurrent.futures
import dataclasses
import enum
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

__version__ = "1.0.0"
__author__ = "Strand Security"

# ═══════════════════════════════════════════════════════════════════════════════
# IOC DATABASE
# Last updated: 2026-03-25
# Sources: GHSA-69fq-xp46-6x23, CrowdStrike, StepSecurity, Datadog, Microsoft,
#          Palo Alto Networks, Wiz, Endor Labs, JFrog, Socket.dev, ramimac.me/teampcp
# ═══════════════════════════════════════════════════════════════════════════════

# --- Malicious Trivy v0.69.4 Binary Hashes (SHA256) ---
# Keys are SHA256 hashes, values are platform descriptions
#
# Source: GHSA-69fq-xp46-6x23 (archive hashes) — these are the authoritative hashes
#         from the official GitHub Security Advisory.
# Source: Wiz blog (raw binary hashes) — single-source, marked accordingly.
MALICIOUS_TRIVY_BINARY_HASHES: Dict[str, str] = {
    # Archive hashes — Source: GHSA-69fq-xp46-6x23
    "c5b16c42dbd2a1494141cd651a406ec9094d5031a421c0aa624c4d139ae81239": "FreeBSD-64bit.tar.gz [GHSA]",
    "cff74e3e9ac0cda2078d31800d8fcad832d7b52c9920b085054d1e96dacff8a3": "Linux-32bit.deb [GHSA]",
    "55047c55a5ceab6d80b13884b4a4e8cd27a0bab7a218a952a00aae9e05f16f80": "Linux-32bit.rpm [GHSA]",
    "ba04ba6a0c028cde17599c8ddaefdb854055c5a23c595e06630732002ea59a76": "Linux-32bit.tar.gz [GHSA]",
    "0ca60dd18178d1c79d59cc06be12c540c121a4aea467484244667131aa13c311": "Linux-64bit.deb [GHSA]",
    "a5696321a6c93071f46c8bb8cbd0a8d2bce6d1860cc3c109247a4e8b64ebd317": "Linux-64bit.rpm [GHSA]",
    "385d498d18a3a7c67878ca7322716f9da25683eb1a4bf9e9592da0d5f2ab09f6": "Linux-64bit.tar.gz [GHSA]",
    "8f0c7b92b251c61cbca2add06c676dd21fde8fbb2d0cd6616383fae29b21756a": "Linux-ARM.deb [GHSA]",
    "c5df9d1bc6275711b2884a9ed4aacfe4e10dbe3c8f6c79df59126fd0e6dcd83f": "Linux-ARM.rpm [GHSA]",
    "f7a9bbfec8add36c548add4d875848b8b57c21fabe236d115f1c49113d12b332": "Linux-ARM.tar.gz [GHSA]",
    "9a833d68a49ec6d44bc50fb9ff3b184bafb0edc913e1293daebe51d334676a70": "Linux-ARM64.deb [GHSA]",
    "451ce0c4deb620894d07a2f4a37c8ea3b7a4f9b6d111651b4ac3bcc737b0fac0": "Linux-ARM64.rpm [GHSA]",
    "e401ae1e6d2442fa9a0c79dc0f3b0457ecfebf74a9c0a920159c49437f663aef": "Linux-ARM64.tar.gz [GHSA]",
    "284622577cf6a7c58704de60194205f765fcef432934c200b462ef0290aa5f57": "Linux-PPC64LE.deb [GHSA]",
    "5fac89e66d70cadec5c0e30c0b0cf8bf38c145cbf06422d40d076985195e1dd6": "Linux-PPC64LE.rpm [GHSA]",
    "52518d441fd6dd25fa5126683a330592d3be80d5ce3fb9e0b1becb806ff4f857": "Linux-PPC64LE.tar.gz [GHSA]",
    "62585efcdc7767f3fe0b9ae2897fe03bf331934492fd7a5da46f14fd7bf705c8": "Linux-s390x.deb [GHSA]",
    "107be2081bdc3ddad2889ae037ab2ad6bbd214fb9a43eaa25390d00411d1c7dd": "Linux-s390x.rpm [GHSA]",
    "16c855c398a8b185a907790054b70164358844a893bf9965651b88d6967c7c0a": "Linux-s390x.tar.gz [GHSA]",
    "90d61cf37355b89fae9ff84867100e1721c1876007ef1771e465ce5a721141ad": "macOS-64bit.tar.gz [GHSA]",
    "1dc871b02cd7a1fd80babb1b8762a2fd9cc2b735d4d3759d012626de3ccc7a5b": "macOS-ARM64.tar.gz [GHSA]",
    "0376b98064636c30f5fbe60fb3b1225516e23e88dd7e909937f81d9265292e7d": "Windows-64bit.zip [GHSA]",
    # Standalone binary hashes — Source: GHSA-69fq-xp46-6x23 (these 4 are in the advisory)
    "822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0": "Linux amd64 standalone [GHSA]",
    "e64e152afe2c722d750f10259626f357cdea40420c5eedae37969fbf13abbecf": "Linux arm64 standalone [GHSA]",
    "d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c": "Linux s390x standalone [GHSA]",
    "ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c": "Linux ppc64le standalone [GHSA]",
    # Raw binary hashes — Source: Wiz blog only (single-source, cross-confirmed where
    # they match GHSA standalone hashes above — the 4 above also appear in Wiz)
    "f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d": "Linux-32bit raw [Wiz]",
    "bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7": "Linux-ARM raw [Wiz]",
    "887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073": "FreeBSD-64bit raw [Wiz]",
    "e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1113243": "macOS-64bit raw [Wiz]",
    "6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538": "macOS-ARM64 raw [Wiz]",
    "0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349": "Windows-64bit raw [Wiz]",
}

# --- Malicious entrypoint.sh hashes ---
# Source: CrowdStrike blog + Socket.dev blog (confirmed by both)
MALICIOUS_ENTRYPOINT_HASH = "18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a"
# Source: CrowdStrike blog only (single-source)
LEGITIMATE_ENTRYPOINT_HASH = "07500e81693c06ef7ac6bf210cff9c882bcc11db5f16b5bded161218353ba4da"
MALICIOUS_ENTRYPOINT_SIZE = 17592
LEGITIMATE_ENTRYPOINT_SIZE = 2855

# --- Malicious Docker Image Digests ---
# Multi-arch manifest digests: Source: GHSA-69fq-xp46-6x23, GitHub Discussion #10425
# Per-architecture digests: Source: GHSA-69fq-xp46-6x23
MALICIOUS_DOCKER_DIGESTS: FrozenSet[str] = frozenset({
    # v0.69.4 — manifest digest confirmed by GHSA + Discussion #10425
    "sha256:27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3",  # manifest [GHSA]
    "sha256:12c702212dee1cbec9471e9261501a3335963321fe76e60e5a715b5acd3c40a2",  # linux/amd64 [GHSA]
    "sha256:2d7cee41048988eec27615412e7c6e2e21046f2b5faa888c24e11ca6764058ed",  # linux/arm64 [GHSA]
    "sha256:ae3494bd6ae860d7727116681bd09fc7b20dc994ec7a8105738f0a623ea93427",  # linux/ppc64le [GHSA]
    "sha256:43f46547efd488e56dcf862ed4d7cc342730a803f8d5bec5cac443028fefabef",  # linux/s390x [GHSA]
    "sha256:cc464a3961e1dbe145c75343b55c2f446e08b821782ec993728c4222b0d85589",  # signature [GHSA]
    # v0.69.5 — manifest digest confirmed by Discussion #10425
    "sha256:5aaa1d7cfa9ca4649d6ffad165435c519dc836fa6e21b729a2174ad10b057d2b",  # manifest [GHSA]
    # NOTE: sha256:f69a8a41... (ramimac Docker Hub push digest) excluded — contradicts GHSA
    #       advisory which attributes 5aaa1d7c... to v0.69.5; omitted pending confirmation.
    "sha256:95ff680103570179feb0c6667a9b9b2d98c53fa5a9a451265036810390bbe70a",  # linux/arm64 [GHSA]
    "sha256:4f7a06bb51714713ab308d2f8125f3b09ee1c3ffbba1a5ffd0cc80da95fbb6cc",  # linux/ppc64le [GHSA]
    "sha256:edef8e5816eced552a909b878ff262c0c47776d3297bcc23796ad4cce1e85414",  # linux/s390x [GHSA]
    # v0.69.6 — manifest digest confirmed by Discussion #10425
    "sha256:425cd3e1a2846ac73944e891250377d2b03653e6f028833e30fc00c1abbc6d33",  # manifest [GHSA]
    "sha256:dd8beb3b40df080b3fd7f9a0f5a1b02f3692f65c68980f46da8328ce8bb788ef",  # linux/amd64 [GHSA]
    "sha256:4b22cedea58780ff76735c3e08b9ee8cb5d06c908ffa868152f11d45349eb696",  # linux/arm64 [GHSA]
    "sha256:9efd59534d2b6b81b8b7a0eeb3ad0e74015f358650e24b9dab00c900d3118593",  # linux/ppc64le [GHSA]
    "sha256:5e5fb53cf4ce5555171ff5206302ba2f4f66f5381bbf673c354c87a925473f07",  # linux/s390x [GHSA]
})

# --- Malicious Git Commit SHAs ---
# Source attribution per commit. The full list of 96 malicious commits is at:
# https://github.com/step-security/trivy-compromise-scanner/blob/main/internal/scanner/patterns.go
MALICIOUS_COMMIT_SHAS: FrozenSet[str] = frozenset({
    # trivy-action — Source: GHSA + StepSecurity + Socket.dev
    "e0198fd2b6e1679e36d32933941182d9afa82f6f",  # All 76 tags pointed here [GHSA, StepSecurity]
    "ddb9da4475c1cef7d5389062bdfdfbdbd1394648",  # tag 0.34.2 [GHSA, StepSecurity]
    "f77738448eec70113cf711656914b61905b3bd47",  # tag 0.0.1 [GHSA]
    "3c615ac0f29e743eda8863377f9776619fd2db76",  # tag 0.0.11 [GHSA]
    "a9bc513ea7989e3234b395cafb8ed5ccc3755636",  # tag 0.34.1 [GHSA]
    "ab6606b76e5a054be08cab3d07da323e90e751e8",  # tag 0.34.0 [GHSA]
    # setup-trivy — Source: GHSA + StepSecurity
    "8afa9b9f9183b4e00c46e2b82d34047e3c177bd0",  # All setup-trivy tags [GHSA, StepSecurity]
    # trivy repo — Source: GHSA + CrowdStrike
    "1885610c6a34811c8296416ae69f568002ef11ec",  # Malicious release commit [GHSA, CrowdStrike]
    "70379aad1a8b40919ce8b382d3cd7d0315cde1d0",  # Rogue actions/checkout [GHSA, CrowdStrike]
    # NOTE: KICS SHA (8e20c7a6...) is handled separately via KICS_COMPROMISED_COMMIT/
    #       _KICS_RE in GitHubActionsScanner — not included here to avoid dead code.
    # NOTE: LiteLLM SHAs are in LITELLM_MALICIOUS_COMMIT_SHAS below; checked via
    #       git cat-file in GitHistoryScanner (not action pins).
    # NOTE: 0e22ec8d... (ramimac only) excluded — secondary sources confirm 8e20c7a6...
})

# --- Malicious LiteLLM Repository Commit SHAs ---
# These are commits to BerriAI/litellm and BerriAI/litellm-skills that stole secrets.
# Checked via git cat-file in GitHistoryScanner (not action pins — no trivy-action involved).
# Source: ramimac.me/teampcp
LITELLM_MALICIOUS_COMMIT_SHAS: FrozenSet[str] = frozenset({
    "fcaa823de07878d0d98e97f6f5552c0e2ac00d2f",  # BerriAI/litellm secrets exfil
    "81c851cc00313c44effd421712523f294b18391e",  # BerriAI/litellm-skills secrets exfil
})

# Safe commit SHAs for pinning
SAFE_TRIVY_ACTION_SHA = "57a97c7e7821a5776cebc9bb87c984fa69cba8f1"
SAFE_SETUP_TRIVY_SHA = "3fb12ec"

# --- Compromised npm Packages (CanisterWorm) ---
# Dict of package_name -> list of known compromised versions (None = all versions suspect)
COMPROMISED_NPM_PACKAGES: Dict[str, Optional[List[str]]] = {
    # @emilgroup scope (40+ packages)
    "@emilgroup/account-sdk": ["1.41.1", "1.41.2"],
    "@emilgroup/account-sdk-node": ["1.40.1", "1.40.2"],
    "@emilgroup/accounting-sdk": None,
    "@emilgroup/accounting-sdk-node": ["1.26.1", "1.26.2"],
    "@emilgroup/api-documentation": ["1.19.1", "1.19.2"],
    "@emilgroup/auth-sdk": ["1.25.1", "1.25.2"],
    "@emilgroup/auth-sdk-node": ["1.21.1", "1.21.2"],
    "@emilgroup/billing-sdk": ["1.56.1", "1.56.2"],
    "@emilgroup/billing-sdk-node": ["1.57.1", "1.57.2"],
    "@emilgroup/changelog-sdk-node": None,
    "@emilgroup/claim-sdk": ["1.41.1", "1.41.2"],
    "@emilgroup/claim-sdk-node": ["1.39.1", "1.39.2"],
    "@emilgroup/commission-sdk": None,
    "@emilgroup/commission-sdk-node": None,
    "@emilgroup/customer-sdk": ["1.54.1", "1.54.2", "1.54.3", "1.54.4", "1.54.5"],  # JFrog reports up to .5
    "@emilgroup/customer-sdk-node": ["1.55.1", "1.55.2"],
    "@emilgroup/discount-sdk": ["1.5.1", "1.5.2", "1.5.3"],
    "@emilgroup/discount-sdk-node": None,
    "@emilgroup/document-sdk": ["1.45.1", "1.45.2"],
    "@emilgroup/document-sdk-node": ["1.43.1", "1.43.2", "1.43.3", "1.43.4", "1.43.5", "1.43.6"],  # JFrog reports up to .6
    "@emilgroup/document-uploader": ["0.0.10", "0.0.11", "0.0.12"],
    "@emilgroup/docxtemplater-util": ["1.1.2", "1.1.3", "1.1.4"],
    "@emilgroup/gdv-sdk": ["2.6.1", "2.6.2"],
    "@emilgroup/gdv-sdk-node": None,
    "@emilgroup/insurance-sdk": ["1.97.1", "1.97.2", "1.97.3", "1.97.4", "1.97.5", "1.97.6"],  # JFrog reports up to .6
    "@emilgroup/insurance-sdk-node": ["1.95.1", "1.95.2"],
    "@emilgroup/notification-sdk-node": ["1.4.1", "1.4.2"],
    "@emilgroup/numbergenerator-sdk-node": ["1.3.1", "1.3.2", "1.3.3"],
    "@emilgroup/partner-portal-sdk": ["1.1.1", "1.1.2", "1.1.3"],
    "@emilgroup/partner-portal-sdk-node": ["1.1.1", "1.1.2"],
    "@emilgroup/partner-sdk": None,
    "@emilgroup/partner-sdk-node": ["1.19.1", "1.19.2"],
    "@emilgroup/payment-sdk": ["1.15.1", "1.15.2"],
    "@emilgroup/payment-sdk-node": ["1.23.1", "1.23.2"],
    "@emilgroup/process-manager-sdk": None,
    "@emilgroup/process-manager-sdk-node": ["1.13.1", "1.13.2"],
    "@emilgroup/public-api-sdk": ["1.33.1", "1.33.2"],
    "@emilgroup/public-api-sdk-node": ["1.35.1", "1.35.2"],
    "@emilgroup/setting-sdk": ["0.2.1", "0.2.2", "0.2.3"],
    "@emilgroup/setting-sdk-node": None,
    "@emilgroup/task-sdk": ["1.0.2", "1.0.3", "1.0.4"],
    "@emilgroup/task-sdk-node": ["1.0.2", "1.0.3", "1.0.4"],
    "@emilgroup/tenant-sdk": ["1.34.1", "1.34.2"],
    "@emilgroup/tenant-sdk-node": ["1.33.1", "1.33.2"],
    "@emilgroup/translation-sdk-node": ["1.1.1", "1.1.2"],
    # @opengov scope
    "@opengov/form-renderer": ["0.2.20"],
    "@opengov/form-builder": ["0.12.3"],
    "@opengov/form-utils": ["0.7.2"],
    "@opengov/ppf-backend-types": ["1.141.2"],
    "@opengov/ppf-eslint-config": ["0.1.11"],
    "@opengov/qa-record-types-api": ["1.0.3"],
    # @teale.io scope
    "@teale.io/eslint-config": ["1.8.9", "1.8.10", "1.8.11", "1.8.12", "1.8.13", "1.8.14", "1.8.15", "1.8.16"],
    # Other scopes
    "@leafnoise/mirage": ["2.0.3"],
    "@airtm/uuid-base32": ["1.0.2"],
    "@pypestream/floating-ui-dom": ["2.15.1"],
    "@virtahealth/substrate-root": ["1.0.1"],
    # Standalone packages
    "jest-preset-ppf": ["0.0.2"],
    "babel-plugin-react-pure-component": ["0.1.6"],
    "eslint-config-service-users": ["0.0.3"],
    "opengov-k6-core": ["1.0.2"],
    "cit-playwright-tests": ["1.0.1"],
    "react-leaflet-marker-layer": ["0.1.5"],
    "react-leaflet-cluster-layer": ["0.0.4"],
    "eslint-config-ppf": ["0.128.2"],
    "react-autolink-text": ["2.0.1"],
    "react-leaflet-heatmap-layer": ["2.0.1"],
}

COMPROMISED_NPM_SCOPES: FrozenSet[str] = frozenset({
    "@emilgroup", "@opengov", "@teale.io", "@leafnoise",
    "@airtm", "@pypestream", "@virtahealth",
})

# --- LiteLLM IOCs ---
LITELLM_COMPROMISED_VERSIONS = {"1.82.7", "1.82.8"}
# Source: Snyk (verbatim match confirmed)
LITELLM_PTH_HASH = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
LITELLM_PROXY_HASH = "a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b"
LITELLM_SYSMON_HASH = "6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"

# --- C2 / Network IOCs ---
# Each entry: (ioc_string, description)
# Source attribution in comments. Multi-source IOCs listed first.
C2_IOCS: List[Tuple[str, str]] = [
    # Multi-source confirmed (CrowdStrike, StepSecurity, Datadog, Microsoft, Wiz)
    ("scan.aquasecurtiy.org", "Primary C2 domain — typosquat of aquasecurity [CS,SS,DD,MS,WZ]"),
    ("aquasecurtiy", "C2 domain fragment — catches partial references [CS,SS,DD,MS,WZ]"),
    # Multi-source confirmed (CrowdStrike, StepSecurity, Datadog, Aikido, Wiz)
    ("tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io", "ICP blockchain C2 [CS,SS,DD,AK,WZ]"),
    ("tdtqy-oyaaa-aaaae-af2dq-cai", "ICP canister ID [CS,SS,DD,AK,WZ]"),
    # IP addresses (different sources report different IPs in same /24)
    ("45.148.10.212", "C2 IP [Wiz]"),
    ("45.148.10.122", "C2 IP [Microsoft]"),
    # Single-source but high confidence (Datadog Security Labs — detailed technical analysis)
    ("models.litellm.cloud", "LiteLLM exfiltration endpoint [DD]"),
    ("checkmarx.zone", "Secondary C2/payload server [DD]"),
    # Cloudflare tunnel domains — confirmed by Datadog + Aikido
    ("souls-entire-defined-routes.trycloudflare.com", "Cloudflare tunnel C2 [DD,AK]"),
    ("investigation-launches-hearings-copying.trycloudflare.com", "Cloudflare tunnel C2 [DD,AK]"),
    ("championships-peoples-point-cassette.trycloudflare.com", "Cloudflare tunnel C2 [DD,AK]"),
    # Single-source Cloudflare tunnels
    ("create-sensitivity-grad-sequence.trycloudflare.com", "Cloudflare tunnel C2 [SafeDep]"),
    ("plug-tab-protective-relay.trycloudflare.com", "Cloudflare tunnel C2 [WZ]"),
    # Phase 1 exfiltration — Source: SafeDep blog
    ("recv.hackmoltrepeat.com", "Phase 1 PAT theft exfiltration [SafeDep]"),
    # KICS C2 server — Source: ramimac.me/teampcp
    ("83.142.209.11", "KICS chain C2 IP — resolves checkmarx.zone [ramimac]"),
]

# --- System Persistence Paths ---
# Each path is annotated with the source(s) that document it.
# [CS]=CrowdStrike, [SS]=StepSecurity, [DD]=Datadog, [AK]=Aikido, [WZ]=Wiz
PERSISTENCE_PATHS_LINUX = [
    # Trivy/LiteLLM sysmon variants
    "~/.config/sysmon/sysmon.py",           # [DD] — LiteLLM variant (note: extra subdir)
    "~/.config/sysmon.py",                  # [CS,WZ] — Trivy variant
    # Systemd user-level persistence
    "~/.config/systemd/user/sysmon.service", # [DD] — Description: "System Telemetry Service"
    "~/.config/systemd/user/sysmon.py",     # [DD] — loader co-located with service
    "~/.config/systemd/user/pgmon.service", # [SS] — CanisterWorm persistence
    # CanisterWorm backdoor
    "~/.local/share/pgmon/service.py",      # [SS] — Python implant
    # System-level systemd (require root / advanced persistence)
    "/etc/systemd/system/internal-monitor.service",  # [AK] — Description: "System Monitor"
    "/etc/systemd/system/pgmonitor.service",         # [AK] — Description: "Postgres Monitor Service"
    # Advanced persistence payloads
    "/var/lib/svc_internal/runner.py",      # [AK]
    "/var/lib/pgmon/pgmon.py",              # [AK]
]

PERSISTENCE_PATHS_MACOS = [
    # Same config paths as Linux (Python-based, cross-platform code)
    "~/.config/sysmon/sysmon.py",           # [DD]
    "~/.config/sysmon.py",                  # [CS,WZ]
    # macOS-specific paths (defensive check — no source documents
    # macOS-specific persistence, but the malware Python code uses
    # os.path.expanduser which resolves these on macOS)
    "~/Library/Application Support/sysmon/sysmon.py",
    "~/Library/Application Support/pgmon/service.py",
]

# Staging artifacts — cross-platform
# Source: [CS,SS,DD,AK,WZ] — confirmed by 5+ sources
STAGING_PATHS = [
    "/tmp/pglog",       # Second-stage binary drop [CS,SS,DD,AK,WZ]
    "/tmp/.pg_state",   # Download state tracker [SS,DD,AK]
]

# Kubernetes IOC strings
# Source: [SS,DD,AK] — confirmed by StepSecurity, Datadog, Aikido
K8S_IOC_DAEMONSETS = {"host-provisioner-iran", "host-provisioner-std"}
# Source: [DD,AK] — confirmed by Datadog, Aikido
K8S_IOC_CONTAINERS = {"kamikaze", "provisioner"}
# Source: [DD] — Datadog only
K8S_IOC_POD_PREFIX = "node-setup-"

# Compromised trivy-action tag range (inclusive)
TRIVY_ACTION_COMPROMISED_RANGE = ((0, 0, 1), (0, 34, 2))  # 0.0.1 to 0.34.2
SETUP_TRIVY_COMPROMISED_RANGE = ((0, 2, 0), (0, 2, 5))  # v0.2.0 to v0.2.5

# File extensions to scan for C2/IOC references
TEXT_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".rb", ".java",
    ".yml", ".yaml", ".json", ".toml", ".cfg", ".conf", ".ini", ".env",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".tf", ".hcl", ".dockerfile", ".xml", ".html", ".css", ".scss",
    ".md", ".txt", ".rst", ".lock", ".sum", ".mod",
})

SKIP_DIRS = frozenset({
    ".git", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    ".eggs", "*.egg-info", ".cache", ".gradle", ".idea", ".vscode",
    "dist", "build", ".terraform",
})

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


# ═══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclasses.dataclass
class Finding:
    category: str
    severity: Severity
    title: str
    detail: str
    file_path: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity.name,
            "title": self.title,
            "detail": self.detail,
            "file_path": self.file_path,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclasses.dataclass
class CategoryResult:
    name: str
    display_name: str
    status: str  # CLEAR, FINDINGS, ERROR, SKIPPED
    findings: List[Finding]
    scan_duration: float
    items_scanned: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "scan_duration_ms": round(self.scan_duration * 1000),
            "items_scanned": self.items_scanned,
        }


@dataclasses.dataclass
class ScanReport:
    timestamp: str
    scanner_version: str
    platform: str
    scan_target: Optional[str]
    system_scan: bool
    categories: List[CategoryResult]
    risk_score: float
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "scanner_version": self.scanner_version,
            "platform": self.platform,
            "scan_target": self.scan_target,
            "system_scan": self.system_scan,
            "categories": [c.to_dict() for c in self.categories],
            "summary": self.summary,
        }


@dataclasses.dataclass
class ScanConfig:
    scan_path: Optional[Path] = None
    system_scan: bool = False
    verbose: bool = False
    output_json: bool = False
    output_markdown: bool = False
    self_test: bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# COLOR / TERMINAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

class Color:
    """ANSI color helper that degrades gracefully."""

    def __init__(self):
        self.enabled = self._detect()

    def _detect(self) -> bool:
        if os.environ.get("NO_COLOR"):
            return False
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False
        if platform.system() == "Windows":
            return self._win_vt()
        return True

    @staticmethod
    def _win_vt() -> bool:
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
        except Exception:
            return False

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def red(self, t: str) -> str: return self._wrap("0;31", t)
    def red_bold(self, t: str) -> str: return self._wrap("1;31", t)
    def yellow(self, t: str) -> str: return self._wrap("1;33", t)
    def green(self, t: str) -> str: return self._wrap("0;32", t)
    def green_bold(self, t: str) -> str: return self._wrap("1;32", t)
    def cyan(self, t: str) -> str: return self._wrap("0;36", t)
    def dim(self, t: str) -> str: return self._wrap("2", t)
    def bold(self, t: str) -> str: return self._wrap("1", t)

    def severity(self, sev: Severity) -> str:
        name = sev.name
        if sev == Severity.CRITICAL:
            return self.red_bold(name)
        elif sev == Severity.HIGH:
            return self.red(name)
        elif sev == Severity.MEDIUM:
            return self.yellow(name)
        elif sev == Severity.LOW:
            return self.cyan(name)
        return self.dim(name)

    def status(self, s: str) -> str:
        if s == "CLEAR":
            return self.green_bold(s)
        elif s == "FINDINGS":
            return self.red_bold(s)
        elif s == "SKIPPED":
            return self.dim(s)
        return self.yellow(s)


C = Color()


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def sha256_file(path: str, chunk_size: int = 65536) -> Optional[str]:
    """Compute SHA256 hash of a file using streaming reads."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def safe_read_text(path: str, max_bytes: int = MAX_FILE_SIZE) -> Optional[str]:
    """Read a text file safely, handling encoding errors and size limits."""
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, PermissionError, UnicodeDecodeError):
        return None


def is_binary_file(path: str) -> bool:
    """Quick check if a file appears to be binary."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
            return b"\x00" in chunk
    except (OSError, PermissionError):
        return True


def parse_version(v: str) -> Optional[Tuple[int, ...]]:
    """Parse a dotted version string into a numeric tuple."""
    v = re.sub(r"^v", "", v.strip())
    parts = []
    for p in v.split("."):
        m = re.match(r"(\d+)", p)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts) if parts else None


def version_in_range(version_str: str, low: Tuple[int, ...], high: Tuple[int, ...]) -> bool:
    """Check if a version is within an inclusive range."""
    v = parse_version(version_str)
    if not v:
        return False
    # Pad to same length
    max_len = max(len(v), len(low), len(high))
    v_pad = v + (0,) * (max_len - len(v))
    lo_pad = low + (0,) * (max_len - len(low))
    hi_pad = high + (0,) * (max_len - len(high))
    return lo_pad <= v_pad <= hi_pad


def scan_binary_for_bytes(path: str, needle: bytes, chunk_size: int = 65536) -> bool:
    """Scan a binary file for a byte pattern using sliding window."""
    overlap = len(needle) - 1
    try:
        with open(path, "rb") as f:
            prev_tail = b""
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buf = prev_tail + chunk
                if needle in buf:
                    return True
                prev_tail = chunk[-overlap:] if overlap > 0 else b""
    except (OSError, PermissionError):
        pass
    return False


def run_cmd(cmd: List[str], timeout: int = 10) -> Optional[str]:
    """Run a command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def walk_files(root: Path, skip_dirs: Set[str] = None, max_depth: int = 20) -> List[str]:
    """Walk directory tree yielding file paths, respecting skip_dirs and depth."""
    if skip_dirs is None:
        skip_dirs = SKIP_DIRS
    results = []
    root_str = str(root)

    def _walk(dir_path: str, depth: int):
        if depth > max_depth:
            return
        try:
            entries = os.scandir(dir_path)
        except (PermissionError, OSError):
            return
        dirs_to_recurse = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_file():
                    results.append(entry.path)
                elif entry.is_dir():
                    if entry.name not in skip_dirs:
                        dirs_to_recurse.append(entry.path)
            except (PermissionError, OSError):
                continue
        for d in dirs_to_recurse:
            _walk(d, depth + 1)

    _walk(root_str, 0)
    return results


def is_self(filepath: str) -> bool:
    """Check if a file path refers to this scanner script itself."""
    try:
        return os.path.samefile(filepath, __file__)
    except (OSError, ValueError):
        return os.path.basename(filepath) == os.path.basename(__file__)


# ═══════════════════════════════════════════════════════════════════════════════
# BASE SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class BaseScanner(abc.ABC):
    category_name: str = ""
    display_name: str = ""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: List[Finding] = []
        self.items_scanned = 0

    def add_finding(self, severity: Severity, title: str, detail: str, **kwargs):
        self.findings.append(Finding(
            category=self.category_name,
            severity=severity,
            title=title,
            detail=detail,
            **kwargs,
        ))

    @abc.abstractmethod
    def scan(self) -> None:
        ...

    def run(self) -> CategoryResult:
        start = time.monotonic()
        status = "CLEAR"
        try:
            self.scan()
            if self.findings:
                status = "FINDINGS"
        except Exception as e:
            status = "ERROR"
            self.add_finding(Severity.INFO, "Scanner error", str(e))
        elapsed = time.monotonic() - start
        return CategoryResult(
            name=self.category_name,
            display_name=self.display_name,
            status=status,
            findings=self.findings,
            scan_duration=elapsed,
            items_scanned=self.items_scanned,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER 1: GitHub Actions
# ═══════════════════════════════════════════════════════════════════════════════

class GitHubActionsScanner(BaseScanner):
    category_name = "github_actions"
    display_name = "GitHub Actions Workflows"

    _USES_RE = re.compile(
        r'uses:\s*["\']?aquasecurity/(trivy-action|setup-trivy)@([^\s"\'#]+)',
        re.IGNORECASE,
    )
    _KICS_RE = re.compile(
        r'uses:\s*["\']?Checkmarx/kics-github-action@([^\s"\'#]+)',
        re.IGNORECASE,
    )
    _PRT_RE = re.compile(r'pull_request_target', re.IGNORECASE)

    # KICS action: all tags v1–v2.1.20 compromised 2026-03-23 12:58–16:50 UTC
    # Source: Checkmarx official, StepSecurity, KICS GitHub issue
    KICS_COMPROMISED_COMMIT = "8e20c7a67bb95632e2040327a355fb97e6014d29"

    def scan(self):
        root = self.config.scan_path or Path(".")
        workflow_files = []
        for fpath in walk_files(root):
            if "/.github/workflows/" in fpath.replace("\\", "/") or \
               "\\.github\\workflows\\" in fpath:
                if fpath.endswith((".yml", ".yaml")):
                    workflow_files.append(fpath)

        if not workflow_files:
            return

        for wf in workflow_files:
            self.items_scanned += 1
            content = safe_read_text(wf)
            if not content:
                continue
            rel = os.path.relpath(wf, str(root))

            # Check for trivy-action / setup-trivy
            for match in self._USES_RE.finditer(content):
                action = match.group(1)  # trivy-action or setup-trivy
                ref = match.group(2)     # tag, branch, or SHA

                # Is it a known malicious commit SHA?
                if ref.lower() in MALICIOUS_COMMIT_SHAS:
                    self.add_finding(
                        Severity.CRITICAL,
                        f"Known malicious {action} commit SHA",
                        f"Workflow pins to a known-compromised commit: {ref}",
                        file_path=rel,
                        evidence=match.group(0),
                        remediation=f"Pin to safe SHA: {SAFE_TRIVY_ACTION_SHA}" if "trivy-action" in action else f"Pin to safe SHA: {SAFE_SETUP_TRIVY_SHA}",
                    )
                    continue

                # Is it a full SHA (40 hex chars)? Use IGNORECASE: GitHub SHAs are lowercase
                # but uppercase is valid hex and should not be misclassified as a mutable tag.
                if re.match(r'^[0-9a-f]{40}$', ref, re.IGNORECASE):
                    # Pinned to SHA but not a known-bad one
                    self.add_finding(
                        Severity.INFO,
                        f"{action} pinned to SHA",
                        f"SHA-pinned reference (verify it is not compromised): {ref}",
                        file_path=rel,
                        evidence=match.group(0),
                        remediation="Verify this SHA against known-safe commits",
                    )
                    continue

                # It's a mutable tag - check version range
                if action == "trivy-action":
                    if version_in_range(ref, TRIVY_ACTION_COMPROMISED_RANGE[0], TRIVY_ACTION_COMPROMISED_RANGE[1]):
                        self.add_finding(
                            Severity.CRITICAL,
                            "trivy-action using compromised tag range",
                            f"Tag {ref} was force-pushed to malicious code (76 of 77 tags compromised). "
                            f"If this workflow ran between 2026-03-19 17:43 UTC and 2026-03-20 05:40 UTC, secrets may have been stolen.",
                            file_path=rel,
                            evidence=match.group(0),
                            remediation=f"Pin to v0.35.0 or commit SHA {SAFE_TRIVY_ACTION_SHA}. Rotate ALL secrets accessible to this workflow.",
                        )
                    elif ref == "0.35.0":
                        self.add_finding(
                            Severity.LOW,
                            "trivy-action using safe tag (but mutable)",
                            f"Tag {ref} was NOT compromised but is still a mutable tag reference.",
                            file_path=rel,
                            evidence=match.group(0),
                            remediation=f"Pin to commit SHA {SAFE_TRIVY_ACTION_SHA} for safety",
                        )
                    else:
                        self.add_finding(
                            Severity.MEDIUM,
                            "trivy-action using mutable tag",
                            f"Tag {ref} is a mutable reference. Could not determine if it was compromised.",
                            file_path=rel,
                            evidence=match.group(0),
                            remediation=f"Pin to commit SHA {SAFE_TRIVY_ACTION_SHA}",
                        )

                elif action == "setup-trivy":
                    if version_in_range(ref, SETUP_TRIVY_COMPROMISED_RANGE[0], SETUP_TRIVY_COMPROMISED_RANGE[1]):
                        self.add_finding(
                            Severity.CRITICAL,
                            "setup-trivy using compromised tag range",
                            f"Tag {ref} was force-pushed to malicious code (all 7 tags compromised). "
                            f"Exposure window: 2026-03-19 17:43 to 21:44 UTC.",
                            file_path=rel,
                            evidence=match.group(0),
                            remediation=f"Pin to v0.2.6 or commit SHA {SAFE_SETUP_TRIVY_SHA}. Rotate ALL secrets.",
                        )
                    elif ref == "v0.2.6" or ref == "0.2.6":
                        self.add_finding(
                            Severity.LOW,
                            "setup-trivy using safe tag (but mutable)",
                            f"Tag {ref} was NOT compromised but is still mutable.",
                            file_path=rel,
                            evidence=match.group(0),
                            remediation=f"Pin to commit SHA {SAFE_SETUP_TRIVY_SHA}",
                        )

            # Check for KICS GitHub Action (compromised 2026-03-23, all tags v1–v2.1.20)
            for kmatch in self._KICS_RE.finditer(content):
                ref = kmatch.group(1)
                if ref.lower() == self.KICS_COMPROMISED_COMMIT.lower():
                    self.add_finding(
                        Severity.CRITICAL,
                        "Known malicious kics-github-action commit SHA",
                        f"Workflow pins to the confirmed malicious KICS commit: {ref}",
                        file_path=rel,
                        evidence=kmatch.group(0),
                        remediation="Pin to a verified post-remediation SHA from the official Checkmarx/kics-github-action repository. Rotate all secrets.",
                    )
                elif re.match(r'^[0-9a-f]{40}$', ref, re.IGNORECASE):
                    self.add_finding(
                        Severity.INFO,
                        "kics-github-action pinned to SHA (verify safety)",
                        f"SHA-pinned reference — verify it is not the compromised commit ({self.KICS_COMPROMISED_COMMIT[:12]}...): {ref}",
                        file_path=rel,
                        evidence=kmatch.group(0),
                        remediation="Verify this SHA against the official Checkmarx repository post-remediation commits.",
                    )
                else:
                    # Any tag ref (v1, v2.1.0, etc.) was compromised
                    self.add_finding(
                        Severity.CRITICAL,
                        f"kics-github-action using compromised tag: {ref}",
                        "All Checkmarx/kics-github-action tags v1–v2.1.20 were force-pushed to "
                        "malicious code on 2026-03-23 12:58–16:50 UTC. If this workflow ran "
                        "during that window, secrets were stolen.",
                        file_path=rel,
                        evidence=kmatch.group(0),
                        remediation="Pin to a verified post-remediation SHA from the official Checkmarx/kics-github-action repository. Rotate all secrets accessible to this workflow.",
                    )

            # Check for pull_request_target (the original attack vector)
            if self._PRT_RE.search(content):
                # Only flag if this workflow also references trivy/aquasecurity/kics
                if re.search(r'aquasecurity|trivy|checkmarx/kics', content, re.IGNORECASE):
                    self.add_finding(
                        Severity.MEDIUM,
                        "pull_request_target with Trivy reference",
                        "This workflow uses pull_request_target (the attack vector used in the Trivy compromise) "
                        "and references Trivy/Aqua Security.",
                        file_path=rel,
                        remediation="Review this workflow for secrets exposure via pull_request_target",
                    )


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER 2: Trivy Binary
# ═══════════════════════════════════════════════════════════════════════════════

class TrivyBinaryScanner(BaseScanner):
    category_name = "trivy_binary"
    display_name = "Trivy Binary Installation"

    def _find_trivy_binaries(self) -> List[str]:
        paths = []
        # Check PATH
        which = shutil.which("trivy")
        if which:
            paths.append(which)

        # Platform-specific locations
        candidates = []
        system = platform.system()
        if system == "Darwin":
            candidates += [
                "/usr/local/bin/trivy",
                "/opt/homebrew/bin/trivy",
                str(Path.home() / ".local" / "bin" / "trivy"),
            ]
            # Homebrew cellar
            for cellar in ["/opt/homebrew/Cellar/trivy", "/usr/local/Cellar/trivy"]:
                if os.path.isdir(cellar):
                    for ver_dir in os.listdir(cellar):
                        p = os.path.join(cellar, ver_dir, "bin", "trivy")
                        candidates.append(p)
        elif system == "Linux":
            candidates += [
                "/usr/local/bin/trivy",
                "/usr/bin/trivy",
                "/snap/bin/trivy",
                str(Path.home() / ".local" / "bin" / "trivy"),
                str(Path.home() / "bin" / "trivy"),
            ]
        elif system == "Windows":
            for env_var in ["LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"]:
                base = os.environ.get(env_var, "")
                if base:
                    candidates.append(os.path.join(base, "trivy", "trivy.exe"))
                    candidates.append(os.path.join(base, "trivy.exe"))

        for c in candidates:
            if os.path.isfile(c) and c not in paths:
                paths.append(c)

        # Also check scan_path for downloaded trivy binaries
        if self.config.scan_path:
            for fpath in walk_files(self.config.scan_path):
                basename = os.path.basename(fpath).lower()
                if basename in ("trivy", "trivy.exe"):
                    if fpath not in paths:
                        paths.append(fpath)

        return paths

    def scan(self):
        if not self.config.system_scan and not self.config.scan_path:
            return

        binaries = self._find_trivy_binaries()
        if not binaries:
            return

        for binary_path in binaries:
            self.items_scanned += 1

            # Hash check
            file_hash = sha256_file(binary_path)
            if file_hash and file_hash in MALICIOUS_TRIVY_BINARY_HASHES:
                desc = MALICIOUS_TRIVY_BINARY_HASHES[file_hash]
                self.add_finding(
                    Severity.CRITICAL,
                    "COMPROMISED Trivy binary detected",
                    f"SHA256 hash matches known malicious v0.69.4 binary ({desc})",
                    file_path=binary_path,
                    evidence=f"SHA256: {file_hash}",
                    remediation="DELETE this binary immediately. Install v0.69.3 or earlier. Rotate ALL accessible credentials.",
                )
                continue

            # C2 string check
            if scan_binary_for_bytes(binary_path, b"aquasecurtiy"):
                self.add_finding(
                    Severity.CRITICAL,
                    "Trivy binary contains C2 domain",
                    "Binary contains the TeamPCP typosquat C2 domain 'aquasecurtiy' (note misspelling).",
                    file_path=binary_path,
                    remediation="DELETE this binary immediately. Rotate ALL accessible credentials.",
                )
                continue

            # Version check
            version_output = run_cmd([binary_path, "--version"])
            if version_output:
                ver_match = re.search(r"(\d+\.\d+\.\d+)", version_output)
                if ver_match:
                    ver = ver_match.group(1)
                    if ver in ("0.69.4", "0.69.5", "0.69.6"):
                        self.add_finding(
                            Severity.HIGH,
                            f"Trivy version {ver} detected (compromised range)",
                            "This version was compromised during the TeamPCP campaign. Hash did not match known-bad "
                            "binaries, but this version should not be used.",
                            file_path=binary_path,
                            evidence=f"Version: {ver}",
                            remediation="Downgrade to v0.69.3 or earlier. Verify binary with cosign.",
                        )


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER 3: npm CanisterWorm
# ═══════════════════════════════════════════════════════════════════════════════

class NpmCanisterWormScanner(BaseScanner):
    category_name = "npm_canisterworm"
    display_name = "npm CanisterWorm Packages"

    # Behavioral patterns that indicate CanisterWorm infection
    _WORM_PATTERNS = [
        (re.compile(r'findNpmTokens', re.IGNORECASE), "npm token harvesting function"),
        (re.compile(r'npm\s+publish\s+--access\s+public\s+--tag\s+latest'), "worm self-propagation command"),
        (re.compile(r'tdtqy-oyaaa-aaaae-af2dq-cai'), "ICP blockchain C2 canister ID"),
        (re.compile(r'registry\.npmjs\.org/:\s*_authToken'), "npm token extraction pattern"),
        (re.compile(r'Buffer\.from\(["\'][A-Za-z0-9+/]{200,}'), "large base64 encoded payload"),
    ]

    def _check_package_json(self, path: str, rel_path: str):
        """Check a package.json for compromised dependencies and behavioral patterns."""
        content = safe_read_text(path)
        if not content:
            return
        try:
            pkg = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return

        # Check all dependency types
        dep_keys = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
        for dk in dep_keys:
            deps = pkg.get(dk, {})
            if not isinstance(deps, dict):
                continue
            for pkg_name, version_spec in deps.items():
                if pkg_name in COMPROMISED_NPM_PACKAGES:
                    known_versions = COMPROMISED_NPM_PACKAGES[pkg_name]
                    # Extract version from spec (strip ^, ~, >=, etc.)
                    ver_match = re.search(r'(\d+\.\d+\.\d+)', str(version_spec))
                    ver = ver_match.group(1) if ver_match else None

                    if known_versions and ver and ver in known_versions:
                        self.add_finding(
                            Severity.CRITICAL,
                            f"Compromised npm package: {pkg_name}@{ver}",
                            f"This exact version was published by the CanisterWorm. "
                            f"Found in {dk} of {rel_path}.",
                            file_path=rel_path,
                            evidence=f'"{pkg_name}": "{version_spec}"',
                            remediation=f"Remove or downgrade {pkg_name}. Run npm audit. Delete node_modules and reinstall with --ignore-scripts.",
                        )
                    else:
                        self.add_finding(
                            Severity.HIGH,
                            f"Known CanisterWorm target package: {pkg_name}",
                            f"This package was compromised by CanisterWorm. "
                            f"Version {version_spec} may or may not be the malicious version. "
                            f"Found in {dk} of {rel_path}.",
                            file_path=rel_path,
                            evidence=f'"{pkg_name}": "{version_spec}"',
                            remediation=f"Verify the exact installed version. Known bad versions: {known_versions}",
                        )

        # Check for suspicious postinstall hook
        scripts = pkg.get("scripts", {})
        if isinstance(scripts, dict):
            postinstall = scripts.get("postinstall", "")
            if "node index.js" in postinstall:
                self.add_finding(
                    Severity.HIGH,
                    "Suspicious postinstall hook (CanisterWorm pattern)",
                    f'postinstall script runs "node index.js" - this is the exact CanisterWorm trigger pattern.',
                    file_path=rel_path,
                    evidence=f'"postinstall": "{postinstall}"',
                    remediation="Inspect index.js for credential harvesting or base64-encoded payloads",
                )

    def _check_lockfile(self, path: str, rel_path: str):
        """Check package-lock.json for compromised packages."""
        content = safe_read_text(path, max_bytes=50 * 1024 * 1024)  # lockfiles can be large
        if not content:
            return
        try:
            lock = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return

        # npm v2+ lockfile format (packages key)
        packages = lock.get("packages", {})
        for pkg_path, info in packages.items():
            name = info.get("name", "")
            version = info.get("version", "")
            if not name:
                # Extract from path: node_modules/@scope/pkg or node_modules/pkg
                parts = pkg_path.replace("\\", "/").split("node_modules/")
                if len(parts) > 1:
                    name = parts[-1]
            if name in COMPROMISED_NPM_PACKAGES:
                known = COMPROMISED_NPM_PACKAGES[name]
                if known and version in known:
                    self.add_finding(
                        Severity.CRITICAL,
                        f"Compromised package in lockfile: {name}@{version}",
                        f"This exact version was published by CanisterWorm.",
                        file_path=rel_path,
                        evidence=f"{name}@{version}",
                        remediation="Delete node_modules, remove from lockfile, reinstall with --ignore-scripts",
                    )
                elif not known or not version:
                    self.add_finding(
                        Severity.HIGH,
                        f"CanisterWorm target in lockfile: {name}@{version}",
                        "This package scope was targeted by CanisterWorm. Verify the version.",
                        file_path=rel_path,
                    )

        # npm v1 lockfile format (dependencies key) - recursive check
        def check_deps(deps_dict, prefix=""):
            for name, info in deps_dict.items():
                version = info.get("version", "")
                if name in COMPROMISED_NPM_PACKAGES:
                    known = COMPROMISED_NPM_PACKAGES[name]
                    sev = Severity.CRITICAL if (known and version in known) else Severity.HIGH
                    self.add_finding(
                        sev,
                        f"{'Compromised' if sev == Severity.CRITICAL else 'Suspect'} package in lockfile: {name}@{version}",
                        f"Found via legacy lockfile dependencies tree.",
                        file_path=rel_path,
                    )
                # Recurse into nested dependencies
                nested = info.get("dependencies", {})
                if nested:
                    check_deps(nested, name + "/")

        legacy_deps = lock.get("dependencies", {})
        if isinstance(legacy_deps, dict) and "packages" not in lock:
            check_deps(legacy_deps)

    def _check_node_modules(self, nm_path: str, rel_base: str):
        """Scan node_modules directory for compromised packages and behavioral patterns."""
        for scope in COMPROMISED_NPM_SCOPES:
            scope_dir = os.path.join(nm_path, scope)
            if os.path.isdir(scope_dir):
                try:
                    for entry in os.scandir(scope_dir):
                        if entry.is_dir():
                            full_name = f"{scope}/{entry.name}"
                            if full_name in COMPROMISED_NPM_PACKAGES:
                                pkg_json = os.path.join(entry.path, "package.json")
                                if os.path.isfile(pkg_json):
                                    self._check_installed_package(entry.path, full_name, rel_base)
                except (PermissionError, OSError):
                    pass

        # Check standalone packages
        for pkg_name in COMPROMISED_NPM_PACKAGES:
            if "/" not in pkg_name:  # standalone (not scoped)
                pkg_dir = os.path.join(nm_path, pkg_name)
                if os.path.isdir(pkg_dir):
                    self._check_installed_package(pkg_dir, pkg_name, rel_base)

    def _check_installed_package(self, pkg_dir: str, pkg_name: str, rel_base: str):
        """Check an installed package directory for compromise indicators."""
        # Read version
        pkg_json_path = os.path.join(pkg_dir, "package.json")
        version = "unknown"
        content = safe_read_text(pkg_json_path)
        if content:
            try:
                pkg = json.loads(content)
                version = pkg.get("version", "unknown")
            except (json.JSONDecodeError, ValueError):
                pass

        known = COMPROMISED_NPM_PACKAGES.get(pkg_name)
        if known and version in known:
            self.add_finding(
                Severity.CRITICAL,
                f"Compromised package INSTALLED: {pkg_name}@{version}",
                "This exact version is installed in node_modules and was published by CanisterWorm.",
                file_path=os.path.relpath(pkg_dir, rel_base),
                remediation="Remove immediately. Delete node_modules and reinstall with --ignore-scripts.",
            )

        # Behavioral scan of key files
        for fname in ("index.js", "deploy.js"):
            fpath = os.path.join(pkg_dir, fname)
            if os.path.isfile(fpath):
                fcontent = safe_read_text(fpath)
                if fcontent:
                    for pattern, desc in self._WORM_PATTERNS:
                        if pattern.search(fcontent):
                            self.add_finding(
                                Severity.CRITICAL,
                                f"CanisterWorm behavioral indicator in {pkg_name}/{fname}",
                                f"Detected: {desc}",
                                file_path=os.path.relpath(fpath, rel_base),
                                evidence=pattern.pattern,
                                remediation="This package contains active CanisterWorm malware. Remove immediately.",
                            )
                            break

    def scan(self):
        root = self.config.scan_path or Path(".")
        root_str = str(root)

        # We need to scan node_modules for this category, so use custom walk
        for dirpath, dirnames, filenames in os.walk(root_str):
            # Skip .git but NOT node_modules (we need it)
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", ".tox")]

            depth = dirpath.replace(root_str, "").count(os.sep)
            if depth > 15:
                dirnames.clear()
                continue

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)

                if fname == "package.json":
                    self.items_scanned += 1
                    rel = os.path.relpath(fpath, root_str)
                    # Skip node_modules package.json for dependency scanning (too many)
                    # but DO check them for behavioral patterns
                    if "node_modules" not in rel:
                        self._check_package_json(fpath, rel)

                elif fname == "package-lock.json" and "node_modules" not in dirpath:
                    self.items_scanned += 1
                    self._check_lockfile(fpath, os.path.relpath(fpath, root_str))

            # Check node_modules directories
            if "node_modules" in dirnames:
                nm_path = os.path.join(dirpath, "node_modules")
                self.items_scanned += 1
                self._check_node_modules(nm_path, root_str)
                # Don't recurse into node_modules further (we handle it ourselves)
                dirnames.remove("node_modules")


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER 4: LiteLLM / PyPI
# ═══════════════════════════════════════════════════════════════════════════════

class LiteLLMScanner(BaseScanner):
    category_name = "litellm_pypi"
    display_name = "LiteLLM PyPI Compromise"

    _LITELLM_RE = re.compile(r'litellm\s*[>=<~!]*=*\s*([\d.]+)', re.IGNORECASE)
    _PTH_SUSPICIOUS = re.compile(r'(exec\s*\(|eval\s*\(|base64\.b64decode|codecs\.decode|compile\s*\()', re.IGNORECASE)
    # Known-safe .pth files that use import/exec legitimately
    _SAFE_PTH_FILES = frozenset({
        "distutils-precedence.pth",
        "setuptools.pth",
        "pip-autoremove.pth",
        "virtualenv.pth",
        "easy-install.pth",
    })

    def _scan_dep_files(self):
        """Scan dependency manifest files for litellm references."""
        root = self.config.scan_path or Path(".")
        dep_patterns = {
            "requirements": re.compile(r'requirements.*\.txt$', re.IGNORECASE),
            "pyproject": re.compile(r'pyproject\.toml$', re.IGNORECASE),
            "pipfile": re.compile(r'Pipfile$', re.IGNORECASE),
            "pipfilelock": re.compile(r'Pipfile\.lock$', re.IGNORECASE),
            "setup_py": re.compile(r'setup\.py$', re.IGNORECASE),
            "setup_cfg": re.compile(r'setup\.cfg$', re.IGNORECASE),
            "poetry_lock": re.compile(r'poetry\.lock$', re.IGNORECASE),
        }

        for fpath in walk_files(root):
            fname = os.path.basename(fpath)
            if any(p.match(fname) for p in dep_patterns.values()):
                if "node_modules" in fpath or ".git" in fpath:
                    continue
                self.items_scanned += 1
                content = safe_read_text(fpath)
                if not content:
                    continue

                # Search for litellm
                for match in self._LITELLM_RE.finditer(content):
                    version = match.group(1)
                    rel = os.path.relpath(fpath, str(root))
                    if version in LITELLM_COMPROMISED_VERSIONS:
                        self.add_finding(
                            Severity.CRITICAL,
                            f"Compromised LiteLLM version: {version}",
                            f"LiteLLM {version} contains TeamPCP credential-stealing malware. "
                            f"v1.82.8 includes a .pth file that executes on every Python invocation.",
                            file_path=rel,
                            evidence=match.group(0),
                            remediation="Downgrade to litellm<=1.82.6 immediately. Rotate ALL credentials. Check for persistence artifacts.",
                        )
                    else:
                        self.add_finding(
                            Severity.MEDIUM,
                            f"LiteLLM dependency found (version {version})",
                            "LiteLLM was compromised in versions 1.82.7 and 1.82.8. "
                            "Verify your installed version is safe (<= 1.82.6).",
                            file_path=rel,
                            evidence=match.group(0),
                            remediation="Run: pip show litellm to verify installed version",
                        )
                    break  # One finding per file

                # Also check for bare "litellm" without version
                if "litellm" in content.lower() and not self._LITELLM_RE.search(content):
                    if re.search(r'\blitellm\b', content, re.IGNORECASE):
                        rel = os.path.relpath(fpath, str(root))
                        self.add_finding(
                            Severity.MEDIUM,
                            "LiteLLM reference without pinned version",
                            "LiteLLM appears in dependency file without a pinned version. "
                            "Unpinned installs may have pulled compromised 1.82.7 or 1.82.8.",
                            file_path=rel,
                            remediation="Pin to litellm<=1.82.6 and verify installed version",
                        )

    def _scan_installed(self):
        """Check for LiteLLM installed on the system."""
        # pip show
        output = run_cmd([sys.executable, "-m", "pip", "show", "litellm"])
        if output:
            ver_match = re.search(r'Version:\s*([\d.]+)', output)
            if ver_match:
                ver = ver_match.group(1)
                if ver in LITELLM_COMPROMISED_VERSIONS:
                    self.add_finding(
                        Severity.CRITICAL,
                        f"COMPROMISED LiteLLM {ver} installed on system",
                        "This version contains TeamPCP credential-stealing malware.",
                        remediation="Run: pip install litellm==1.82.6 immediately. Rotate ALL credentials.",
                    )
                else:
                    self.add_finding(
                        Severity.INFO,
                        f"LiteLLM {ver} installed (safe version)",
                        "Installed version is not in the compromised range.",
                    )

        # Check for litellm_init.pth in site-packages
        try:
            site_output = run_cmd([sys.executable, "-c", "import site; print('\\n'.join(site.getsitepackages()))"])
            if site_output:
                for sp_dir in site_output.strip().split("\n"):
                    sp_dir = sp_dir.strip()
                    if not os.path.isdir(sp_dir):
                        continue

                    # Check for litellm_init.pth
                    pth_path = os.path.join(sp_dir, "litellm_init.pth")
                    if os.path.isfile(pth_path):
                        file_hash = sha256_file(pth_path)
                        if file_hash == LITELLM_PTH_HASH:
                            self.add_finding(
                                Severity.CRITICAL,
                                "Malicious litellm_init.pth detected (hash confirmed)",
                                "This .pth file executes TeamPCP malware on EVERY Python interpreter startup. "
                                "All Python processes on this system are compromised.",
                                file_path=pth_path,
                                evidence=f"SHA256: {file_hash}",
                                remediation="DELETE this file immediately: rm " + pth_path,
                            )
                        else:
                            self.add_finding(
                                Severity.HIGH,
                                "litellm_init.pth file exists (unknown hash)",
                                "A litellm_init.pth file exists. This file type auto-executes on Python startup.",
                                file_path=pth_path,
                                evidence=f"SHA256: {file_hash}",
                                remediation="Inspect this file and delete if suspicious",
                            )

                    # Check for malicious proxy_server.py
                    proxy_path = os.path.join(sp_dir, "litellm", "proxy", "proxy_server.py")
                    if os.path.isfile(proxy_path):
                        file_hash = sha256_file(proxy_path)
                        if file_hash == LITELLM_PROXY_HASH:
                            self.add_finding(
                                Severity.CRITICAL,
                                "Malicious litellm proxy_server.py detected (hash confirmed)",
                                "Contains injected TeamPCP credential stealer.",
                                file_path=proxy_path,
                                evidence=f"SHA256: {file_hash}",
                                remediation="Run: pip install --force-reinstall litellm==1.82.6",
                            )

                    # Scan ALL .pth files for suspicious patterns
                    try:
                        for entry in os.scandir(sp_dir):
                            if entry.name.endswith(".pth") and entry.is_file():
                                if entry.name in self._SAFE_PTH_FILES:
                                    continue
                                content = safe_read_text(entry.path, max_bytes=100000)
                                if content and self._PTH_SUSPICIOUS.search(content):
                                    self.add_finding(
                                        Severity.HIGH,
                                        f"Suspicious .pth file: {entry.name}",
                                        "Contains exec/eval/base64/compile patterns that could indicate auto-execute malware.",
                                        file_path=entry.path,
                                        evidence=self._PTH_SUSPICIOUS.search(content).group(0),  # type: ignore
                                        remediation="Inspect this file manually",
                                    )
                    except (PermissionError, OSError):
                        pass
        except Exception:
            pass

    def scan(self):
        self._scan_dep_files()
        if self.config.system_scan:
            self._scan_installed()


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER 5: Docker / Container
# ═══════════════════════════════════════════════════════════════════════════════

class DockerContainerScanner(BaseScanner):
    category_name = "docker_container"
    display_name = "Docker / Container Images"

    # Matches aquasec/trivy, aquasecurity/trivy, and mirror.gcr.io/aquasec/trivy variants
    _IMAGE_RE = re.compile(
        r'(?:mirror\.gcr\.io/)?(?:aquasec(?:urity)?)/trivy[:\s@]+([^\s"\']+)',
        re.IGNORECASE,
    )
    _DIGEST_RE = re.compile(r'(sha256:[0-9a-f]{64})', re.IGNORECASE)

    def _scan_files(self):
        """Scan Dockerfiles, compose files, and K8s manifests for trivy image references."""
        root = self.config.scan_path or Path(".")
        target_patterns = re.compile(
            r'(Dockerfile|docker-compose|\.dockerfile).*$|.*\.(ya?ml)$',
            re.IGNORECASE,
        )

        for fpath in walk_files(root):
            fname = os.path.basename(fpath)
            if not target_patterns.match(fname):
                continue
            if "node_modules" in fpath or ".git" in fpath:
                continue

            content = safe_read_text(fpath)
            if not content:
                continue
            cl = content.lower()
            if ("aquasec/trivy" not in cl and "aquasecurity/trivy" not in cl
                    and "mirror.gcr.io" not in cl):
                continue

            self.items_scanned += 1
            rel = os.path.relpath(fpath, str(root))

            for match in self._IMAGE_RE.finditer(content):
                # Handle tag@sha256:digest form (e.g. trivy:0.69.4@sha256:abc...).
                # Strip the digest half so version checks work — _DIGEST_RE handles the digest.
                tag = match.group(1).split("@")[0]
                if tag in ("0.69.4", "0.69.5", "0.69.6", "v0.69.4", "v0.69.5", "v0.69.6"):
                    self.add_finding(
                        Severity.CRITICAL,
                        f"Compromised Trivy image version: {tag}",
                        "This Docker image version was published with TeamPCP malware.",
                        file_path=rel,
                        evidence=match.group(0),
                        remediation="Use aquasec/trivy:0.69.3 or earlier. Pin by digest.",
                    )
                elif tag == "latest":
                    self.add_finding(
                        Severity.HIGH,
                        "Trivy image using 'latest' tag",
                        "The 'latest' tag pointed to compromised versions during the attack window. "
                        "If pulled between Mar 19-23, it may have been malicious.",
                        file_path=rel,
                        evidence=match.group(0),
                        remediation="Pin to a specific safe version or digest.",
                    )
                else:
                    self.add_finding(
                        Severity.INFO,
                        f"Trivy image reference: {tag}",
                        "Trivy image reference found. Verify the version is safe.",
                        file_path=rel,
                        evidence=match.group(0),
                    )

            # Check for known-bad digests
            for dmatch in self._DIGEST_RE.finditer(content):
                digest = dmatch.group(1)
                if digest in MALICIOUS_DOCKER_DIGESTS:
                    self.add_finding(
                        Severity.CRITICAL,
                        "Known malicious Docker image digest",
                        f"This digest matches a compromised Trivy image.",
                        file_path=rel,
                        evidence=digest,
                        remediation="Remove this reference immediately.",
                    )

    def _scan_local_docker(self):
        """Check locally pulled Docker images."""
        if not shutil.which("docker"):
            return

        output = run_cmd(["docker", "images", "--digests", "--format",
                          "{{.Repository}}:{{.Tag}} {{.Digest}}"], timeout=15)
        if not output:
            return

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if "aquasec/trivy" in line.lower():
                self.items_scanned += 1
                # Check for compromised tags
                for bad_ver in ("0.69.4", "0.69.5", "0.69.6"):
                    if f":{bad_ver}" in line:
                        self.add_finding(
                            Severity.CRITICAL,
                            f"Compromised Trivy Docker image on system",
                            f"Local Docker image matches compromised version.",
                            evidence=line,
                            remediation=f"Run: docker rmi aquasec/trivy:{bad_ver}",
                        )

                # Check digest
                digest_match = self._DIGEST_RE.search(line)
                if digest_match and digest_match.group(1) in MALICIOUS_DOCKER_DIGESTS:
                    self.add_finding(
                        Severity.CRITICAL,
                        "Compromised Trivy Docker image digest on system",
                        "Local Docker image digest matches known-bad image.",
                        evidence=line,
                        remediation="Remove this image immediately.",
                    )

    def scan(self):
        self._scan_files()
        if self.config.system_scan:
            self._scan_local_docker()


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER 6: System Persistence
# ═══════════════════════════════════════════════════════════════════════════════

class SystemPersistenceScanner(BaseScanner):
    category_name = "system_persistence"
    display_name = "System Persistence Artifacts"

    def _check_path(self, path_template: str, description: str):
        """Check if a persistence artifact exists at the given path."""
        path = os.path.expanduser(os.path.expandvars(path_template))
        if os.path.exists(path):
            self.items_scanned += 1
            file_hash = sha256_file(path)
            evidence = f"SHA256: {file_hash}" if file_hash else "File exists"

            # Extra confirmation for known hashes
            extra = ""
            if file_hash == LITELLM_SYSMON_HASH:
                extra = " (hash confirmed as TeamPCP sysmon.py)"

            self.add_finding(
                Severity.CRITICAL,
                f"TeamPCP persistence artifact: {os.path.basename(path)}{extra}",
                f"{description}. Path: {path}",
                file_path=path,
                evidence=evidence,
                remediation=f"Delete this file: rm '{path}'. Check for associated systemd services. Rotate all credentials.",
            )
            return True
        return False

    def _check_persistence_content(self):
        """Verify persistence files by checking content for TeamPCP indicators."""
        # If we found a persistence file, check its content for known patterns
        # that confirm it's TeamPCP (not a legitimate file with the same name)
        teampcp_content_indicators = [
            b"tdtqy-oyaaa-aaaae-af2dq-cai",   # ICP canister ID
            b"aquasecurtiy",                    # Typosquat C2 domain
            b"tpcp",                            # TeamPCP marker
            b"TeamPCP Cloud stealer",           # Payload self-attribution string [ramimac]
            b"checkmarx.zone",                  # C2 domain
            b"models.litellm.cloud",            # Exfil domain
            b"pglog",                           # Staging path reference
            b".pg_state",                       # State file reference
        ]
        for path_template in (PERSISTENCE_PATHS_LINUX if platform.system() == "Linux"
                              else PERSISTENCE_PATHS_MACOS if platform.system() == "Darwin"
                              else []):
            path = os.path.expanduser(os.path.expandvars(path_template))
            if os.path.isfile(path):
                try:
                    with open(path, "rb") as f:
                        content = f.read(50000)
                    for indicator in teampcp_content_indicators:
                        if indicator in content:
                            self.add_finding(
                                Severity.CRITICAL,
                                f"TeamPCP content confirmed in: {os.path.basename(path)}",
                                f"File contains TeamPCP indicator '{indicator.decode()}'. "
                                f"This is a confirmed active compromise.",
                                file_path=path,
                                evidence=indicator.decode(),
                                remediation="Incident response required. Isolate this system. Rotate all credentials.",
                            )
                            break
                except (PermissionError, OSError):
                    pass

    def _check_processes(self):
        """Check for running TeamPCP processes."""
        system = platform.system()
        # Use specific patterns to avoid false positives (e.g., "service.py" is too broad)
        process_indicators = [
            ("sysmon.py", "TeamPCP sysmon loader"),
            ("pgmon", "TeamPCP pgmon backdoor"),
            ("/tmp/pglog", "TeamPCP staged payload"),
            ("internal-monitor", "TeamPCP systemd service"),
            ("pgmonitor", "TeamPCP systemd service"),
        ]

        if system in ("Linux", "Darwin"):
            output = run_cmd(["ps", "aux"])
            if output:
                for line in output.split("\n"):
                    if "teampcp_scanner" in line or "grep" in line:
                        continue
                    for indicator, desc in process_indicators:
                        if indicator in line:
                            self.add_finding(
                                Severity.CRITICAL,
                                f"Suspicious process running: {desc}",
                                f"A process matching TeamPCP indicator '{indicator}' is currently running.",
                                evidence=line.strip()[:200],
                                remediation="Kill this process and investigate. Check systemd services.",
                            )
        elif system == "Windows":
            output = run_cmd(["tasklist", "/v"])
            if output:
                for line in output.split("\n"):
                    for indicator, desc in process_indicators:
                        if indicator.lower() in line.lower():
                            self.add_finding(
                                Severity.CRITICAL,
                                f"Suspicious process: {desc}",
                                "A process matching TeamPCP indicator is running.",
                                evidence=line.strip()[:200],
                            )

    def _check_systemd(self):
        """Check for TeamPCP systemd services on Linux."""
        if platform.system() != "Linux":
            return
        for svc in ["pgmon", "sysmon", "internal-monitor", "pgmonitor"]:
            output = run_cmd(["systemctl", "--user", "is-active", svc])
            if output and "active" in output.strip():
                self.add_finding(
                    Severity.CRITICAL,
                    f"TeamPCP systemd service active: {svc}",
                    f"The '{svc}' user service is currently running.",
                    remediation=f"Run: systemctl --user stop {svc} && systemctl --user disable {svc}",
                )
            # Also check system-level
            output = run_cmd(["systemctl", "is-active", svc])
            if output and "active" in output.strip():
                self.add_finding(
                    Severity.CRITICAL,
                    f"TeamPCP system service active: {svc}",
                    f"The '{svc}' system service is currently running.",
                    remediation=f"Run: sudo systemctl stop {svc} && sudo systemctl disable {svc}",
                )

    def _check_launchd(self):
        """Check for suspicious LaunchAgents on macOS."""
        if platform.system() != "Darwin":
            return
        la_dir = os.path.expanduser("~/Library/LaunchAgents")
        if not os.path.isdir(la_dir):
            return
        try:
            for entry in os.scandir(la_dir):
                if entry.is_file() and entry.name.endswith(".plist"):
                    content = safe_read_text(entry.path)
                    if content:
                        for indicator in ["sysmon", "pgmon", "pglog", "internal-monitor"]:
                            if indicator in content:
                                self.add_finding(
                                    Severity.CRITICAL,
                                    f"Suspicious LaunchAgent: {entry.name}",
                                    f"Contains TeamPCP indicator '{indicator}'.",
                                    file_path=entry.path,
                                    remediation=f"Run: launchctl unload {entry.path} && rm {entry.path}",
                                )
        except (PermissionError, OSError):
            pass

    def scan(self):
        system = platform.system()

        # Check persistence file paths
        if system == "Linux":
            paths = PERSISTENCE_PATHS_LINUX
        elif system == "Darwin":
            paths = PERSISTENCE_PATHS_MACOS
        else:
            # Windows
            appdata = os.environ.get("APPDATA", "")
            localappdata = os.environ.get("LOCALAPPDATA", "")
            temp = os.environ.get("TEMP", os.environ.get("TMP", ""))
            paths = []
            if appdata:
                paths += [
                    os.path.join(appdata, "sysmon", "sysmon.py"),
                    os.path.join(appdata, "pgmon", "service.py"),
                ]
            if localappdata:
                paths += [
                    os.path.join(localappdata, "sysmon", "sysmon.py"),
                    os.path.join(localappdata, "pgmon", "service.py"),
                ]

        for p in paths:
            self._check_path(p, "TeamPCP persistence implant")

        # Staging artifacts (cross-platform)
        staging = list(STAGING_PATHS)
        if system == "Windows":
            temp_dir = os.environ.get("TEMP", os.environ.get("TMP", ""))
            if temp_dir:
                staging = [
                    os.path.join(temp_dir, "pglog"),
                    os.path.join(temp_dir, ".pg_state"),
                ]
        for p in staging:
            self._check_path(p, "TeamPCP staging/payload artifact")

        # tpcp.tar.gz exfiltration bundle
        for tmp in ["/tmp", os.environ.get("TEMP", ""), os.environ.get("TMP", "")]:
            if tmp:
                tpcp = os.path.join(tmp, "tpcp.tar.gz")
                self._check_path(tpcp, "TeamPCP encrypted exfiltration bundle")

        # Content verification of any found persistence files
        self._check_persistence_content()

        # Process checks
        self._check_processes()

        # Platform-specific service checks
        if system == "Linux":
            self._check_systemd()
        elif system == "Darwin":
            self._check_launchd()


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER 7: C2 / Network IOC
# ═══════════════════════════════════════════════════════════════════════════════

class C2NetworkIOCScanner(BaseScanner):
    category_name = "c2_network_ioc"
    display_name = "C2 / Network IOCs"

    def _scan_files(self):
        """Scan source code files for C2 domain/IP references."""
        root = self.config.scan_path or Path(".")

        for fpath in walk_files(root):
            # Skip self
            if is_self(fpath):
                continue

            ext = os.path.splitext(fpath)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue

            if is_binary_file(fpath):
                continue

            self.items_scanned += 1
            content = safe_read_text(fpath)
            if not content:
                continue

            rel = os.path.relpath(fpath, str(root))
            for ioc, desc in C2_IOCS:
                if ioc in content:
                    # Don't double-report the short fragment if the full domain was found
                    if ioc == "aquasecurtiy" and "aquasecurtiy.org" in content:
                        continue

                    self.add_finding(
                        Severity.HIGH,
                        f"C2 IOC in source: {ioc}",
                        f"{desc}. Found in {rel}",
                        file_path=rel,
                        evidence=ioc,
                        remediation="Investigate this reference. If it appears in application code (not documentation/scanning tools), this may indicate compromise.",
                    )
                    break  # One finding per file

    def _scan_shell_history(self):
        """Check shell history for C2 domain references."""
        history_files = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.local/share/fish/fish_history"),
        ]
        if platform.system() == "Windows":
            pshistory = os.path.expandvars(
                r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            )
            history_files.append(pshistory)

        for hf in history_files:
            if not os.path.isfile(hf):
                continue
            content = safe_read_text(hf)
            if not content:
                continue
            for ioc, desc in C2_IOCS:
                if ioc == "aquasecurtiy":
                    continue  # Too generic for history matching
                if ioc in content:
                    self.add_finding(
                        Severity.CRITICAL,
                        f"C2 IOC in shell history: {ioc}",
                        f"{desc}. Found in {hf}. This may indicate this system interacted with TeamPCP infrastructure.",
                        file_path=hf,
                        evidence=ioc,
                        remediation="Investigate immediately. Check for persistence artifacts. Rotate all credentials.",
                    )

    def _scan_dns_cache(self):
        """Check DNS cache for C2 domains (Windows only - reliable method)."""
        if platform.system() != "Windows":
            return
        output = run_cmd(["ipconfig", "/displaydns"], timeout=15)
        if not output:
            return
        for ioc, desc in C2_IOCS:
            if "." not in ioc:
                continue  # Skip IPs and fragments
            if ioc in output:
                self.add_finding(
                    Severity.CRITICAL,
                    f"C2 domain in DNS cache: {ioc}",
                    f"{desc}. This system has recently resolved this domain.",
                    remediation="This system may be actively communicating with TeamPCP C2. Investigate immediately.",
                )

    def scan(self):
        self._scan_files()
        if self.config.system_scan:
            self._scan_shell_history()
            self._scan_dns_cache()


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER 8: Kubernetes IOC
# ═══════════════════════════════════════════════════════════════════════════════

class KubernetesIOCScanner(BaseScanner):
    category_name = "kubernetes_ioc"
    display_name = "Kubernetes IOCs"

    def _scan_manifests(self):
        """Scan YAML/JSON manifests for TeamPCP Kubernetes IOCs."""
        root = self.config.scan_path or Path(".")

        for fpath in walk_files(root):
            if not fpath.endswith((".yml", ".yaml", ".json")):
                continue
            if "node_modules" in fpath or ".git" in fpath:
                continue

            content = safe_read_text(fpath)
            if not content:
                continue

            # Quick pre-filter
            content_lower = content.lower()
            has_k8s = any(k in content_lower for k in ["kind:", "daemonset", "host-provisioner", "kamikaze", "node-setup"])
            if not has_k8s:
                continue

            self.items_scanned += 1
            rel = os.path.relpath(fpath, str(root))

            for ds_name in K8S_IOC_DAEMONSETS:
                if ds_name in content:
                    self.add_finding(
                        Severity.CRITICAL,
                        f"TeamPCP Kubernetes DaemonSet: {ds_name}",
                        f"{'Iran-targeted WIPER' if 'iran' in ds_name else 'Persistence backdoor'} DaemonSet manifest detected.",
                        file_path=rel,
                        evidence=ds_name,
                        remediation=f"kubectl delete daemonset {ds_name} -n kube-system",
                    )

            for container in K8S_IOC_CONTAINERS:
                # Use context-aware matching to avoid false positives
                pattern = re.compile(
                    r'(?:name|container)[\s:]*["\']?' + re.escape(container) + r'["\']?\s',
                    re.IGNORECASE,
                )
                if pattern.search(content):
                    self.add_finding(
                        Severity.HIGH,
                        f"TeamPCP container name: {container}",
                        f"Container name '{container}' matches TeamPCP K8s wiper/backdoor.",
                        file_path=rel,
                        evidence=container,
                    )

            if K8S_IOC_POD_PREFIX in content:
                self.add_finding(
                    Severity.HIGH,
                    "TeamPCP pod name pattern: node-setup-*",
                    "Pod naming pattern matches TeamPCP Kubernetes lateral movement.",
                    file_path=rel,
                    evidence=K8S_IOC_POD_PREFIX,
                )

    def _scan_live_cluster(self):
        """Query live Kubernetes cluster for TeamPCP IOCs."""
        if not shutil.which("kubectl"):
            return

        # Check DaemonSets
        output = run_cmd(["kubectl", "get", "daemonsets", "-A", "-o", "json"], timeout=10)
        if output:
            try:
                data = json.loads(output)
                for item in data.get("items", []):
                    name = item.get("metadata", {}).get("name", "")
                    ns = item.get("metadata", {}).get("namespace", "")
                    if name in K8S_IOC_DAEMONSETS:
                        self.add_finding(
                            Severity.CRITICAL,
                            f"LIVE TeamPCP DaemonSet: {name} in {ns}",
                            "Active TeamPCP DaemonSet found in your cluster!",
                            evidence=f"{ns}/{name}",
                            remediation=f"kubectl delete daemonset {name} -n {ns}",
                        )
            except (json.JSONDecodeError, ValueError):
                pass

        # Check pods
        output = run_cmd(["kubectl", "get", "pods", "-A", "-o", "json"], timeout=10)
        if output:
            try:
                data = json.loads(output)
                for item in data.get("items", []):
                    name = item.get("metadata", {}).get("name", "")
                    ns = item.get("metadata", {}).get("namespace", "")
                    if name.startswith(K8S_IOC_POD_PREFIX):
                        self.add_finding(
                            Severity.CRITICAL,
                            f"LIVE TeamPCP pod: {name} in {ns}",
                            "Active TeamPCP lateral movement pod found!",
                            evidence=f"{ns}/{name}",
                            remediation=f"kubectl delete pod {name} -n {ns}",
                        )
                    # Check container names
                    containers = item.get("spec", {}).get("containers", [])
                    for c in containers:
                        cname = c.get("name", "")
                        if cname in K8S_IOC_CONTAINERS:
                            self.add_finding(
                                Severity.CRITICAL,
                                f"LIVE TeamPCP container: {cname} in pod {name}",
                                "Active TeamPCP wiper/backdoor container found!",
                                evidence=f"{ns}/{name}/{cname}",
                            )
            except (json.JSONDecodeError, ValueError):
                pass

    def scan(self):
        self._scan_manifests()
        if self.config.system_scan:
            self._scan_live_cluster()


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER 9: Git History
# ═══════════════════════════════════════════════════════════════════════════════

class GitHistoryScanner(BaseScanner):
    category_name = "git_history"
    display_name = "Git History & Exfiltration"

    def _find_git_repos(self) -> List[str]:
        """Find all git repositories under scan path."""
        root = self.config.scan_path or Path(".")
        repos = []
        for dirpath, dirnames, _ in os.walk(str(root)):
            if ".git" in dirnames:
                repos.append(dirpath)
                dirnames.remove(".git")
            # Don't recurse into node_modules, etc.
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d != "node_modules"]
            if len(dirpath.replace(str(root), "").split(os.sep)) > 5:
                dirnames.clear()
        return repos

    def scan(self):
        repos = self._find_git_repos()

        for repo in repos:
            self.items_scanned += 1
            repo_name = os.path.basename(repo)

            # Check remotes for tpcp-docs (exfiltration indicator)
            output = run_cmd(["git", "-C", repo, "remote", "-v"])
            if output:
                for line in output.split("\n"):
                    ll = line.lower()
                    # tpcp-docs = Trivy/CanisterWorm exfil pattern [GHSA,CS,SS]
                    # docs-tpcp = KICS chain exfil pattern [multi-source]
                    # Use boundary regex to avoid "my-docs-tpcp-extension" false positives
                    _m = re.search(r'(?:^|[/\s:@])(tpcp-docs|docs-tpcp)(?:[/\s.@]|\.git|$)', ll)
                    if _m:
                        pattern = _m.group(1)
                        self.add_finding(
                            Severity.CRITICAL,
                            f"Exfiltration repo '{pattern}' in remotes ({repo_name})",
                            "The TeamPCP malware uses 'tpcp-docs' (Trivy/CanisterWorm chain) and "
                            "'docs-tpcp' (KICS chain) repos as credential exfiltration destinations. "
                            "This is a strong indicator that credentials were stolen from this system.",
                            file_path=repo,
                            evidence=line.strip(),
                            remediation="Investigate this remote. Rotate ALL credentials immediately. Check GitHub for public tpcp-docs/docs-tpcp repos in your org.",
                        )

            # Check git log during attack window
            output = run_cmd([
                "git", "-C", repo, "log", "--oneline",
                "--after=2026-03-19", "--before=2026-03-25",
                "--all", "--grep=trivy",
            ])
            if output and output.strip():
                self.add_finding(
                    Severity.MEDIUM,
                    f"Trivy-related commits during attack window ({repo_name})",
                    "Commits mentioning 'trivy' were made during the TeamPCP attack window (Mar 19-24, 2026).",
                    file_path=repo,
                    evidence=output.strip()[:200],
                    remediation="Review these commits to determine if they indicate exposure.",
                )

            # Check for known malicious LiteLLM commits in this repo's object store
            # These appear if the repo has BerriAI/litellm cloned and fetched the bad commits,
            # or if litellm is a submodule pinned to a malicious SHA.
            for sha in LITELLM_MALICIOUS_COMMIT_SHAS:
                result = run_cmd(["git", "-C", repo, "cat-file", "-t", sha])
                if result and result.strip() == "commit":
                    self.add_finding(
                        Severity.CRITICAL,
                        f"Malicious LiteLLM commit in repository ({repo_name})",
                        f"Repository contains commit {sha[:12]}..., a known malicious BerriAI/litellm commit "
                        "that exfiltrated secrets. This indicates the repo had litellm cloned or as a "
                        "submodule at the point of compromise.",
                        file_path=repo,
                        evidence=sha,
                        remediation="Rotate all secrets accessible from this repository. Audit litellm usage and remove the malicious commit from history.",
                    )

            # Check for tpcp-docs in repo names/descriptions
            git_config = os.path.join(repo, ".git", "config")
            if os.path.isfile(git_config):
                content = safe_read_text(git_config)
                if content and re.search(r'(?:^|[/\s:@])(tpcp-docs|docs-tpcp)(?:[/\s.@]|\.git|$)', content, re.IGNORECASE | re.MULTILINE):
                    self.add_finding(
                        Severity.CRITICAL,
                        f"TeamPCP exfiltration repo reference in git config ({repo_name})",
                        "TeamPCP exfiltration indicator (tpcp-docs or docs-tpcp) found in git configuration.",
                        file_path=git_config,
                    )


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER 10: Credential Exposure Assessment
# ═══════════════════════════════════════════════════════════════════════════════

class CredentialExposureScanner(BaseScanner):
    category_name = "credential_exposure"
    display_name = "Credential Exposure Assessment"

    def _scan_repo(self):
        """Check for credential files in the scanned path."""
        root = self.config.scan_path or Path(".")
        cred_patterns = [
            (".npmrc", "npm authentication tokens", True),
            (".pypirc", "PyPI authentication tokens", True),
            (".env", "environment variables and/or API keys", False),
            ("credentials", "cloud provider credentials", True),
        ]

        for fpath in walk_files(root):
            if ".git" in fpath or "node_modules" in fpath:
                continue
            fname = os.path.basename(fpath).lower()

            for pattern, desc, is_exact in cred_patterns:
                if (is_exact and fname == pattern) or (not is_exact and fname.startswith(pattern)):
                    self.items_scanned += 1
                    rel = os.path.relpath(fpath, str(root))
                    content = safe_read_text(fpath, max_bytes=50000)

                    if fname == ".npmrc" and content and "_authToken" in content:
                        self.add_finding(
                            Severity.HIGH,
                            f"npm token in repository: {rel}",
                            "An npm authentication token is present in the repository. "
                            "If this system was compromised, this token was likely stolen.",
                            file_path=rel,
                            remediation="Rotate this npm token immediately. Use environment variables instead of checked-in .npmrc.",
                        )
                    elif fname == ".pypirc" and content and "password" in content.lower():
                        self.add_finding(
                            Severity.HIGH,
                            f"PyPI credentials in repository: {rel}",
                            "PyPI credentials are present in the repository.",
                            file_path=rel,
                            remediation="Rotate PyPI credentials. Use API tokens instead.",
                        )
                    elif fname.startswith(".env"):
                        self.add_finding(
                            Severity.LOW,
                            f"Environment file in repository: {rel}",
                            f"May contain {desc}. If this system was compromised, these values may have been exfiltrated.",
                            file_path=rel,
                            remediation="If exposed to a compromised CI/CD pipeline, rotate all values in this file.",
                        )
                    break

    def _scan_system(self):
        """Check system-level credential files that TeamPCP targets."""
        home = str(Path.home())
        ssh_dir = os.path.join(home, ".ssh")
        system_creds = [
            (os.path.join(home, ".npmrc"), "npm global auth token"),
            (os.path.join(home, ".pypirc"), "PyPI credentials"),
            (os.path.join(home, ".aws", "credentials"), "AWS credentials"),
            (os.path.join(home, ".docker", "config.json"), "Docker registry credentials"),
            (os.path.join(home, ".kube", "config"), "Kubernetes config"),
            # SSH private keys — explicitly harvested by TeamPCP [ramimac]
            (os.path.join(ssh_dir, "id_rsa"), "SSH private key (RSA)"),
            (os.path.join(ssh_dir, "id_ed25519"), "SSH private key (Ed25519)"),
            (os.path.join(ssh_dir, "id_ecdsa"), "SSH private key (ECDSA)"),
        ]

        for cred_path, desc in system_creds:
            if os.path.isfile(cred_path):
                self.items_scanned += 1
                self.add_finding(
                    Severity.INFO,
                    f"System credential file exists: {desc}",
                    f"Path: {cred_path}. TeamPCP harvests this file. "
                    "If your system was compromised, these credentials should be rotated.",
                    file_path=cred_path,
                    remediation=f"If exposed, rotate credentials in {cred_path}",
                )

    def scan(self):
        self._scan_repo()
        if self.config.system_scan:
            self._scan_system()


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN ENGINE (Orchestrator)
# ═══════════════════════════════════════════════════════════════════════════════

class ScanEngine:
    SCANNER_CLASSES = [
        GitHubActionsScanner,
        TrivyBinaryScanner,
        NpmCanisterWormScanner,
        LiteLLMScanner,
        DockerContainerScanner,
        SystemPersistenceScanner,
        C2NetworkIOCScanner,
        KubernetesIOCScanner,
        GitHistoryScanner,
        CredentialExposureScanner,
    ]

    def __init__(self, config: ScanConfig):
        self.config = config

    def run(self) -> ScanReport:
        scanners = [cls(self.config) for cls in self.SCANNER_CLASSES]

        # Run scanners in parallel
        results: List[CategoryResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            future_map = {pool.submit(s.run): s for s in scanners}
            for future in concurrent.futures.as_completed(future_map):
                scanner = future_map[future]
                try:
                    result = future.result(timeout=120)
                except Exception as e:
                    result = CategoryResult(
                        name=scanner.category_name,
                        display_name=scanner.display_name,
                        status="ERROR",
                        findings=[Finding(
                            category=scanner.category_name,
                            severity=Severity.INFO,
                            title="Scanner failed",
                            detail=str(e),
                        )],
                        scan_duration=0,
                        items_scanned=0,
                    )
                results.append(result)
                if not self.config.output_json and not self.config.output_markdown:
                    above = [f for f in result.findings if f.severity > Severity.INFO]
                    if result.status == "FINDINGS" and above:
                        max_sev = max(f.severity for f in above)
                        dot = C.red_bold("●") if max_sev == Severity.CRITICAL else C.red("●")
                    elif result.status == "CLEAR":
                        dot = C.green("●")
                    else:
                        dot = C.dim("●")
                    dur = f"{result.scan_duration*1000:.0f}ms"
                    print(f"  {dot}  {result.display_name}  {C.dim(dur)}")

        # Sort by original order
        order = {cls.category_name: i for i, cls in enumerate(self.SCANNER_CLASSES)}  # type: ignore[attr-defined]
        results.sort(key=lambda r: order.get(r.name, 99))

        # Compute risk score
        risk_score = self._compute_risk_score(results)

        # Build summary
        summary = {"total_findings": 0, "by_severity": {}}
        for sev in Severity:
            count = sum(len([f for f in r.findings if f.severity == sev]) for r in results)
            summary["by_severity"][sev.name] = count
            summary["total_findings"] += count

        return ScanReport(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            scanner_version=__version__,
            platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
            scan_target=str(self.config.scan_path) if self.config.scan_path else os.getcwd(),
            system_scan=self.config.system_scan,
            categories=results,
            risk_score=risk_score,
            summary=summary,
        )

    @staticmethod
    def _compute_risk_score(results: List[CategoryResult]) -> float:
        score = 0.0
        for cat in results:
            for f in cat.findings:
                if f.severity == Severity.CRITICAL:
                    score += 3.0
                elif f.severity == Severity.HIGH:
                    score += 1.5
                elif f.severity == Severity.MEDIUM:
                    score += 0.5
                elif f.severity == Severity.LOW:
                    score += 0.1
        return min(10.0, round(score, 1))


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATTERS
# ═══════════════════════════════════════════════════════════════════════════════

def format_terminal(report: ScanReport) -> str:  # noqa: C901
    W = 72  # total line width

    # ── ANSI-aware helpers ───────────────────────────────────────────────
    def _vlen(s: str) -> int:
        """Visible length of a string, stripping ANSI escape codes."""
        return len(re.sub(r'\033\[[0-9;]*m', '', s))

    def _pad(s: str, width: int, align: str = "left") -> str:
        """Pad a (possibly ANSI-colored) string to a given visible width."""
        p = max(0, width - _vlen(s))
        if align == "right":
            return " " * p + s
        if align == "center":
            lp = p // 2
            return " " * lp + s + " " * (p - lp)
        return s + " " * p

    def _wrap(text: str, width: int) -> List[str]:
        """Word-wrap plain text to width, returning list of lines."""
        if not text:
            return [""]
        words = text.split()
        lines_out: List[str] = []
        cur: List[str] = []
        cur_len = 0
        for w in words:
            wl = len(w)
            if cur and cur_len + 1 + wl > width:
                lines_out.append(" ".join(cur))
                cur = [w]
                cur_len = wl
            else:
                cur_len = cur_len + (1 if cur else 0) + wl
                cur.append(w)
        if cur:
            lines_out.append(" ".join(cur))
        return lines_out or [""]

    def _hrule(char: str = "═", width: int = W) -> str:
        return char * width

    out: List[str] = []

    # ── HEADER ──────────────────────────────────────────────────────────
    ver = f"v{report.scanner_version}"
    title = "  TeamPCP / Trivy Supply Chain Scanner"
    out.append("")
    out.append(C.bold(_hrule("═")))
    out.append(C.bold(_pad(title, W - len(ver) - 2) + "  " + ver))
    out.append(C.dim("  CVE-2026-33634  ·  GHSA-69fq-xp46-6x23"))
    out.append(C.bold(_hrule("─")))
    out.append("")

    meta = [
        ("Scan time",   report.timestamp),
        ("Platform",    report.platform),
        ("Target",      report.scan_target),
        ("System scan", "Yes  (binaries, Docker images, shell history, K8s, credentials)"
                        if report.system_scan
                        else "No   (persistence & processes always checked; --system adds binaries/Docker/history)"),
    ]
    lw = max(len(k) for k, _ in meta)
    for k, v in meta:
        out.append(f"  {C.dim(_pad(k, lw))}  {v}")
    out.append("")

    # ── SCAN OVERVIEW TABLE ──────────────────────────────────────────────
    # Layout: "  │ " mod_w " │ " stat_w " │ " scan_w " │"
    #          4  +  mod_w + 3 +  stat_w + 3 +  scan_w + 2  = W=72
    #          mod_w + stat_w + scan_w = 60
    mod_w, stat_w, scan_w = 34, 16, 10

    def _tsep(l: str, m: str, r: str) -> str:
        segs = ["─" * (mod_w + 2), "─" * (stat_w + 2), "─" * (scan_w + 2)]
        return "  " + l + m.join(segs) + r

    def _trow(c1: str, c2: str, c3: str) -> str:
        return ("  │ " + _pad(c1, mod_w)
                + " │ " + _pad(c2, stat_w, "center")
                + " │ " + _pad(c3, scan_w, "right") + " │")

    out.append(C.bold("  SCAN OVERVIEW"))
    out.append("")
    out.append(_tsep("┌", "┬", "┐"))
    out.append(_trow(C.bold("Module"), C.bold("Status"), C.bold("Scanned")))
    out.append(_tsep("├", "┼", "┤"))

    for cat in report.categories:
        above = [f for f in cat.findings if f.severity > Severity.INFO]
        if cat.status == "CLEAR":
            status_cell = C.green_bold("CLEAR")
        elif cat.status == "FINDINGS":
            n = len(above)
            label = f"{n} finding{'s' if n != 1 else ''}"
            max_sev = max((f.severity for f in above), default=Severity.INFO)
            if max_sev == Severity.CRITICAL:
                status_cell = C.red_bold(label)
            elif max_sev == Severity.HIGH:
                status_cell = C.red(label)
            else:
                status_cell = C.yellow(label)
        elif cat.status == "SKIPPED":
            status_cell = C.dim("SKIPPED")
        else:
            status_cell = C.yellow(cat.status)

        scan_cell = (f"{cat.items_scanned} items" if cat.items_scanned > 0
                     else C.dim("—"))
        out.append(_trow(cat.display_name, status_cell, scan_cell))

    out.append(_tsep("└", "┴", "┘"))
    out.append("")

    # ── FINDINGS DETAIL ──────────────────────────────────────────────────
    # Card: "  ┌" + "─"*68 + "┐"   (3 + 68 + 1 = 72)
    #        "  │ " + content(66) + " │"  (4 + 66 + 2 = 72)
    card_inner = W - 6   # 66 chars inside the card borders + padding
    label_col = 9        # width of row labels ("Evidence ", "Action  ", etc.)

    def _card_top() -> str:
        return "  ┌" + "─" * (card_inner + 2) + "┐"

    def _card_sep() -> str:
        return "  ├" + "─" * (card_inner + 2) + "┤"

    def _card_bot() -> str:
        return "  └" + "─" * (card_inner + 2) + "┘"

    def _card_row(content: str) -> str:
        return "  │ " + _pad(content, card_inner) + " │"

    def _card_field(label: str, value: str,
                    color_fn=None) -> List[str]:
        """Labeled field row inside a card, with word-wrapping."""
        val_w = card_inner - label_col - 1
        wrapped = _wrap(value, val_w)
        rows: List[str] = []
        for i, line in enumerate(wrapped):
            colored = color_fn(line) if color_fn else line
            if i == 0:
                prefix = _pad(label, label_col) + " "
            else:
                prefix = " " * (label_col + 1)
            rows.append(_card_row(prefix + colored))
        return rows

    finding_cats = [cat for cat in report.categories
                    if cat.status == "FINDINGS"
                    and any(f.severity > Severity.INFO for f in cat.findings)]

    if finding_cats:
        out.append(C.bold("  FINDINGS"))
        out.append("")

        for cat in finding_cats:
            above = [f for f in cat.findings if f.severity > Severity.INFO]
            out.append(f"  {C.bold('▸')} {C.bold(cat.display_name)}")
            out.append("")

            for finding in above:
                sev_badge = C.severity(finding.severity)
                # Title row inside card: severity badge + title text
                badge_plain = f"[{finding.severity.name}]"
                title_avail = card_inner - len(badge_plain) - 2
                title_text = finding.title[:title_avail]
                title_line = sev_badge + "  " + title_text

                out.append(_card_top())
                out.append(_card_row(C.bold(title_line)))
                out.append(_card_sep())

                if finding.detail:
                    out.extend(_card_field("Detail", finding.detail, C.dim))
                if finding.file_path:
                    out.extend(_card_field("File", finding.file_path))
                if finding.evidence:
                    out.extend(_card_field("Evidence", str(finding.evidence)[:120],
                                           C.yellow))
                if finding.remediation:
                    out.extend(_card_field("Action", finding.remediation, C.cyan))

                out.append(_card_bot())
                out.append("")

    # ── SUMMARY ──────────────────────────────────────────────────────────
    out.append(C.bold(_hrule("═")))
    out.append(C.bold("  SUMMARY"))
    out.append(C.bold(_hrule("═")))
    out.append("")

    # Severity breakdown table (compact — no need to fill full width)
    # "  │ " sev_w " │ " cnt_w " │"
    #   4  +  sev_w + 3 + cnt_w + 2
    sev_w, cnt_w = 10, 5
    by_sev = report.summary["by_severity"]

    def _stsep(l: str, m: str, r: str) -> str:
        return "  " + l + m.join(["─" * (sev_w + 2), "─" * (cnt_w + 2)]) + r

    def _strow(label: str, count: int, color_fn=None) -> str:
        s = color_fn(label) if (color_fn and count > 0) else C.dim(label)
        c_str = (color_fn(str(count)) if (color_fn and count > 0)
                 else C.dim(str(count)))
        return "  │ " + _pad(s, sev_w) + " │ " + _pad(c_str, cnt_w, "right") + " │"

    sev_rows = [
        ("CRITICAL", by_sev.get("CRITICAL", 0), C.red_bold),
        ("HIGH",     by_sev.get("HIGH",     0), C.red),
        ("MEDIUM",   by_sev.get("MEDIUM",   0), C.yellow),
        ("LOW",      by_sev.get("LOW",      0), C.cyan),
        ("INFO",     by_sev.get("INFO",     0), C.dim),
    ]
    out.append(_stsep("┌", "┬", "┐"))
    out.append("  │ " + _pad(C.bold("Severity"), sev_w)
               + " │ " + _pad(C.bold("Count"), cnt_w, "right") + " │")
    out.append(_stsep("├", "┼", "┤"))
    for sev_name, count, color_fn in sev_rows:
        out.append(_strow(sev_name, count, color_fn))
    out.append(_stsep("└", "┴", "┘"))
    out.append("")

    # Action guidance
    if by_sev.get("CRITICAL", 0) > 0:
        out.append(C.red_bold("  IMMEDIATE ACTIONS REQUIRED:"))
        out.append(C.red("  1. Rotate ALL secrets accessible to compromised components"))
        out.append(C.red("  2. Check for tpcp-docs repos in your GitHub org"))
        out.append(C.red("  3. Remove all compromised packages/binaries"))
        out.append(C.red("  4. Check for persistence artifacts on all CI runners"))
        out.append(C.red("  5. Block C2 domains/IPs at network egress"))
        out.append("")
    elif by_sev.get("HIGH", 0) > 0:
        for ln in _wrap(
            "Review HIGH findings above. C2 IOC references in application code "
            "(not documentation or scanning tools) are a strong indicator of active compromise.",
            W - 4
        ):
            out.append(f"  {C.yellow(ln)}")
        out.append("")

    # Footer
    out.append(C.bold(_hrule("═")))
    elapsed = sum(c.scan_duration for c in report.categories) * 1000
    out.append(C.dim(f"  Completed in {elapsed:.0f}ms  ·  GHSA-69fq-xp46-6x23"))
    out.append(C.dim("  For a full investigation: will@strandintelligence.com"))
    out.append("")

    return "\n".join(out)


def format_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


def format_markdown(report: ScanReport) -> str:
    lines = []
    lines.append("# TeamPCP / Trivy Supply Chain Exposure Report")
    lines.append("")
    lines.append(f"**CVE:** CVE-2026-33634 | **Scanner:** teampcp-scanner v{report.scanner_version}")
    lines.append(f"**Scan time:** {report.timestamp}")
    lines.append(f"**Platform:** {report.platform}")
    lines.append(f"**Target:** {report.scan_target}")
    lines.append(f"**System scan:** {'Yes' if report.system_scan else 'No'}")
    lines.append("")

    # Summary table
    by_sev = report.summary["by_severity"]
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {sev_name} | {by_sev.get(sev_name, 0)} |")
    lines.append(f"| **Total** | **{report.summary['total_findings']}** |")
    lines.append("")

    # Per-category
    for cat in report.categories:
        status_icon = {"CLEAR": "pass", "FINDINGS": "FAIL", "SKIPPED": "skip", "ERROR": "err"}.get(cat.status, "?")
        lines.append(f"## [{status_icon}] {cat.display_name}")
        lines.append("")

        findings_above_info = [f for f in cat.findings if f.severity > Severity.INFO]
        if not findings_above_info:
            lines.append("No issues detected.")
            lines.append("")
            continue

        lines.append("| Severity | Finding | Detail |")
        lines.append("|----------|---------|--------|")
        for f in findings_above_info:
            detail = f.detail[:100].replace("|", "\\|").replace("\n", " ")
            file_info = f" `{f.file_path}`" if f.file_path else ""
            lines.append(f"| **{f.severity.name}** | {f.title}{file_info} | {detail} |")
        lines.append("")

        # Remediation
        remediations = set(f.remediation for f in findings_above_info if f.remediation)
        if remediations:
            lines.append("**Remediation:**")
            for r in remediations:
                lines.append(f"- {r}")
            lines.append("")

    lines.append("---")
    lines.append(f"*Generated by teampcp-scanner v{report.scanner_version} on {report.timestamp}*")
    lines.append(f"*Reference: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23*")
    lines.append(f"*For a full investigation, contact Strand Intelligence: will@strandintelligence.com*")
    lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# SELF-TEST
# ═══════════════════════════════════════════════════════════════════════════════

def _create_test_fixtures(tmpdir: str):
    """Create synthetic test fixtures for self-test."""
    # Fixture 1: GitHub Actions workflow with compromised trivy-action
    wf_dir = os.path.join(tmpdir, ".github", "workflows")
    os.makedirs(wf_dir)
    with open(os.path.join(wf_dir, "ci.yml"), "w") as f:
        f.write("""name: CI
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aquasecurity/trivy-action@v0.34.0
        with:
          scan-type: fs
""")

    # Fixture 2: package.json with compromised npm package
    with open(os.path.join(tmpdir, "package.json"), "w") as f:
        json.dump({
            "name": "test-project",
            "dependencies": {
                "@emilgroup/auth-sdk": "^1.25.2",
                "express": "^4.18.0",
            },
            "scripts": {
                "start": "node server.js",
            },
        }, f)

    # Fixture 3: requirements.txt with compromised litellm
    with open(os.path.join(tmpdir, "requirements.txt"), "w") as f:
        f.write("flask>=2.0\nlitellm==1.82.8\nrequests>=2.28\n")

    # Fixture 4: Dockerfile with compromised trivy image
    with open(os.path.join(tmpdir, "Dockerfile"), "w") as f:
        f.write("FROM python:3.11\nRUN pip install trivy\n")

    # Fixture 5: File containing C2 domain
    with open(os.path.join(tmpdir, "suspicious.py"), "w") as f:
        f.write('url = "https://models.litellm.cloud/upload"\n')

    # Fixture 6: K8s manifest with wiper DaemonSet
    with open(os.path.join(tmpdir, "k8s-bad.yaml"), "w") as f:
        f.write("""apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: host-provisioner-iran
  namespace: kube-system
spec:
  template:
    spec:
      containers:
        - name: kamikaze
          image: alpine:latest
""")

    # Fixture 7: package-lock.json with compromised version
    with open(os.path.join(tmpdir, "package-lock.json"), "w") as f:
        json.dump({
            "name": "test-project",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/@opengov/form-renderer": {
                    "name": "@opengov/form-renderer",
                    "version": "0.2.20",
                },
            },
        }, f)


def run_self_test() -> bool:
    """Create test fixtures and validate scanner detection capabilities."""
    print(C.bold("\nRunning self-test with synthetic fixtures...\n"))

    with tempfile.TemporaryDirectory(prefix="teampcp_test_") as tmpdir:
        _create_test_fixtures(tmpdir)

        # Run scan
        config = ScanConfig(
            scan_path=Path(tmpdir),
            system_scan=False,
            verbose=True,
        )
        engine = ScanEngine(config)
        report = engine.run()

        # Validate expected findings
        all_findings = []
        for cat in report.categories:
            all_findings.extend(cat.findings)

        expected_checks = [
            ("GitHub Actions compromised tag", lambda f: "trivy-action" in f.title.lower() and f.severity >= Severity.CRITICAL),
            ("npm compromised package", lambda f: "emilgroup" in f.title.lower() or "canisterworm" in f.category),
            ("LiteLLM compromised version", lambda f: "litellm" in f.title.lower() and "1.82.8" in (f.detail or "")),
            ("C2 IOC detection", lambda f: "c2" in f.category.lower() and "litellm.cloud" in (f.evidence or "")),
            ("K8s DaemonSet IOC", lambda f: "host-provisioner-iran" in (f.evidence or f.title or "")),
            ("Lockfile compromised package", lambda f: "lockfile" in f.title.lower() and "opengov" in (f.evidence or f.title or "")),
        ]

        passed = 0
        failed = 0
        for check_name, check_fn in expected_checks:
            found = any(check_fn(f) for f in all_findings)
            if found:
                print(f"  {C.green_bold('PASS')}  {check_name}")
                passed += 1
            else:
                print(f"  {C.red_bold('FAIL')}  {check_name}")
                failed += 1

        print(f"\n  Results: {C.green_bold(str(passed))} passed, {C.red_bold(str(failed)) if failed else C.dim('0')} failed")
        print(f"  Total findings from fixtures: {len(all_findings)}")
        print()

        return failed == 0


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="teampcp-scanner",
        description=(
            "Detect exposure to the TeamPCP/Trivy supply chain attack (CVE-2026-33634). "
            "Scans for compromised GitHub Actions, npm packages (CanisterWorm), LiteLLM PyPI backdoor, "
            "Trivy binaries, Docker images, system persistence, C2 IOCs, and Kubernetes wiper components."
        ),
        epilog="Reference: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23",
    )
    p.add_argument(
        "--scan-path", type=Path, default=None,
        help="Path to scan (default: current directory)",
    )
    p.add_argument(
        "--system", action="store_true", default=False,
        help="Enable deep system checks (binaries, processes, installed packages, Docker images, K8s clusters)",
    )
    p.add_argument(
        "--json", dest="output_json", action="store_true",
        help="Output results as JSON",
    )
    p.add_argument(
        "--markdown", action="store_true",
        help="Output results as Markdown report",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed progress and informational findings",
    )
    p.add_argument(
        "--self-test", action="store_true",
        help="Run built-in test with synthetic fixtures to verify scanner accuracy",
    )
    p.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Self-test mode
    if args.self_test:
        if args.output_json or args.markdown:
            # Run self-test silently and output report in requested format
            config = ScanConfig(self_test=True, output_json=args.output_json, output_markdown=args.markdown)
            with tempfile.TemporaryDirectory(prefix="teampcp_test_") as tmpdir:
                _create_test_fixtures(tmpdir)
                config.scan_path = Path(tmpdir)
                engine = ScanEngine(config)
                report = engine.run()
                if args.output_json:
                    print(format_json(report))
                else:
                    print(format_markdown(report))
            sys.exit(0)
        else:
            success = run_self_test()
            sys.exit(0 if success else 1)

    config = ScanConfig(
        scan_path=args.scan_path,
        system_scan=args.system,
        verbose=args.verbose,
        output_json=args.output_json,
        output_markdown=args.markdown,
    )

    # Scanning indicator (terminal mode only)
    if not config.output_json and not config.output_markdown:
        target = str(config.scan_path) if config.scan_path else os.getcwd()
        print()
        print(C.dim(f"  Scanning {target} ..."))

    # Run scan
    engine = ScanEngine(config)
    report = engine.run()

    # Format output
    if config.output_json:
        print(format_json(report))
    elif config.output_markdown:
        print(format_markdown(report))
    else:
        print(format_terminal(report))

    # Exit code
    critical = report.summary["by_severity"].get("CRITICAL", 0)
    total = report.summary["total_findings"] - report.summary["by_severity"].get("INFO", 0)
    if critical > 0:
        sys.exit(2)
    elif total > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
