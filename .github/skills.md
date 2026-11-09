---
name: azure-devsecops-pipeline
description: >
  Implement, configure, validate and maintain a production-grade DevSecOps pipeline on
  GitHub Actions + GitHub Advanced Security + Microsoft Azure. Covers CodeQL SAST,
  Dependabot, secret scanning + push protection + Gitleaks, SCA, Docker/container
  security, Terraform/IaC security, SBOM + provenance (supply chain), OIDC to Azure,
  Azure Key Vault, policy enforcement, deployment gates, reporting, remediation and
  audit logging. Use when asked to "add security scanning", "set up DevSecOps",
  "secure the pipeline", "add CodeQL/Dependabot/Trivy/Checkov/Gitleaks", "harden
  Terraform", "secure Docker images", or "set up OIDC to Azure".
version: 1.0.0
owner: Data Excellence – DevSecOps
---

# Skill: Azure DevSecOps Pipeline (GitHub Actions + GHAS + Azure + Terraform + Docker)

> This file is an **executable instruction set** for an AI coding assistant. Follow it
> in order. Every section states WHAT to build, the EXACT files to create, HOW to
> validate them, and what NOT to do. Where a value depends on the repository, the
> skill tells you how to discover it — **never guess the language, framework,
> package manager, cloud resource or deployment target.**

---

## Table of contents

0. Operating rules for the assistant (read first)
1. Phase 0 – Repository discovery (mandatory before writing any file)
2. Target file layout
3. DevSecOps architecture – stages, triggers, outputs, failure handling
4. Security policy – severity model, gates, SLAs, exceptions
5. Static Application Security Testing (CodeQL)
6. Dependency security and Dependabot
7. Secret detection, push protection, Gitleaks, incident response
8. Software Composition Analysis (SCA)
9. Docker and container security
10. Infrastructure-as-Code security (Terraform)
11. Azure authentication with OIDC (no long-lived credentials)
12. Azure Key Vault integration
13. Software supply chain security (pinning, SBOM, provenance, Scorecard)
14. Security policy enforcement (rulesets, CODEOWNERS, environments, policy-as-code)
15. Deployment security validation
16. Vulnerability reporting and remediation workflow
17. Security monitoring and audit logging
18. Validation – how to prove the pipeline works
19. Maintenance and continuous improvement
20. Definition of done (acceptance checklist)

---

## 0. Operating rules for the assistant (read first)

These rules override any convenience shortcut. If a user request conflicts with them,
stop and explain the conflict.

### 0.1 Non-negotiable security rules

1. **Never print, echo, log, commit, upload or paste secrets** — not in workflow logs,
   step summaries, PR comments, SARIF, artifacts, issues or chat. Any value read at
   runtime from Key Vault or elsewhere MUST be masked with `::add-mask::` *before* any
   other use. Secret scanners MUST run in redact mode.
2. **No long-lived cloud credentials in GitHub.** Azure access uses OIDC workload
   identity federation only (`azure/login` with `client-id`/`tenant-id`/
   `subscription-id`). Never create or store `AZURE_CREDENTIALS` JSON, client secrets,
   storage account keys, ACR admin passwords or SAS tokens in GitHub secrets.
3. **Least privilege everywhere.** Every workflow starts with `permissions: {}` (or
   `contents: read`) at top level and grants only what each job needs.
4. **Never use `pull_request_target` to build or run code from a PR.** Never check out
   PR head code in a privileged context. Never interpolate untrusted input
   (`github.event.pull_request.title`, `head_ref`, issue bodies, commit messages)
   directly into `run:` scripts — pass it through `env:` and quote it.
5. **Pin every third-party action to a full 40-char commit SHA** with the version in a
   trailing comment (`uses: owner/action@<sha> # vX.Y.Z`). The examples in this file
   use version tags for readability; **you must convert them to SHAs before
   committing** (see §13.1). Dependabot keeps SHA pins up to date.
6. **Do not weaken a security gate to make a build pass.** Do not add
   `continue-on-error: true`, `exit-code: 0`, `--soft-fail`, blanket ignore files,
   `skip-check` without justification, or lower severity thresholds unless the user
   explicitly asks AND a documented exception (§4.5) exists.
7. **Never auto-merge security-sensitive changes** (major versions, security
   advisories, workflow files, IaC, Dockerfiles, auth code) without all required
   checks passing and an explicitly configured approval policy (§6.5).
8. **Never run code fetched from the internet** (install scripts, curl | bash) inside
   workflows unless it is version-pinned AND checksum- or signature-verified.
9. **Do not assume a technology stack.** Run Phase 0 first and generate only the
   configuration that matches what was detected.
10. **Removing a secret from Git history never replaces revoking and rotating it.**

### 0.2 Working style

- Make the smallest complete change that delivers a working, gated pipeline; then
  iterate. Keep each workflow independently runnable.
- After generating files, run the local validation in §18 and report the actual
  observed results. Never claim a workflow passes unless a run (local or GitHub) shows it.
- When a feature depends on the GitHub plan (e.g., secret scanning on private repos,
  code scanning merge protection, custom patterns), check availability (§1.4) and
  document the fallback (Gitleaks, required status checks) instead of silently skipping it.
- Record every decision, default and deviation in `docs/security/DEVSECOPS.md`.

---

## 1. Phase 0 – Repository discovery (mandatory)

Run these commands and record the results in `docs/security/DEVSECOPS.md` under
"Repository inventory". All later sections consume this inventory.

### 1.1 Languages and frameworks

```bash
# Languages GitHub detects (authoritative for CodeQL mapping)
gh api "repos/{owner}/{repo}/languages" --jq 'to_entries|sort_by(-.value)|.[]|"\(.key)\t\(.value)"'

# Local fallback (works offline / before first push)
git ls-files | sed -n 's/.*\.\([A-Za-z0-9]*\)$/\1/p' | sort | uniq -c | sort -rn | head -25
```

### 1.2 Package manifests → Dependabot ecosystems and SCA tools

```bash
git ls-files | grep -E '(^|/)(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|Pipfile(\.lock)?|uv\.lock|setup\.py|[^/]*\.csproj|packages\.lock\.json|Directory\.Packages\.props|global\.json|pom\.xml|build\.gradle(\.kts)?|go\.mod|Cargo\.toml|Gemfile|composer\.json|Dockerfile[^/]*|[^/]*\.dockerfile|docker-compose[^/]*\.ya?ml|compose\.ya?ml|[^/]*\.tf|\.terraform\.lock\.hcl|Chart\.yaml|[^/]*\.bicep)$' \
  | sort
ls .github/workflows 2>/dev/null
```

Use this mapping (keep only rows that match detected files):

| Detected file(s) | CodeQL language (`build-mode`) | Dependabot `package-ecosystem` | Ecosystem audit tool |
|---|---|---|---|
| `package.json` + lockfile, `.js/.ts` | `javascript-typescript` (`none`) | `npm` (also yarn/pnpm) | `npm audit --omit=dev` / `pnpm audit` |
| `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile` | `python` (`none`) | `pip` / `uv` (Poetry & Pipenv use `pip`) | `pip-audit` |
| `*.csproj`, `*.sln`, `Directory.Packages.props` | `csharp` (`none`, or `autobuild`/`manual` if needed) | `nuget` (+ `dotnet-sdk` for `global.json`) | `dotnet list package --vulnerable --include-transitive` |
| `pom.xml`, `build.gradle(.kts)` | `java-kotlin` (`none` or `autobuild`) | `maven` / `gradle` | OWASP Dependency-Check |
| `go.mod` | `go` (`autobuild`) | `gomod` | `govulncheck ./...` |
| `Cargo.toml` | `rust` (`none`) | `cargo` | `cargo audit` |
| `Gemfile` | `ruby` (`none`) | `bundler` | `bundle audit` |
| `composer.json` | not supported by CodeQL – use Semgrep/PHPStan | `composer` | `composer audit` |
| `*.c/*.cpp/*.h` | `c-cpp` (`autobuild` or `manual`) | n/a | Trivy fs |
| `*.swift` | `swift` (`autobuild`, macOS runner) | `swift` | Trivy fs |
| `.github/workflows/*.yml` | `actions` (`none`) | `github-actions` | zizmor / actionlint |
| `Dockerfile*`, compose files | n/a | `docker` / `docker-compose` | Hadolint + Trivy config/image |
| `*.tf`, `.terraform.lock.hcl` | n/a | `terraform` | TFLint + Checkov + Trivy config |
| `*.bicep` | n/a | n/a (`bicep` not supported) | Checkov / PSRule for Azure |

### 1.3 Build, test and deployment target

Identify and record (read `README*`, existing workflows, `Makefile`, `package.json`
scripts, `*.csproj`, `pyproject.toml`, Terraform resources):

- Build command and test command (re-used by Dependabot PR validation, §6.4).
- Whether the app ships as a container, and every Dockerfile path / build context.
- Azure deployment target: Container Apps, App Service, AKS, Functions, Static Web Apps
  (search `*.tf` for `azurerm_container_app`, `azurerm_linux_web_app`,
  `azurerm_kubernetes_cluster`, `azurerm_linux_function_app`).
- Azure Container Registry name(s), Key Vault name(s), Terraform root modules and
  backend configuration (`backend "azurerm"` blocks).
- Environments (dev / staging / prod) and their subscriptions.

If a required fact cannot be discovered, ask the user once with all open questions
batched; otherwise take the safe default and record it.

### 1.4 GitHub plan and feature availability

```bash
gh api "repos/{owner}/{repo}" --jq '{visibility, security_and_analysis}'
```

| Feature | Public repo | Private/internal repo |
|---|---|---|
| CodeQL code scanning | Free | Requires **GitHub Code Security** (formerly GHAS) |
| Secret scanning + push protection | Free | Requires **GitHub Secret Protection** (formerly GHAS) |
| Custom secret patterns, delegated bypass, Copilot generic-secret detection | n/a | Secret Protection |
| Dependency graph, Dependabot alerts/updates | Free | Free |
| Dependency review action | Free | Requires Code Security |
| Artifact attestations | Free | Requires GitHub Enterprise Cloud |
| Audit-log streaming | n/a | Enterprise |

If a feature is unavailable, implement the documented fallback and record it:
CodeQL unavailable → Semgrep OSS + SARIF artifact; secret scanning unavailable →
Gitleaks is the required gate; dependency review unavailable → Trivy fs + ecosystem
audit as required gate; attestations unavailable → Cosign keyless signing (§13.4).

---

## 2. Target file layout

Generate only the files relevant to the detected stack.

```
.github/
├── CODEOWNERS
├── dependabot.yml
├── secret_scanning.yml                 # paths excluded from GitHub secret scanning (minimal)
├── codeql/
│   ├── codeql-config.yml
│   └── custom-queries/<language>/      # optional custom QL pack
├── scripts/
│   ├── validate_exceptions.py
│   └── security_summary.sh
└── workflows/
    ├── codeql.yml                      # SAST
    ├── secret-scan.yml                 # Gitleaks (PR, push, weekly full history)
    ├── sca.yml                         # dependency review + Trivy fs + ecosystem audit
    ├── iac-security.yml                # Terraform fmt/validate/TFLint/Checkov/Trivy + plan/apply
    ├── container-security.yml          # Hadolint, build, Trivy image, runtime checks, SBOM, push, attest
    ├── deploy.yml                      # gated, environment-aware deployment by digest
    ├── security-policy.yml             # workflow lint (actionlint, zizmor), exception validation
    ├── scorecard.yml                   # OpenSSF Scorecard
    ├── security-report.yml             # scheduled posture report
    └── dependabot-auto-merge.yml       # OPT-IN, disabled by default
.security/
├── exceptions.yaml                     # single register of approved risk exceptions
└── README.md
.gitleaks.toml
.gitleaksignore                         # fingerprints only, each referenced in exceptions.yaml
.trivyignore.yaml
trivy.yaml
.checkov.yaml
.tflint.hcl
.hadolint.yaml
.pre-commit-config.yaml
.dockerignore
SECURITY.md
docs/security/
├── DEVSECOPS.md                        # inventory, decisions, architecture, runbooks
├── secret-incident-response.md
└── vulnerability-management.md
```

---

## 3. DevSecOps architecture

### 3.1 Flow

```
 Developer workstation            Pull request                         main branch                  Release / deploy
 ───────────────────────          ───────────────────────────────      ─────────────────────────    ─────────────────────────────
 pre-commit: gitleaks,      ──►   CodeQL (SAST)                  ──►   CodeQL + full scans     ──►  verify provenance + SBOM
 terraform fmt, tflint,           Gitleaks (PR range)                  Build image → scan →         re-scan image by digest
 hadolint, checkov                Dependency review (SCA)              push to ACR by digest        environment approval (prod)
                                  Trivy fs (SCA, secrets, misconfig)   SBOM + provenance attest     OIDC → Azure, secrets from KV
 GitHub push protection     ──►   IaC: fmt/validate/TFLint/            Terraform plan → apply       deploy by digest → smoke test
 blocks known secrets             Checkov/Trivy + plan (OIDC)          (environment-gated)          post-deploy Defender check
                                  Container: Hadolint, build,
                                  Trivy image, non-root/RO checks      Scheduled: weekly CodeQL, full-history Gitleaks,
                                  Policy: actionlint, zizmor,          Trivy re-scan of deployed digests, Scorecard,
                                  exception register validation        posture report → GitHub issue
                                  Rulesets enforce all of the above    Continuous: Dependabot alerts + PRs,
                                                                       Defender for Cloud, Sentinel, audit logs
```

### 3.2 Stage contract

| # | Stage | Purpose | Trigger | Tooling | Expected output | Failure handling |
|---|---|---|---|---|---|---|
| 1 | Source code security | Stop secrets & obvious defects before they leave the laptop | `git commit` (pre-commit), `git push` | pre-commit, Gitleaks, push protection | Blocked commit/push with redacted finding | Developer fixes locally; push-protection bypass requires a reason and is audited |
| 2 | PR security validation | Single merge gate aggregating all checks | `pull_request` to `main`/`release/*` | Rulesets + required checks | Check runs + code-scanning annotations on the PR diff | Merge blocked until all required checks pass |
| 3 | SAST | Find code-level vulnerabilities | PR, push to `main`, weekly cron | CodeQL | SARIF in Code Scanning, PR annotations | Ruleset blocks merge on new alerts ≥ High security severity or `error` |
| 4 | Dependency scanning (SCA) | Find vulnerable/ill-licensed direct & transitive deps | PR, push, daily cron, Dependabot | Dependency review, Trivy fs, ecosystem audits, Dependabot | PR summary comment, SARIF, JSON report artifact | Fail on fixable Critical/High (configurable); exceptions via register |
| 5 | Secret detection | Prevent and detect credentials in code/history | push, PR, weekly full history | GitHub secret scanning, push protection, Gitleaks | Secret scanning alerts; redacted SARIF | Fail job; trigger incident response (§7.7) – revoke & rotate first |
| 6 | IaC scanning | Prevent insecure Azure infrastructure | PR/push touching IaC, weekly | terraform fmt/validate, TFLint, Checkov, Trivy config | SARIF + PR plan summary (no secrets) | Fail on any failed policy without justified inline skip |
| 7 | Docker image scanning | Prevent vulnerable/misconfigured images | PR/push touching app or Dockerfile, daily re-scan | Hadolint, Trivy config/image, runtime config checks | SARIF + JSON report, image config check results | Fail PR on fixable Critical/High; block push/promotion |
| 8 | Supply chain security | Prove what was built, from what, by whom | push to `main`, release | SHA pinning, SBOM (Syft), build provenance + SBOM attestations, Scorecard | SPDX/CycloneDX SBOM, signed attestations in registry and GitHub | Release blocked if SBOM/attestation missing |
| 9 | Policy enforcement | Make controls mandatory, not advisory | Every PR; settings drift weekly | Rulesets, CODEOWNERS, environments, actionlint, zizmor, exception validator | Enforced protections; policy check results | PR blocked; drift → issue to security owners |
| 10 | Deployment validation | Only verified, scanned artifacts reach Azure | `workflow_run` (dev), manual dispatch (staging/prod) | `gh attestation verify`, Trivy, OIDC, Key Vault, environment approvals | Deployed digest + evidence in step summary | Deployment aborted; nothing partially promoted |
| 11 | Reporting & remediation | Track risk to closure within SLA | Weekly cron + on gate failure | Code scanning/Dependabot/secret alerts APIs, issues | Posture issue with counts by severity and SLA breaches | SLA breach escalated to owners (§16) |

---

## 4. Security policy – severity model, gates, SLAs, exceptions

Write this section verbatim (adapted to the project) into
`docs/security/vulnerability-management.md`, and keep the gate values in repository
**variables** so they are environment-aware and changeable without editing workflows.

### 4.1 Severity levels

| Severity | Typical source score | Meaning |
|---|---|---|
| **Critical** | CVSS ≥ 9.0, CodeQL `security-severity` ≥ 9.0, any verified live secret | Remotely exploitable, high impact, or credential exposure |
| **High** | CVSS 7.0–8.9 | Exploitable with significant impact |
| **Medium** | CVSS 4.0–6.9 | Limited impact or hard to exploit |
| **Low** | CVSS 0.1–3.9 | Minimal impact / defence-in-depth |

Raise severity one level when the component is internet-facing **and** a public exploit
or a CISA KEV listing exists. Never lower severity without a documented exception.

### 4.2 Gate matrix

| Gate | Critical | High | Medium | Low |
|---|---|---|---|---|
| PR (code, deps, IaC, image) | **Block** | **Block** if a fix exists; else warn + exception required before release | Report | Report |
| Release / promotion to prod | **Block** (fixed or unfixed) unless approved exception | **Block** unless fixed or approved exception | Report; SLA tracked | Report |
| Secrets | **Block always** (no exception for live secrets) | — | — | — |
| IaC policy (Checkov / Trivy config) | **Block** any failed check without an inline justified skip | | | |

Repository variables (Settings → Secrets and variables → Actions → Variables):

| Variable | Default | Used by |
|---|---|---|
| `SEC_PR_FAIL_SEVERITY` | `CRITICAL,HIGH` | Trivy PR gates |
| `SEC_PR_IGNORE_UNFIXED` | `true` | Trivy PR gates (fixable only) |
| `SEC_RELEASE_FAIL_SEVERITY` | `CRITICAL,HIGH` | deploy re-scan |
| `SEC_RELEASE_IGNORE_UNFIXED` | `false` | deploy re-scan |
| `SEC_DEP_REVIEW_FAIL_SEVERITY` | `high` | dependency review |

### 4.3 Remediation SLAs (from detection)

| Severity | Internet-facing / prod | Internal / non-prod |
|---|---|---|
| Critical | 72 hours (live secret: revoke **immediately**, ≤ 1 h) | 7 days |
| High | 14 days | 30 days |
| Medium | 60 days | 90 days |
| Low | 180 days or next major refactor | Best effort |

### 4.4 Remediation order of preference

1. Upgrade to the patched version (direct dependency, or override/resolution for transitive).
2. Replace the component.
3. Remove the vulnerable code path / feature flag it off.
4. Compensating control (WAF rule, network isolation, input validation) **plus** an exception.
5. Accept risk via an exception (Medium/Low only, unless CISO-level approval).

### 4.5 Exception (risk acceptance) register

All suppressions in any tool MUST reference an entry in `.security/exceptions.yaml`.
Suppressions without a register entry are rejected by `security-policy.yml`.

```yaml
# .security/exceptions.yaml
# Every suppression (Trivy ignore, Checkov skip, Gitleaks fingerprint, dismissed alert)
# MUST have an entry here. Max duration: Critical 30d, High 90d, Medium/Low 180d.
version: 1
exceptions:
  - id: EXC-0001
    tool: trivy                  # trivy | checkov | gitleaks | codeql | dependency-review | hadolint
    finding: CVE-2024-00000      # CVE / GHSA / rule id / check id / fingerprint
    scope: "ghcr.io/example/app:* / package-name@1.2.3"
    severity: HIGH
    justification: >
      Vulnerable function is not reachable: the parser is only used on trusted,
      build-time input. Verified by code search and call-graph review.
    compensating_controls: "Input never user-controlled; WAF rule 942100 enabled."
    owner: "@org/team-name"
    approved_by: "@security-approver"
    approved_on: 2026-11-09
    expires_on: 2027-02-07
    ticket: "SEC-123"
```

Rules:

- `expires_on` is mandatory. Expired exceptions make the policy check fail.
- Approval must come from someone listed in CODEOWNERS for `/.security/` (not the author).
- Tool-level suppressions must carry the exception id, e.g.
  `#checkov:skip=CKV_AZURE_33:EXC-0002 queue logging handled by diagnostic setting`.
- Dismissing a GitHub code scanning / Dependabot alert requires choosing a reason and a
  comment that includes the exception id.

### 4.6 Exception validator

Create `.github/scripts/validate_exceptions.py`:

```python
#!/usr/bin/env python3
"""Validate .security/exceptions.yaml and make sure every tool suppression is registered.

Exit code 1 on any violation. Never prints secret material (only ids/paths).
"""
import datetime as dt
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTER = ROOT / ".security" / "exceptions.yaml"
MAX_DAYS = {"CRITICAL": 30, "HIGH": 90, "MEDIUM": 180, "LOW": 180}
REQUIRED = ["id", "tool", "finding", "scope", "severity", "justification",
            "owner", "approved_by", "approved_on", "expires_on"]
errors: list[str] = []


def as_date(value, field, exc_id):
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        errors.append(f"{exc_id}: '{field}' is not an ISO date")
        return None


def load_register():
    if not REGISTER.exists():
        return {}
    data = yaml.safe_load(REGISTER.read_text()) or {}
    today = dt.date.today()
    ids = {}
    for exc in data.get("exceptions") or []:
        exc_id = exc.get("id", "<missing id>")
        for field in REQUIRED:
            if not exc.get(field):
                errors.append(f"{exc_id}: missing required field '{field}'")
        sev = str(exc.get("severity", "")).upper()
        if sev not in MAX_DAYS:
            errors.append(f"{exc_id}: severity must be one of {sorted(MAX_DAYS)}")
        approved = as_date(exc.get("approved_on"), "approved_on", exc_id)
        expires = as_date(exc.get("expires_on"), "expires_on", exc_id)
        if expires and expires < today:
            errors.append(f"{exc_id}: expired on {expires}")
        if approved and expires and sev in MAX_DAYS and (expires - approved).days > MAX_DAYS[sev]:
            errors.append(f"{exc_id}: duration exceeds {MAX_DAYS[sev]} days for {sev}")
        if exc.get("owner") and exc.get("owner") == exc.get("approved_by"):
            errors.append(f"{exc_id}: owner cannot approve their own exception")
        if exc_id in ids:
            errors.append(f"{exc_id}: duplicate id")
        ids[exc_id] = exc
    return ids


def check_suppressions(ids):
    exc_ref = re.compile(r"EXC-\d{4}")
    # Checkov inline skips in Terraform / Dockerfiles
    for path in list(ROOT.rglob("*.tf")) + list(ROOT.rglob("Dockerfile*")):
        if ".terraform" in path.parts:
            continue
        for n, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if "checkov:skip=" in line:
                ref = exc_ref.search(line)
                if not ref or ref.group(0) not in ids:
                    errors.append(f"{path.relative_to(ROOT)}:{n}: checkov skip without registered EXC id")
    # Trivy YAML ignore file
    trivy_ignore = ROOT / ".trivyignore.yaml"
    if trivy_ignore.exists():
        data = yaml.safe_load(trivy_ignore.read_text()) or {}
        for section in ("vulnerabilities", "misconfigurations", "secrets", "licenses"):
            for item in data.get(section) or []:
                stmt = str(item.get("statement", ""))
                ref = exc_ref.search(stmt)
                if not ref or ref.group(0) not in ids:
                    errors.append(f".trivyignore.yaml: {item.get('id')} lacks registered EXC id in 'statement'")
                if not item.get("expired_at"):
                    errors.append(f".trivyignore.yaml: {item.get('id')} lacks 'expired_at'")
    if (ROOT / ".trivyignore").exists():
        errors.append(".trivyignore (plain) is not allowed; use .trivyignore.yaml with expiry")
    # Gitleaks fingerprints: line must be followed by '# EXC-NNNN'
    gl = ROOT / ".gitleaksignore"
    if gl.exists():
        for n, line in enumerate(gl.read_text().splitlines(), 1):
            if line.strip() and not line.lstrip().startswith("#"):
                ref = exc_ref.search(line)
                if not ref or ref.group(0) not in ids:
                    errors.append(f".gitleaksignore:{n}: fingerprint without registered EXC id")


if __name__ == "__main__":
    check_suppressions(load_register())
    if errors:
        print("Security exception policy violations:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print("Exception register and suppressions are valid.")
```

---

## 5. Static Application Security Testing (CodeQL)

### 5.1 Default vs advanced setup

- Use **advanced setup** (workflow below) when you need a config file, custom queries,
  path filters, or a manual build. Use **default setup** only for simple repos with no
  customisation needs.
- Default and advanced setup cannot both be active. Before committing `codeql.yml`,
  disable default setup:
  `gh api -X PATCH "repos/{owner}/{repo}/code-scanning/default-setup" -f state=not-configured`.

### 5.2 Language detection

The workflow detects CodeQL-supported languages from the GitHub languages API at
runtime, so new languages are picked up automatically. It always includes `actions`
(to scan workflow files). Compiled languages that need a build are mapped to the right
`build-mode`. If Phase 0 shows a compiled language that cannot be built with
`autobuild`, set `build-mode: manual` for it and fill in the build step.

### 5.3 `.github/workflows/codeql.yml`

```yaml
name: CodeQL

on:
  pull_request:
    branches: [main, "release/**"]
  push:
    branches: [main, "release/**"]
  schedule:
    - cron: "27 3 * * 1"          # weekly, Monday 03:27 UTC – picks up new queries
  workflow_dispatch:

permissions: {}

concurrency:
  group: codeql-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  detect:
    name: Detect CodeQL languages
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
    outputs:
      matrix: ${{ steps.detect.outputs.matrix }}
    steps:
      - id: detect
        env:
          GH_TOKEN: ${{ github.token }}
          REPO: ${{ github.repository }}
        run: |
          set -euo pipefail
          langs=$(gh api "repos/${REPO}/languages" --jq 'keys[]')
          include='[{"language":"actions","build-mode":"none"}]'
          add() { include=$(jq -c --arg l "$1" --arg b "$2" '. + [{"language":$l,"build-mode":$b}] | unique_by(.language)' <<<"$include"); }
          while IFS= read -r l; do
            case "$l" in
              JavaScript|TypeScript|Vue|Svelte) add javascript-typescript none ;;
              Python)                           add python none ;;
              C#)                               add csharp none ;;
              Java|Kotlin)                      add java-kotlin none ;;
              Go)                               add go autobuild ;;
              Ruby)                             add ruby none ;;
              Rust)                             add rust none ;;
              C|C++)                            add c-cpp autobuild ;;
              Swift)                            add swift autobuild ;;
            esac
          done <<<"$langs"
          echo "Detected CodeQL targets: $include"
          echo "matrix={\"include\":$include}" >> "$GITHUB_OUTPUT"

  analyze:
    name: Analyze (${{ matrix.language }})
    needs: detect
    runs-on: ${{ matrix.language == 'swift' && 'macos-latest' || 'ubuntu-latest' }}
    timeout-minutes: 120
    permissions:
      contents: read
      actions: read
      packages: read            # needed only for private CodeQL packs
      security-events: write    # upload SARIF to Code Scanning
    strategy:
      fail-fast: false
      matrix: ${{ fromJSON(needs.detect.outputs.matrix) }}
    steps:
      - name: Harden runner
        uses: step-security/harden-runner@v2
        with:
          egress-policy: audit   # switch to 'block' with an allow-list once stable

      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          build-mode: ${{ matrix.build-mode }}
          config-file: ./.github/codeql/codeql-config.yml

      # Only used when a language is switched to build-mode: manual.
      - name: Manual build
        if: matrix.build-mode == 'manual'
        run: |
          echo "Replace with the project's build command discovered in Phase 0" >&2
          exit 1

      - name: Perform CodeQL analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

### 5.4 `.github/codeql/codeql-config.yml`

```yaml
name: "Security CodeQL config"

# security-extended = default security queries + lower-precision security queries.
# Use security-and-quality only if the team will triage quality alerts too.
queries:
  - uses: security-extended

# Optional custom pack (see 5.5). Remove if not used.
# packs:
#   python:
#     - ./.github/codeql/custom-queries/python

paths-ignore:
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/*.min.js"
  - "**/test/fixtures/**"
  # Do NOT ignore application test code wholesale without a reason; tests can leak secrets/SSRF helpers.

# Exclude specific noisy queries ONLY with a documented exception id:
# query-filters:
#   - exclude:
#       id: js/some-query-id     # EXC-0003
```

### 5.5 Custom security queries (optional)

Add custom queries only for organisation-specific risks (e.g., a banned internal API,
an in-house crypto wrapper misuse). Layout:

```
.github/codeql/custom-queries/<language>/
├── qlpack.yml
└── BannedFunction.ql
```

`qlpack.yml` (example for Python):

```yaml
name: org/python-custom-security
version: 0.0.1
library: false
dependencies:
  codeql/python-all: "*"
```

`BannedFunction.ql`:

```ql
/**
 * @name Use of banned insecure deserialization helper
 * @description Calls to legacy_loads() deserialize untrusted data.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id org/python/banned-legacy-loads
 * @tags security external/cwe/cwe-502
 */
import python

from Call c
where c.getFunc().(Name).getId() = "legacy_loads"
select c, "Banned function legacy_loads() used; use safe_loads() instead."
```

Reference it from `codeql-config.yml` under `packs:` and validate locally with the
CodeQL CLI (`codeql query compile`) before committing.

### 5.6 Integration with PR review

- CodeQL alerts on changed lines appear as PR annotations automatically.
- Enforce via ruleset **code scanning merge protection** (§14.1): block when CodeQL
  reports new alerts with security severity `high_or_higher` or alert severity `errors`.
- Enable **Copilot Autofix** for code scanning (Settings → Advanced Security) where
  licensed; autofix suggestions still require human review and passing checks.
- Required action on a new CodeQL alert: fix in the PR, or dismiss with reason
  (`false positive` / `used in tests` / `won't fix`) **and** an exception id comment.

---

## 6. Dependency security and Dependabot

### 6.1 Enable repository features

```bash
gh api -X PUT "repos/{owner}/{repo}/vulnerability-alerts"          # Dependabot alerts (requires dependency graph)
gh api -X PUT "repos/{owner}/{repo}/automated-security-fixes"      # Dependabot security updates
gh api -X PATCH "repos/{owner}/{repo}" --input - <<'JSON'
{ "security_and_analysis": { "dependency_graph": { "status": "enabled" } } }
JSON
```

(The `dependency_graph` key may be rejected on public repos where it is always on —
that is fine.) For ecosystems whose transitive graph GitHub cannot read statically
(e.g., Gradle, some Maven setups), add a dependency submission action
(`gradle/actions/dependency-submission`, `advanced-security/maven-dependency-submission-action`)
so Dependabot alerts cover transitive dependencies.

### 6.2 `.github/dependabot.yml`

Keep **only** the ecosystems detected in Phase 0. A Dependabot entry pointing at a
directory without a manifest fails. Use `directories` (glob-capable) for monorepos.

```yaml
version: 2

# Private registries (only if the project uses them). Credentials come from
# *Dependabot secrets* (Settings → Secrets → Dependabot), never Actions secrets.
# registries:
#   acr:
#     type: docker-registry
#     url: myregistry.azurecr.io
#     username: ${{ secrets.ACR_DEPENDABOT_USER }}      # token-scoped, pull-only
#     password: ${{ secrets.ACR_DEPENDABOT_TOKEN }}

updates:
  # ── GitHub Actions (always) ────────────────────────────────────────────────
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule: { interval: "weekly", day: "monday", time: "05:00", timezone: "Africa/Lagos" }
    open-pull-requests-limit: 5
    commit-message: { prefix: "ci", include: "scope" }
    labels: ["dependencies", "github-actions", "security-review"]
    groups:
      actions-minor-patch:
        applies-to: version-updates
        update-types: ["minor", "patch"]

  # ── Docker base images (if Dockerfiles exist) ──────────────────────────────
  - package-ecosystem: "docker"
    directories: ["/", "/src/**"]           # adjust to Dockerfile locations from Phase 0
    schedule: { interval: "weekly", day: "monday", time: "05:00", timezone: "Africa/Lagos" }
    open-pull-requests-limit: 5
    commit-message: { prefix: "build", include: "scope" }
    labels: ["dependencies", "docker", "security-review"]
    ignore:
      # Major base-image jumps (e.g. OS release) are planned work, not auto-PRs.
      - dependency-name: "*"
        update-types: ["version-update:semver-major"]

  # ── Docker Compose (if compose files exist) ────────────────────────────────
  - package-ecosystem: "docker-compose"
    directory: "/"
    schedule: { interval: "weekly" }
    labels: ["dependencies", "docker"]

  # ── Terraform providers & modules (if *.tf exists) ─────────────────────────
  - package-ecosystem: "terraform"
    directories: ["/infra/**"]              # adjust to Terraform roots/modules
    schedule: { interval: "weekly", day: "tuesday", time: "05:00", timezone: "Africa/Lagos" }
    open-pull-requests-limit: 5
    commit-message: { prefix: "infra", include: "scope" }
    labels: ["dependencies", "terraform", "security-review"]
    groups:
      terraform-providers:
        applies-to: version-updates
        update-types: ["minor", "patch"]

  # ── Application ecosystem: keep the block(s) matching Phase 0 ─────────────
  # npm / yarn / pnpm
  - package-ecosystem: "npm"
    directory: "/"
    schedule: { interval: "daily", time: "05:00", timezone: "Africa/Lagos" }
    open-pull-requests-limit: 10
    versioning-strategy: increase-if-necessary
    commit-message: { prefix: "deps", prefix-development: "deps-dev", include: "scope" }
    labels: ["dependencies", "javascript"]
    groups:
      security-fixes:                # one PR per run for all security fixes
        applies-to: security-updates
        patterns: ["*"]
      prod-minor-patch:
        applies-to: version-updates
        dependency-type: "production"
        update-types: ["minor", "patch"]
      dev-minor-patch:
        applies-to: version-updates
        dependency-type: "development"
        update-types: ["minor", "patch"]

  # Python (pip / pip-compile / poetry / pipenv) – use "uv" if uv.lock is present
  # - package-ecosystem: "pip"
  #   directory: "/"
  #   schedule: { interval: "daily", time: "05:00", timezone: "Africa/Lagos" }
  #   open-pull-requests-limit: 10
  #   labels: ["dependencies", "python"]
  #   groups:
  #     security-fixes: { applies-to: security-updates, patterns: ["*"] }
  #     minor-patch:    { applies-to: version-updates, update-types: ["minor", "patch"] }

  # .NET
  # - package-ecosystem: "nuget"
  #   directory: "/"
  #   schedule: { interval: "daily" }
  #   open-pull-requests-limit: 10
  #   labels: ["dependencies", "dotnet"]
  #   groups:
  #     security-fixes: { applies-to: security-updates, patterns: ["*"] }
  #     microsoft:      { applies-to: version-updates, patterns: ["Microsoft.*", "System.*"], update-types: ["minor", "patch"] }

  # Java
  # - package-ecosystem: "maven"     # or "gradle"
  #   directory: "/"
  #   schedule: { interval: "daily" }
  #   labels: ["dependencies", "java"]

  # Go
  # - package-ecosystem: "gomod"
  #   directory: "/"
  #   schedule: { interval: "daily" }
  #   labels: ["dependencies", "go"]
```

Version update strategy rules:

- `versioning-strategy: increase-if-necessary` for apps with lockfiles (keeps ranges,
  updates lockfile); `increase` for libraries only if the team wants ranges bumped.
- Major versions are never grouped and never auto-merged.
- Security updates are grouped separately (`applies-to: security-updates`) so they
  are never blocked behind feature updates.
- If supported by the GitHub version in use, add `cooldown: { default-days: 3 }` to
  version updates (not security updates) to avoid adopting freshly-published,
  possibly-compromised releases. Validate the config after adding it (§18.1).

### 6.3 Dependency vulnerability alerts

- Dependabot alerts are the system of record for known-vulnerable dependencies.
- Enable **Dependabot auto-triage rules** (Settings → Advanced Security) only for
  documented low-risk cases (e.g., dev-only dependency, Low severity), and record each
  rule in `.security/exceptions.yaml` as a `dependency-review` exception.
- Alerts are triaged per §16.

### 6.4 Dependabot PRs must run the full pipeline

- All security workflows trigger on `pull_request`, so Dependabot PRs run them
  automatically. Dependabot-triggered runs get a **read-only token and no Actions
  secrets** — that is intended. Do not convert workflows to `pull_request_target`
  to get secrets.
- The project's build/test workflow must also run on `pull_request` (no path filter
  that excludes manifests/lockfiles). Required checks (§14.1) apply to Dependabot PRs.
- Jobs that need Azure (Terraform plan) are skipped for Dependabot and forked PRs
  (see §10.6); static scans still run and remain required.

### 6.5 Auto-merge policy (OPT-IN, disabled by default)

Auto-merge is allowed **only** when ALL of these are true:

1. Repository variable `DEPENDABOT_AUTOMERGE_ENABLED` is `true` (explicit opt-in).
2. Update type is `semver-patch` (or `semver-minor` for `development` dependencies).
3. The PR is not a security advisory fix of severity High/Critical, and the
   ecosystem is not `github-actions`, `docker` or `terraform` (these always need human review).
4. Branch ruleset requires all checks + at least one approving review; GitHub's
   native auto-merge waits for them. The workflow below only *approves and enables*
   auto-merge; it cannot bypass required checks.

`.github/workflows/dependabot-auto-merge.yml`:

```yaml
name: Dependabot auto-merge (opt-in)

on: pull_request

permissions: {}

jobs:
  automerge:
    if: github.event.pull_request.user.login == 'dependabot[bot]' && vars.DEPENDABOT_AUTOMERGE_ENABLED == 'true'
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: write
      pull-requests: write
    steps:
      - id: meta
        uses: dependabot/fetch-metadata@v2
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Approve and enable auto-merge for low-risk updates only
        if: >-
          steps.meta.outputs.package-ecosystem != 'github_actions' &&
          steps.meta.outputs.package-ecosystem != 'docker' &&
          steps.meta.outputs.package-ecosystem != 'terraform' &&
          (steps.meta.outputs.alert-state == '' || steps.meta.outputs.cvss < 7.0) &&
          (steps.meta.outputs.update-type == 'version-update:semver-patch' ||
           (steps.meta.outputs.update-type == 'version-update:semver-minor' &&
            steps.meta.outputs.dependency-type == 'direct:development'))
        env:
          PR_URL: ${{ github.event.pull_request.html_url }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh pr review --approve "$PR_URL"
          gh pr merge --auto --squash "$PR_URL"
```

Note: a review by `github-actions[bot]` only satisfies "required approvals" if the
ruleset allows it; if the ruleset requires a CODEOWNER/human approval, auto-merge
waits for that human — which is the desired behaviour for production repos. Repository
setting "Allow auto-merge" must be enabled for `gh pr merge --auto` to work.

### 6.6 Automated dependency remediation – documented flow

```
Advisory published → Dependabot alert (severity, patched version)
  → Dependabot security update PR (grouped)  → all PR security & test workflows run
  → Dependency review + Trivy confirm the CVE is resolved and no new ones introduced
  → CODEOWNER review (or opt-in auto-merge for patch-level, non-sensitive deps)
  → merge → main pipeline rebuilds image, regenerates SBOM, re-attests → deploy
  → alert auto-closes; SLA clock stops.
If no patched version exists: exception (§4.5) + compensating control + weekly re-check.
If Dependabot cannot update (transitive pin conflict): add an override
(npm "overrides", pip constraint, NuGet central package pin, Maven dependencyManagement)
in a manual PR referencing the alert.
```

---

## 7. Secret detection, push protection, Gitleaks and incident response

### 7.1 Enable GitHub secret scanning and push protection

```bash
gh api -X PATCH "repos/{owner}/{repo}" --input - <<'JSON'
{
  "security_and_analysis": {
    "secret_scanning":                       { "status": "enabled" },
    "secret_scanning_push_protection":       { "status": "enabled" },
    "secret_scanning_non_provider_patterns": { "status": "enabled" },
    "secret_scanning_validity_checks":       { "status": "enabled" }
  }
}
JSON
gh api "repos/{owner}/{repo}" --jq '.security_and_analysis'   # verify
```

- Prefer enabling at **organisation level** via a security configuration so new repos
  inherit it.
- Enable **Copilot secret scanning / generic secret detection** (passwords) where licensed.
- Push protection bypass: enable **delegated bypass** so bypass requests need approval
  from the security team; every bypass is audited and reviewed weekly (§16).
- Secret scanning scans the full Git history on enablement; no extra action is needed
  for GitHub-detected patterns. Gitleaks adds a weekly full-history scan for custom rules.

### 7.2 Custom secret patterns

Custom patterns are configured in Settings → Advanced Security → Secret scanning →
Custom patterns (repo, org or enterprise level). Define and **dry-run** these first,
then publish and enable push protection for each:

| Name | Secret format regex | Notes |
|---|---|---|
| Azure Storage connection string | `DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9+/]{86}==` | Also covered by provider patterns; keep for internal formats |
| SQL connection string password | `(?i)(?:Password\|Pwd)=[^;'"\s]{8,}` with "before secret": `(?i)(?:Server\|Data Source)=` | Restrict to config file paths |
| Internal API key | `org_[a-z]{2,8}_[A-Za-z0-9]{32}` | Replace with the real internal format |

Keep the same patterns in `.gitleaks.toml` (§7.4) so local and CI detection match.

### 7.3 `.github/secret_scanning.yml`

Exclude only paths that cannot contain real secrets. Never exclude source folders.

```yaml
paths-ignore:
  - "docs/security/examples/**"     # contains deliberately fake, documented examples only
```

### 7.4 `.gitleaks.toml`

```toml
title = "Repository Gitleaks configuration"

[extend]
# Start from Gitleaks' maintained default rules (AWS, Azure, GCP, GitHub, Slack,
# private keys, JWTs, generic API keys, etc.)
useDefault = true

[[rules]]
id = "azure-storage-connection-string"
description = "Azure Storage account connection string with account key"
regex = '''DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9+/]{86}=='''
keywords = ["accountkey"]
tags = ["azure", "cloud-credential"]

[[rules]]
id = "azure-sas-token"
description = "Azure Shared Access Signature token"
regex = '''(?i)[?&]sig=[A-Za-z0-9%+/=]{40,}'''
keywords = ["sig="]
tags = ["azure", "token"]

[[rules]]
id = "connection-string-password"
description = "Database connection string with inline password"
regex = '''(?i)(?:server|data source|host)=[^;]+;[^"'\n]*?(?:password|pwd)=([^;"'\s]{8,})'''
secretGroup = 1
keywords = ["password=", "pwd="]
tags = ["database", "password"]

[[rules]]
id = "terraform-sensitive-default"
description = "Hard-coded default for a Terraform variable that looks like a secret"
regex = '''(?is)variable\s+"[^"]*(?:password|secret|token|key)[^"]*"\s*\{[^}]*default\s*=\s*"([^"]{8,})"'''
secretGroup = 1
keywords = ["password", "secret", "token", "key"]
tags = ["terraform"]

[allowlist]
description = "Global allowlist – paths that never contain real secrets"
paths = [
  '''(^|/)\.gitleaks\.toml$''',
  '''(^|/)docs/security/examples/''',
  '''(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|go\.sum)$''',
]
# Do NOT allowlist test folders wholesale. Use .gitleaksignore fingerprints + EXC ids.
```

Private keys, cloud provider keys, GitHub/Slack/JWT tokens and generic API keys are
covered by the default rule set (`useDefault = true`); do not duplicate them.

`.gitleaksignore` format (one fingerprint per line, followed by its exception id):

```
<commit>:<file>:<rule-id>:<line>   # EXC-0004 fake key used in parser unit test
```

### 7.5 `.github/workflows/secret-scan.yml`

Gitleaks runs from its official container image (no licence key, no third-party
action). **Pin the image by digest** (`docker buildx imagetools inspect
ghcr.io/gitleaks/gitleaks:<tag>` prints it) and use the `git` sub-command available in
Gitleaks ≥ 8.19. `--redact` guarantees secrets never reach logs or SARIF.

```yaml
name: Secret Scan

on:
  pull_request:
  push:
    branches: [main, "release/**"]
  schedule:
    - cron: "0 2 * * 0"            # weekly full-history scan
  workflow_dispatch:

permissions: {}

env:
  GITLEAKS_IMAGE: ghcr.io/gitleaks/gitleaks:v8.24.3   # replace with <tag>@sha256:<digest>

jobs:
  gitleaks:
    name: sec-gitleaks
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0                 # history needed for range / full scans
          persist-credentials: false

      - name: Determine scan scope
        id: scope
        env:
          EVENT: ${{ github.event_name }}
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
          BEFORE: ${{ github.event.before }}
          AFTER: ${{ github.sha }}
        run: |
          set -euo pipefail
          case "$EVENT" in
            pull_request) echo "log_opts=${BASE_SHA}..${HEAD_SHA}" >> "$GITHUB_OUTPUT" ;;
            push)
              if [ "$BEFORE" = "0000000000000000000000000000000000000000" ]; then
                echo "log_opts=" >> "$GITHUB_OUTPUT"             # new branch: full history
              else
                echo "log_opts=${BEFORE}..${AFTER}" >> "$GITHUB_OUTPUT"
              fi ;;
            *) echo "log_opts=" >> "$GITHUB_OUTPUT" ;;           # schedule/dispatch: full history
          esac

      - name: Run Gitleaks (redacted, output suppressed)
        env:
          LOG_OPTS: ${{ steps.scope.outputs.log_opts }}
        run: |
          set -uo pipefail
          git config --global --add safe.directory /repo
          args=(git /repo --config /repo/.gitleaks.toml --redact --no-banner
                --report-format sarif --report-path /repo/gitleaks.sarif --exit-code 2)
          [ -f .gitleaksignore ] && args+=(--gitleaks-ignore-path /repo/.gitleaksignore)
          [ -n "$LOG_OPTS" ] && args+=(--log-opts "$LOG_OPTS")
          docker run --rm --network none --user "$(id -u):$(id -g)" \
            -v "$PWD:/repo" -w /repo "$GITLEAKS_IMAGE" "${args[@]}" > /dev/null 2>&1
          rc=$?
          echo "GITLEAKS_RC=$rc" >> "$GITHUB_ENV"
          if [ "$rc" -eq 2 ]; then
            echo "::error::Gitleaks detected potential secrets. Redacted details are in Code Scanning. Follow docs/security/secret-incident-response.md - revoke and rotate first."
          elif [ "$rc" -ne 0 ]; then
            echo "::error::Gitleaks failed to run (exit $rc)."
          fi

      - name: Upload redacted SARIF
        if: always() && hashFiles('gitleaks.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks.sarif
          category: gitleaks

      - name: Enforce gate
        if: always()
        run: |
          echo "### Secret scan" >> "$GITHUB_STEP_SUMMARY"
          if [ "${GITLEAKS_RC:-1}" -eq 0 ]; then
            echo "No secrets detected." >> "$GITHUB_STEP_SUMMARY"; exit 0
          fi
          echo "Potential secrets detected or scanner error (values redacted)." >> "$GITHUB_STEP_SUMMARY"
          exit 1
```

Notes:
- Gitleaks stdout/stderr are discarded on purpose; findings are available only as
  redacted SARIF in Code Scanning. If the safe.directory step is insufficient inside
  the container, mount a `.gitconfig` with `safe.directory=/repo`; never drop `--redact`.
- Never upload the checkout or unredacted reports as artifacts.

### 7.6 Pre-commit (developer workstation)

`.pre-commit-config.yaml` (pin each `rev` to the latest verified tag at implementation time):

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.24.3
    hooks:
      - id: gitleaks
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.96.1
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_tflint
        args: ["--args=--config=__GIT_WORKING_DIR__/.tflint.hcl"]
  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint-docker
  - repo: https://github.com/bridgecrewio/checkov
    rev: 3.2.300
    hooks:
      - id: checkov
        args: ["--config-file", ".checkov.yaml"]
```

Document installation of `pre-commit` and `pre-commit install` in `CONTRIBUTING.md`.
Pre-commit is a convenience layer; CI remains the enforcing gate.

### 7.7 Secret incident response (`docs/security/secret-incident-response.md`)

Write this runbook into the repo. **Order matters: contain first, clean up second.**

1. **Identify**
   - Sources: GitHub secret scanning alert, push-protection bypass, Gitleaks failure,
     Defender for Cloud, external report.
   - Record: secret type, alert/fingerprint id, file path, commit SHA, first-exposed
     time, repo visibility, whether forks/clones/CI logs/artifacts may contain it.
   - Check validity status on the alert — but **treat the secret as live until
     revocation is confirmed**.
   - Never paste the secret value into tickets, chat or email; reference the alert URL.
2. **Revoke (immediately, ≤ 1 h for Critical)**
   - Entra ID app client secret: list metadata with `az ad app credential list --id <appId>`
     then `az ad app credential delete --id <appId> --key-id <keyId>`.
   - Storage account key: `az storage account keys renew -g <rg> -n <account> --key primary|secondary`;
     then disable shared-key auth where possible (`--allow-shared-key-access false`).
   - SAS token: rotate the signing key or revoke the stored access policy.
   - ACR: `az acr update -n <acr> --admin-enabled false`; delete leaked scope-map tokens.
   - SQL/PostgreSQL password: reset the login password; prefer Entra-only authentication.
   - GitHub PAT / GitHub App key: revoke in GitHub settings.
   - Third-party API keys: revoke in the provider console.
3. **Rotate**
   - Generate the new credential and store it **only** in Azure Key Vault:
     `az keyvault secret set --vault-name <kv> --name <name> --file <tmpfile>` (from a
     file, never as a CLI argument that lands in shell history), then `shred -u <tmpfile>`.
   - Restart/redeploy consumers so they read the new version; verify health.
   - Prefer eliminating the secret entirely (managed identity, OIDC, Entra auth).
4. **Remove from application configuration**
   - Replace the literal with a Key Vault reference / managed identity / runtime
     injection. Add a Gitleaks custom rule or test for the format to prevent recurrence.
5. **Clean Git history (when necessary)**
   - Required when the repo is or will become public, or policy demands it.
   - Use `git filter-repo --replace-text replacements.txt` (or BFG) on a fresh mirror
     clone; schedule a force-push window (destructive — needs explicit approval from the
     repo owner); collaborators re-clone; ask GitHub Support to purge cached views and
     PR refs if needed. Close the secret scanning alert as **revoked**.
   - History rewriting **does not** make the credential safe — step 2 already did.
6. **Review affected systems**
   - Query Azure Activity Log, Entra sign-in logs (service principal sign-ins), Key
     Vault/Storage diagnostic logs for use of the credential between first exposure and
     revocation (§17.4). Look for new role assignments, federated credentials, resources
     or data exfiltration. Escalate to the incident response team if misuse is found.
7. **Record**
   - Create a private security incident record: timeline, secret type, exposure window,
     revocation/rotation evidence, history-cleanup decision, log review result, root
     cause, preventive action (new custom pattern, pre-commit adoption, managed identity).
   - Close the alert as `revoked`. Never add a real secret to `.gitleaksignore`.

---

## 8. Software Composition Analysis (SCA)

### 8.1 Tool roles

| Tool | Role | When |
|---|---|---|
| GitHub dependency graph + Dependabot alerts | System of record, transitive deps, patched versions | Continuous |
| Dependency review action | Blocks PRs that **introduce** vulnerable or disallowed-licence deps | PR |
| Trivy filesystem scan | Lockfile CVEs (direct + transitive), secrets; SARIF + JSON | PR, push, daily |
| Ecosystem audit (`npm audit`, `pip-audit`, `dotnet list package --vulnerable`, `govulncheck`) | Ecosystem-native advisories; reachability (govulncheck) | PR |
| OWASP Dependency-Check | Deep Java/.NET analysis where needed (NVD API key in Actions secret `NVD_API_KEY`) | Weekly / Java projects |

### 8.2 `trivy.yaml` (shared config)

```yaml
# Shared Trivy configuration used by fs, config and image scans.
severity:
  - CRITICAL
  - HIGH
  - MEDIUM
  - LOW
scan:
  skip-dirs:
    - node_modules
    - .terraform
    - .git
vulnerability:
  ignore-unfixed: false        # reports keep everything; gates decide separately
db:
  no-progress: true
ignorefile: .trivyignore.yaml
```

`.trivyignore.yaml` (every entry needs `expired_at` and a `statement` with the EXC id):

```yaml
vulnerabilities: []
#  - id: CVE-2024-00000
#    paths: ["package-lock.json"]
#    expired_at: 2027-02-07
#    statement: "EXC-0001 not reachable; see .security/exceptions.yaml"
misconfigurations: []
secrets: []
```

### 8.3 `.github/workflows/sca.yml`

```yaml
name: SCA

on:
  pull_request:
  push:
    branches: [main, "release/**"]
  schedule:
    - cron: "15 4 * * *"            # daily: new CVEs against unchanged code
  workflow_dispatch:

permissions: {}

concurrency:
  group: sca-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  dependency-review:
    name: sec-dependency-review
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
      pull-requests: write          # PR summary comment
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }
      - uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: ${{ vars.SEC_DEP_REVIEW_FAIL_SEVERITY || 'high' }}
          fail-on-scopes: runtime, development
          comment-summary-in-pr: on-failure
          show-patched-versions: true
          vulnerability-check: true
          license-check: true
          deny-licenses: AGPL-1.0-only, AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0
          warn-on-openssf-scorecard-level: 3
          retry-on-snapshot-warnings: true

  trivy-fs:
    name: sec-trivy-fs
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }

      - name: Trivy fs - full report (SARIF, all severities)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          scan-ref: .
          trivy-config: trivy.yaml
          scanners: vuln,secret
          format: sarif
          output: trivy-fs.sarif
          exit-code: "0"             # reporting only; the gate is a separate step

      - name: Upload SARIF
        if: always() && hashFiles('trivy-fs.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-fs.sarif
          category: trivy-fs

      - name: Trivy fs - JSON report
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          scan-ref: .
          trivy-config: trivy.yaml
          scanners: vuln
          format: json
          output: trivy-fs.json
          exit-code: "0"
          skip-setup-trivy: true

      - name: Trivy fs - severity gate
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          scan-ref: .
          trivy-config: trivy.yaml
          scanners: vuln,secret
          severity: ${{ vars.SEC_PR_FAIL_SEVERITY || 'CRITICAL,HIGH' }}
          ignore-unfixed: ${{ vars.SEC_PR_IGNORE_UNFIXED || 'true' }}
          format: table
          exit-code: "1"
          skip-setup-trivy: true

      - name: Summary
        if: always() && hashFiles('trivy-fs.json') != ''
        run: bash .github/scripts/security_summary.sh trivy-fs.json "Dependency vulnerabilities (Trivy fs)"

      - name: Upload machine-readable report
        if: always() && hashFiles('trivy-fs.json') != ''
        uses: actions/upload-artifact@v4
        with:
          name: sca-report-${{ github.run_id }}
          path: trivy-fs.json
          retention-days: 30

  ecosystem-audit:
    name: sec-ecosystem-audit
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }
      # Keep ONLY the steps for ecosystems detected in Phase 0; pin tool versions.
      - name: npm audit
        if: hashFiles('package-lock.json') != ''
        run: npm audit --omit=dev --audit-level=high
      - name: pip-audit
        if: hashFiles('requirements.txt') != ''
        run: |
          python -m pip install --disable-pip-version-check "pip-audit==2.*"
          pip-audit -r requirements.txt --strict --vulnerability-service osv
      - name: dotnet vulnerable packages
        if: hashFiles('**/*.csproj') != ''
        run: |
          dotnet restore
          dotnet list package --vulnerable --include-transitive 2>&1 | tee dotnet-vuln.txt
          if grep -qE '\b(High|Critical)\b' dotnet-vuln.txt; then
            echo "::error::High/Critical vulnerable NuGet packages"; exit 1
          fi
      - name: govulncheck
        if: hashFiles('go.mod') != ''
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
          govulncheck ./...
```

### 8.4 `.github/scripts/security_summary.sh`

```bash
#!/usr/bin/env bash
# Usage: security_summary.sh <trivy-json> <title>
# Writes a severity table (counts + top fixable findings) to the job summary.
# Secret findings are counted only - values are never written.
set -euo pipefail
report="$1"; title="$2"
{
  echo "### ${title}"
  echo ""
  echo "| Severity | Total | Fix available |"
  echo "|---|---|---|"
  for sev in CRITICAL HIGH MEDIUM LOW; do
    total=$(jq --arg s "$sev" '[.Results[]?.Vulnerabilities[]? | select(.Severity==$s)] | length' "$report")
    fixable=$(jq --arg s "$sev" '[.Results[]?.Vulnerabilities[]? | select(.Severity==$s and (.FixedVersion // "") != "")] | length' "$report")
    echo "| ${sev} | ${total} | ${fixable} |"
  done
  secrets=$(jq '[.Results[]?.Secrets[]?] | length' "$report")
  misconf=$(jq '[.Results[]?.Misconfigurations[]? | select(.Status=="FAIL")] | length' "$report")
  echo ""
  echo "Secret findings: **${secrets}** (values never shown) · Failed misconfigurations: **${misconf}**"
  echo ""
  echo "<details><summary>Top Critical/High with fixes</summary>"
  echo ""
  echo "| ID | Package | Installed | Fixed in | Target |"
  echo "|---|---|---|---|---|"
  jq -r '[.Results[]? as $r | $r.Vulnerabilities[]?
          | select((.Severity=="CRITICAL" or .Severity=="HIGH") and (.FixedVersion // "") != "")
          | "| \(.VulnerabilityID) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion) | \($r.Target) |"]
         | unique | .[:25][]' "$report"
  echo ""
  echo "</details>"
} >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
```

### 8.5 Interpreting SCA results

- **Outdated packages:** Dependabot version-update PRs, plus the ecosystem "outdated"
  command in the weekly report.
- **Transitive vulnerabilities:** Trivy JSON `PkgPath`/`PkgIdentifier` and the Dependabot
  alert dependency path show the chain; fix by upgrading the direct parent or adding an override.
- **Patched versions:** `FixedVersion` (Trivy) and `first_patched_version` (Dependabot alerts API).
- **No silent suppression:** only via `.trivyignore.yaml` + a register entry (§4.5).

---

## 9. Docker and container security

### 9.1 Dockerfile standards (enforced by Hadolint + Trivy config + review)

| Control | Requirement |
|---|---|
| Trusted base image | Official or Microsoft images (`mcr.microsoft.com/...`), Chainguard, distroless or an internal golden image in ACR. No unknown Docker Hub publishers. |
| Pinned base | `FROM image:tag@sha256:<digest>` — Dependabot updates both tag and digest. Never `latest`. |
| Minimal | Multi-stage builds; runtime stage contains only the app and runtime (distroless/alpine/`-slim`/chiseled). No compilers, package managers, shells or curl in runtime stage where possible. |
| Non-root | `USER 10001:10001` (numeric UID/GID) in the final stage. Files owned by root, read-only to the app user. |
| No secrets | No `ARG`/`ENV` holding secrets; build-time secrets only via `RUN --mount=type=secret`. `.dockerignore` excludes `.git`, `.env*`, `*.pem`, `*.key`, `terraform*`, `node_modules`, tests. |
| Package hygiene | `apt-get install --no-install-recommends` + remove lists; `apk add --no-cache`; pin versions where practical. |
| Ports | Unprivileged port (≥ 1024) so `NET_BIND_SERVICE` is not needed. |
| Read-only root FS | App writes only to explicit volumes / `tmpfs` (`/tmp`). |
| Health | `HEALTHCHECK` (or platform health probes documented). |
| Metadata | OCI labels `org.opencontainers.image.source`, `.revision`, `.created` set by `docker/metadata-action`. |
| No `ADD` from URLs | Use `COPY`; download with checksum verification in a build stage if unavoidable. |

Reference pattern (adapt to the detected stack; do not copy blindly):

```dockerfile
# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:<digest> AS build
WORKDIR /src
COPY *.csproj ./
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0-noble-chiseled@sha256:<digest> AS runtime
WORKDIR /app
COPY --from=build --chown=0:0 --chmod=0555 /app ./
ENV ASPNETCORE_HTTP_PORTS=8080 DOTNET_EnableDiagnostics=0
EXPOSE 8080
USER 10001:10001
ENTRYPOINT ["dotnet", "App.dll"]
```

`.hadolint.yaml`:

```yaml
failure-threshold: warning
trustedRegistries:
  - mcr.microsoft.com
  - docker.io            # remove if only internal/MCR images are allowed
  - "*.azurecr.io"
  - cgr.dev
ignored: []              # any ignore needs an EXC id comment
```

### 9.2 Image tagging standard

| Tag | When | Mutable? | Use |
|---|---|---|---|
| `sha-<12-char git sha>` | every main build | No (ACR tag locking / immutable repo setting) | traceability |
| `<semver>` (e.g. `1.4.2`) | Git tag `v*` | No | releases |
| `pr-<number>` | never pushed | — | PR images are built and scanned locally only |
| `latest` | never | — | forbidden |

Deployments **always** reference `registry/repo@sha256:<digest>`. Enable ACR tag locking
(`az acr repository update --name <acr> --image <repo>:<tag> --write-enabled false`) or
repository-level immutability where available.

### 9.3 `.github/workflows/container-security.yml`

Required repository/environment **variables** (not secrets): `AZURE_CLIENT_ID`,
`AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `ACR_NAME`, `IMAGE_NAME`, optional
`DOCKERFILE` (default `Dockerfile`), `DOCKER_CONTEXT` (default `.`),
`CONTAINER_SMOKE_TEST` (`true` to run the read-only runtime test).

```yaml
name: Container Security

on:
  pull_request:
  push:
    branches: [main]
    tags: ["v*"]
  schedule:
    - cron: "45 4 * * *"            # daily re-scan of the main image for new CVEs
  workflow_dispatch:

permissions: {}

env:
  DOCKERFILE: ${{ vars.DOCKERFILE || 'Dockerfile' }}
  CONTEXT: ${{ vars.DOCKER_CONTEXT || '.' }}
  LOCAL_IMAGE: local/app:${{ github.sha }}

jobs:
  detect:
    name: Detect Dockerfile
    runs-on: ubuntu-latest
    timeout-minutes: 2
    permissions: { contents: read }
    outputs:
      present: ${{ steps.d.outputs.present }}
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }
      - id: d
        run: |
          if [ -f "$DOCKERFILE" ]; then echo "present=true" >> "$GITHUB_OUTPUT"; else echo "present=false" >> "$GITHUB_OUTPUT"; fi

  dockerfile-lint:
    name: sec-dockerfile-lint
    needs: detect
    if: needs.detect.outputs.present == 'true'
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }
      - name: Hadolint
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: ${{ env.DOCKERFILE }}
          config: .hadolint.yaml
          format: sarif
          output-file: hadolint.sarif
          no-fail: true             # gate below, after SARIF upload
      - name: Upload Hadolint SARIF
        if: always() && hashFiles('hadolint.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: hadolint.sarif, category: hadolint }
      - name: Hadolint gate
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: ${{ env.DOCKERFILE }}
          config: .hadolint.yaml
      - name: Trivy config scan of Dockerfile
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: config
          scan-ref: ${{ env.CONTEXT }}
          trivy-config: trivy.yaml
          severity: CRITICAL,HIGH
          exit-code: "1"

  image:
    name: sec-image-scan
    needs: [detect, dockerfile-lint]
    if: needs.detect.outputs.present == 'true'
    runs-on: ubuntu-latest
    timeout-minutes: 45
    environment: ${{ github.event_name == 'push' && 'acr-push' || '' }}
    permissions:
      contents: read
      security-events: write
      id-token: write               # OIDC to Azure (push only) + attestations
      attestations: write
    outputs:
      digest: ${{ steps.push.outputs.digest }}
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }

      - uses: docker/setup-buildx-action@v3

      - name: Build (load locally, no push)
        uses: docker/build-push-action@v6
        with:
          context: ${{ env.CONTEXT }}
          file: ${{ env.DOCKERFILE }}
          load: true
          push: false
          tags: ${{ env.LOCAL_IMAGE }}
          provenance: false          # GitHub artifact attestations used instead
          sbom: false
          cache-from: type=gha
          cache-to: type=gha,mode=max
          labels: |
            org.opencontainers.image.source=${{ github.server_url }}/${{ github.repository }}
            org.opencontainers.image.revision=${{ github.sha }}

      - name: Image configuration checks (non-root, no latest base, healthcheck)
        run: |
          set -euo pipefail
          user=$(docker image inspect "$LOCAL_IMAGE" --format '{{.Config.User}}')
          if [ -z "$user" ] || [ "${user%%:*}" = "root" ] || [ "${user%%:*}" = "0" ]; then
            echo "::error::Image runs as root (USER='${user}'). Set a non-root numeric USER."; exit 1
          fi
          if grep -Eiq '^FROM[[:space:]]+[^[:space:]]+:latest([[:space:]]|$)' "$DOCKERFILE"; then
            echo "::error::Base image uses ':latest'"; exit 1
          fi
          if ! grep -Eiq '^FROM[[:space:]]+[^[:space:]]+@sha256:' "$DOCKERFILE"; then
            echo "::warning::Base image(s) not pinned by digest"
          fi
          ports=$(docker image inspect "$LOCAL_IMAGE" --format '{{range $p, $_ := .Config.ExposedPorts}}{{$p}} {{end}}')
          for p in $ports; do n=${p%%/*}; if [ "$n" -lt 1024 ]; then echo "::error::Privileged port $p exposed"; exit 1; fi; done
          echo "User=${user}; ExposedPorts=${ports:-none}" >> "$GITHUB_STEP_SUMMARY"

      - name: Runtime hardening smoke test (read-only FS, no capabilities)
        if: vars.CONTAINER_SMOKE_TEST == 'true'
        run: |
          set -euo pipefail
          cid=$(docker run -d --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
                 --cap-drop ALL --security-opt no-new-privileges:true \
                 --pids-limit 256 --memory 512m "$LOCAL_IMAGE")
          sleep 15
          state=$(docker inspect -f '{{.State.Running}}' "$cid")
          docker rm -f "$cid" >/dev/null
          if [ "$state" != "true" ]; then
            echo "::error::Container does not stay up with --read-only and --cap-drop ALL"; exit 1
          fi

      - name: Trivy image - SARIF (all severities)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: image
          image-ref: ${{ env.LOCAL_IMAGE }}
          trivy-config: trivy.yaml
          scanners: vuln,secret,misconfig
          format: sarif
          output: trivy-image.sarif
          exit-code: "0"
      - name: Upload SARIF
        if: always() && hashFiles('trivy-image.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: trivy-image.sarif, category: trivy-image }

      - name: Trivy image - JSON report
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: image
          image-ref: ${{ env.LOCAL_IMAGE }}
          trivy-config: trivy.yaml
          scanners: vuln,secret
          format: json
          output: trivy-image.json
          exit-code: "0"
          skip-setup-trivy: true

      - name: Trivy image - severity gate
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: image
          image-ref: ${{ env.LOCAL_IMAGE }}
          trivy-config: trivy.yaml
          scanners: vuln,secret
          severity: ${{ vars.SEC_PR_FAIL_SEVERITY || 'CRITICAL,HIGH' }}
          ignore-unfixed: ${{ vars.SEC_PR_IGNORE_UNFIXED || 'true' }}
          exit-code: "1"
          skip-setup-trivy: true

      - name: Summary
        if: always() && hashFiles('trivy-image.json') != ''
        run: bash .github/scripts/security_summary.sh trivy-image.json "Container image vulnerabilities"

      - name: Generate SBOM (SPDX)
        uses: anchore/sbom-action@v0
        with:
          image: ${{ env.LOCAL_IMAGE }}
          format: spdx-json
          output-file: sbom.spdx.json
          upload-artifact: false

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: container-reports-${{ github.run_id }}
          path: |
            trivy-image.json
            sbom.spdx.json
          if-no-files-found: ignore
          retention-days: 30

      # ── Publish (main / tags only): push the SAME scanned image by digest ──
      - name: Azure login (OIDC)
        if: github.event_name == 'push'
        uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}

      - name: Push to ACR
        id: push
        if: github.event_name == 'push'
        env:
          ACR_NAME: ${{ vars.ACR_NAME }}
          IMAGE_NAME: ${{ vars.IMAGE_NAME }}
          REF_TYPE: ${{ github.ref_type }}
          REF_NAME: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          az acr login --name "$ACR_NAME" >/dev/null
          registry="${ACR_NAME}.azurecr.io"
          tag="sha-${GITHUB_SHA::12}"
          [ "$REF_TYPE" = "tag" ] && tag="${REF_NAME#v}"
          docker tag "$LOCAL_IMAGE" "${registry}/${IMAGE_NAME}:${tag}"
          docker push "${registry}/${IMAGE_NAME}:${tag}" >/dev/null
          digest=$(docker image inspect "${registry}/${IMAGE_NAME}:${tag}" --format '{{range .RepoDigests}}{{println .}}{{end}}' \
                   | grep "^${registry}/${IMAGE_NAME}@" | head -1 | cut -d@ -f2)
          echo "digest=${digest}" >> "$GITHUB_OUTPUT"
          echo "registry=${registry}" >> "$GITHUB_OUTPUT"
          az acr repository update --name "$ACR_NAME" --image "${IMAGE_NAME}:${tag}" --write-enabled false --delete-enabled false >/dev/null
          echo "Pushed ${registry}/${IMAGE_NAME}@${digest} (tag ${tag}, locked)" >> "$GITHUB_STEP_SUMMARY"

      - name: Attest build provenance
        if: github.event_name == 'push'
        uses: actions/attest-build-provenance@v2
        with:
          subject-name: ${{ steps.push.outputs.registry }}/${{ vars.IMAGE_NAME }}
          subject-digest: ${{ steps.push.outputs.digest }}
          push-to-registry: true

      - name: Attest SBOM
        if: github.event_name == 'push'
        uses: actions/attest-sbom@v2
        with:
          subject-name: ${{ steps.push.outputs.registry }}/${{ vars.IMAGE_NAME }}
          subject-digest: ${{ steps.push.outputs.digest }}
          sbom-path: sbom.spdx.json
          push-to-registry: true

      - name: Post-publish scan (by digest, from registry)
        if: github.event_name == 'push'
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: image
          image-ref: ${{ steps.push.outputs.registry }}/${{ vars.IMAGE_NAME }}@${{ steps.push.outputs.digest }}
          trivy-config: trivy.yaml
          scanners: vuln
          severity: CRITICAL
          exit-code: "1"
          skip-setup-trivy: true

      - name: Record digest for deployment
        if: github.event_name == 'push'
        env:
          DIGEST: ${{ steps.push.outputs.digest }}
        run: echo "$DIGEST" > image-digest.txt
      - uses: actions/upload-artifact@v4
        if: github.event_name == 'push'
        with:
          name: image-digest
          path: image-digest.txt
          retention-days: 90
```

Notes:
- The scheduled run rebuilds from `main` and re-scans; for **deployed** digests use the
  re-scan job in `security-report.yml` (§16.3) and Microsoft Defender for Containers
  (continuous registry and runtime vulnerability assessment).
- If ACR has public network access disabled, GitHub-hosted runners cannot push; use
  self-hosted runners in the VNet or Azure private networking for GitHub-hosted runners.

### 9.4 Azure Container Registry security baseline

- Premium SKU where private endpoints, retention and geo-replication are needed.
- `admin_enabled = false`; anonymous pull disabled; public network access disabled or
  restricted; push only via the `acr-push` OIDC identity with `AcrPush`; runtime pulls
  via managed identity with `AcrPull`.
- **Separate registries (or repositories) per stage**: images are promoted to the prod
  registry with `az acr import --source <dev-acr>.azurecr.io/<repo>@<digest>` only after
  the deployment gates in §15 pass.
- Enable Microsoft Defender for Containers; route its findings to Log Analytics (§17).
- Retention policy for untagged manifests; content trust is superseded by attestations (§13).

---

## 10. Infrastructure-as-Code security (Terraform)

### 10.1 Required Azure security controls (policy baseline)

Checkov/Trivy/TFLint enforce most of these; reviewers enforce the rest. Every exception
needs an inline skip with an EXC id.

| Area | Control |
|---|---|
| Storage accounts | `public_network_access_enabled = false` (or network rules default `Deny`); `allow_nested_items_to_be_public = false`; `min_tls_version = "TLS1_2"`; HTTPS only; `shared_access_key_enabled = false` where workloads support Entra auth; `infrastructure_encryption_enabled = true`; blob soft delete + versioning; CMK where required |
| Network | No NSG rule allowing `0.0.0.0/0`/`*`/`Internet` inbound to 22, 3389, database or management ports; private endpoints for PaaS; no public IPs on VMs unless justified; DDoS/WAF for internet ingress |
| Key Vault | `purge_protection_enabled = true`; `soft_delete_retention_days >= 7` (90 preferred); RBAC authorization; `public_network_access_enabled = false` or network ACL `default_action = "Deny"`; secrets/keys have expiry; diagnostic logs on |
| Identity | Managed identities for workloads; no secrets/passwords in Terraform variables defaults; least-privilege role assignments at the narrowest scope; no `Owner`/`User Access Administrator` to workloads |
| Databases | Entra-only auth where supported; public network access disabled; TLS 1.2; auditing + threat detection on; backups/geo-redundancy per RPO |
| Compute/containers | AKS: Entra RBAC, local accounts disabled, private cluster or authorized IP ranges, Azure Policy add-on, Defender; Container Apps/App Service: HTTPS only, TLS 1.2, managed identity, FTP disabled, remote debugging off |
| Logging | Diagnostic settings to Log Analytics for every resource that supports them; Activity Log exported |
| Encryption | Encryption at rest everywhere (default) + CMK where data classification requires; TLS in transit |
| Governance | Mandatory tags (`owner`, `environment`, `data-classification`, `cost-center`); resource locks on prod state storage and Key Vaults |
| State | Remote `azurerm` backend, Entra auth (`use_azuread_auth = true`), private storage account with versioning + soft delete, state never committed (`*.tfstate*` in `.gitignore`) |

Reference snippets (azurerm provider 4.x attribute names; check the provider version
from `.terraform.lock.hcl` and adjust — some attributes were renamed between 3.x and 4.x):

```hcl
resource "azurerm_key_vault" "this" {
  name                          = var.key_vault_name
  location                      = var.location
  resource_group_name           = var.resource_group_name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true      # 3.x: enable_rbac_authorization
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
  tags = var.tags
}

resource "azurerm_storage_account" "this" {
  name                              = var.storage_account_name
  resource_group_name               = var.resource_group_name
  location                          = var.location
  account_tier                      = "Standard"
  account_replication_type          = "ZRS"
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true  # 3.x: enable_https_traffic_only
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false
  public_network_access_enabled     = false
  infrastructure_encryption_enabled = true
  default_to_oauth_authentication   = true

  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 30 }
    container_delete_retention_policy { days = 30 }
  }
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
  tags = var.tags
}
```

Backend (no secrets in code; identity supplied by OIDC env vars):

```hcl
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
  }
  backend "azurerm" {
    use_azuread_auth = true
    use_oidc         = true
    # resource_group_name / storage_account_name / container_name / key passed via -backend-config
  }
}
```

Variables holding sensitive values must be declared `sensitive = true` and must not have
defaults; values come from Key Vault data sources or pipeline-masked inputs. Outputs
containing secrets must be `sensitive = true`.

### 10.2 `.tflint.hcl`

```hcl
config {
  call_module_type = "local"
  force            = false
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "azurerm" {
  enabled = true
  version = "0.28.0"     # pin; update deliberately
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}

rule "terraform_required_providers" { enabled = true }
rule "terraform_required_version"   { enabled = true }
rule "terraform_unused_declarations" { enabled = true }
```

### 10.3 `.checkov.yaml`

```yaml
framework:
  - terraform
  - terraform_plan
  - dockerfile
  - github_actions
  - secrets
directory:
  - .
skip-path:
  - .terraform
  - node_modules
download-external-modules: false   # set true only for trusted, pinned registry modules
compact: true
quiet: true                        # show failures only
# Global skips are discouraged; prefer inline:  #checkov:skip=CKV_AZURE_XX:EXC-0002 reason
skip-check: []
```

Checkov severity filtering (`--hard-fail-on`/`--soft-fail-on` by severity) only works
with a Prisma Cloud API key. Without it, **every failed check fails the job**, and the
only way to accept a finding is an inline skip with a registered EXC id.

### 10.4 `.github/workflows/iac-security.yml`

Repository variable `TF_ROOTS` = space-separated Terraform root directories
(e.g. `infra/envs/dev infra/envs/prod`). Per-environment variables (on GitHub
environments `infra-dev`, `infra-staging`, `infra-prod`, `infra-plan`):
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `TFSTATE_RG`,
`TFSTATE_ACCOUNT`, `TFSTATE_CONTAINER`, `TF_ROOT`.

```yaml
name: IaC Security

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "30 3 * * 2"            # weekly: new policies against unchanged IaC
  workflow_dispatch:
    inputs:
      environment:
        description: "Environment to apply (infra-staging / infra-prod)"
        type: choice
        options: [infra-staging, infra-prod]

permissions: {}

env:
  TF_IN_AUTOMATION: "true"
  TF_INPUT: "false"

jobs:
  detect:
    name: Detect Terraform
    runs-on: ubuntu-latest
    timeout-minutes: 2
    permissions: { contents: read }
    outputs:
      present: ${{ steps.d.outputs.present }}
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }
      - id: d
        run: |
          if git ls-files '*.tf' | grep -q .; then echo "present=true" >> "$GITHUB_OUTPUT"; else echo "present=false" >> "$GITHUB_OUTPUT"; fi

  iac-static:
    name: sec-iac-scan
    needs: detect
    if: needs.detect.outputs.present == 'true'
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: "~1.9"
          terraform_wrapper: false

      - name: terraform fmt
        run: terraform fmt -check -recursive -diff

      - name: terraform validate (no backend, no credentials)
        env:
          TF_ROOTS: ${{ vars.TF_ROOTS || 'infra' }}
        run: |
          set -euo pipefail
          for d in $TF_ROOTS; do
            echo "::group::validate $d"
            terraform -chdir="$d" init -backend=false -input=false -lockfile=readonly
            terraform -chdir="$d" validate -no-color
            echo "::endgroup::"
          done

      - uses: terraform-linters/setup-tflint@v4
        with: { tflint_version: v0.53.0 }
      - name: TFLint
        env:
          GITHUB_TOKEN: ${{ github.token }}   # avoids plugin download rate limits
        run: |
          tflint --init --config "$PWD/.tflint.hcl"
          tflint --recursive --config "$PWD/.tflint.hcl" --format compact

      - name: Checkov (SARIF + gate)
        uses: bridgecrewio/checkov-action@v12
        with:
          config_file: .checkov.yaml
          output_format: cli,sarif
          output_file_path: console,checkov.sarif
      - name: Upload Checkov SARIF
        if: always() && hashFiles('checkov.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: checkov.sarif, category: checkov }

      - name: Trivy config (SARIF)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: config
          scan-ref: .
          trivy-config: trivy.yaml
          format: sarif
          output: trivy-iac.sarif
          exit-code: "0"
      - name: Upload Trivy IaC SARIF
        if: always() && hashFiles('trivy-iac.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: trivy-iac.sarif, category: trivy-iac }
      - name: Trivy config gate
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: config
          scan-ref: .
          trivy-config: trivy.yaml
          severity: CRITICAL,HIGH
          exit-code: "1"
          skip-setup-trivy: true

  plan:
    name: iac-plan
    needs: iac-static
    # Same-repo PRs only: forks and Dependabot get no OIDC token / secrets.
    if: >-
      github.event_name == 'pull_request' &&
      github.event.pull_request.head.repo.full_name == github.repository &&
      github.actor != 'dependabot[bot]'
    runs-on: ubuntu-latest
    timeout-minutes: 30
    environment: infra-plan          # federated subject: repo:<org>/<repo>:environment:infra-plan
    permissions:
      contents: read
      id-token: write
      pull-requests: write
    env:
      ARM_USE_OIDC: "true"
      ARM_USE_AZUREAD: "true"
      ARM_CLIENT_ID: ${{ vars.AZURE_CLIENT_ID }}
      ARM_TENANT_ID: ${{ vars.AZURE_TENANT_ID }}
      ARM_SUBSCRIPTION_ID: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      TF_ROOT: ${{ vars.TF_ROOT }}
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }
      - uses: hashicorp/setup-terraform@v3
        with: { terraform_version: "~1.9", terraform_wrapper: false }
      - name: terraform init
        run: |
          terraform -chdir="$TF_ROOT" init -input=false -lockfile=readonly \
            -backend-config="resource_group_name=${{ vars.TFSTATE_RG }}" \
            -backend-config="storage_account_name=${{ vars.TFSTATE_ACCOUNT }}" \
            -backend-config="container_name=${{ vars.TFSTATE_CONTAINER }}" \
            -backend-config="key=${{ vars.TF_ROOT }}.tfstate"
      - name: terraform plan
        run: |
          set -euo pipefail
          terraform -chdir="$TF_ROOT" plan -input=false -lock-timeout=5m -out=tfplan -no-color > /dev/null
          terraform -chdir="$TF_ROOT" show -json tfplan > plan.json
      - name: Checkov on plan (evaluates computed values)
        uses: bridgecrewio/checkov-action@v12
        with:
          file: plan.json
          framework: terraform_plan
          output_format: cli
      - name: Plan summary (counts only - no attribute values)
        run: |
          {
            echo "### Terraform plan: \`${TF_ROOT}\`"
            jq -r '[.resource_changes[] | .change.actions | join(",")] | group_by(.) | map("- \(.[0]): \(length)") | .[]' plan.json
            echo ""
            echo "Destroy/replace targets:"
            jq -r '.resource_changes[] | select(.change.actions | index("delete")) | "- `\(.address)`"' plan.json
          } >> "$GITHUB_STEP_SUMMARY"
      - name: Remove plan files
        if: always()
        run: rm -f "$TF_ROOT/tfplan" plan.json     # plans can contain sensitive values; never upload them

  apply:
    name: iac-apply
    needs: iac-static
    if: (github.event_name == 'push' && github.ref == 'refs/heads/main') || github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    timeout-minutes: 60
    environment: ${{ github.event_name == 'workflow_dispatch' && inputs.environment || 'infra-dev' }}
    concurrency:
      group: terraform-${{ github.event_name == 'workflow_dispatch' && inputs.environment || 'infra-dev' }}
      cancel-in-progress: false
    permissions:
      contents: read
      id-token: write
    env:
      ARM_USE_OIDC: "true"
      ARM_USE_AZUREAD: "true"
      ARM_CLIENT_ID: ${{ vars.AZURE_CLIENT_ID }}
      ARM_TENANT_ID: ${{ vars.AZURE_TENANT_ID }}
      ARM_SUBSCRIPTION_ID: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      TF_ROOT: ${{ vars.TF_ROOT }}
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }
      - uses: hashicorp/setup-terraform@v3
        with: { terraform_version: "~1.9", terraform_wrapper: false }
      - name: terraform init
        run: |
          terraform -chdir="$TF_ROOT" init -input=false -lockfile=readonly \
            -backend-config="resource_group_name=${{ vars.TFSTATE_RG }}" \
            -backend-config="storage_account_name=${{ vars.TFSTATE_ACCOUNT }}" \
            -backend-config="container_name=${{ vars.TFSTATE_CONTAINER }}" \
            -backend-config="key=${{ vars.TF_ROOT }}.tfstate"
      - name: terraform plan (fresh) + policy check
        run: |
          set -euo pipefail
          terraform -chdir="$TF_ROOT" plan -input=false -lock-timeout=5m -out=tfplan -no-color > /dev/null
          terraform -chdir="$TF_ROOT" show -json tfplan > plan.json
      - uses: bridgecrewio/checkov-action@v12
        with: { file: plan.json, framework: terraform_plan, output_format: cli }
      - name: terraform apply
        run: terraform -chdir="$TF_ROOT" apply -input=false -lock-timeout=5m -no-color tfplan > /dev/null
      - name: Cleanup
        if: always()
        run: rm -f "$TF_ROOT/tfplan" plan.json
```

Notes:
- `-no-color > /dev/null` keeps resource attribute values (which may be sensitive) out
  of logs; the summary step reports counts and addresses only. Remove the redirect
  temporarily only on a private debugging branch, never on `main`.
- Environment `infra-prod` must have required reviewers and a deployment-branch policy
  restricted to `main`.
- Drift detection: schedule `terraform plan -detailed-exitcode` weekly per environment
  (exit code 2 = drift → open an issue).

### 10.5 Azure Policy as the runtime backstop

Assign built-in initiatives (e.g., **Microsoft cloud security benchmark**) at
management-group or subscription scope with `Deny`/`Audit` effects for storage public
access, Key Vault purge protection, allowed locations and required tags. Pipeline
scanning prevents most issues; Azure Policy catches anything deployed outside the pipeline.

### 10.6 Why plan is skipped for forks and Dependabot

Fork and Dependabot PR runs do not receive OIDC tokens bound to protected environments
or Actions secrets. Static IaC scanning still runs and remains a required check; the
plan runs after a maintainer re-runs the PR from a same-repo branch if needed.

---

## 11. Azure authentication with OIDC

### 11.1 Identity design (one identity per purpose and environment)

| Identity (user-assigned MI or app registration) | Federated subject | Azure roles (narrowest scope) |
|---|---|---|
| `id-gh-<repo>-plan` | `repo:<org>/<repo>:environment:infra-plan` | `Reader` on target RGs; `Storage Blob Data Contributor` on the tfstate **container** (state lock) |
| `id-gh-<repo>-infra-<env>` | `repo:<org>/<repo>:environment:infra-<env>` | `Contributor` on the env RG(s) (or a custom role); `Storage Blob Data Contributor` on tfstate container; `Role Based Access Control Administrator` with an ABAC condition limiting assignable roles **only** if Terraform manages role assignments |
| `id-gh-<repo>-acr-push` | `repo:<org>/<repo>:environment:acr-push` | `AcrPush` on the non-prod ACR (`Container Registry Repository Writer` on ABAC-enabled registries) |
| `id-gh-<repo>-deploy-<env>` | `repo:<org>/<repo>:environment:<env>` | Deploy role on the app resource only (e.g. `Contributor` scoped to the Container App); `AcrPull`/import rights for promotion; `Key Vault Secrets User` on the specific vault if the pipeline must read a secret |

Rules: never `Owner`, never subscription-wide `Contributor` for app deploys, never one
identity shared across environments, never the `pull_request` subject for an identity
that can write to Azure.

### 11.2 Create the federation (Azure CLI, run by an administrator)

```bash
RG=rg-identity-prod ; LOC=westeurope ; ORG=<org> ; REPO=<repo> ; ENV=prod
az identity create -g "$RG" -n "id-gh-${REPO}-deploy-${ENV}" -l "$LOC"
CLIENT_ID=$(az identity show -g "$RG" -n "id-gh-${REPO}-deploy-${ENV}" --query clientId -o tsv)
PRINCIPAL_ID=$(az identity show -g "$RG" -n "id-gh-${REPO}-deploy-${ENV}" --query principalId -o tsv)

az identity federated-credential create \
  --identity-name "id-gh-${REPO}-deploy-${ENV}" -g "$RG" \
  --name "github-${ENV}" \
  --issuer "https://token.actions.githubusercontent.com" \
  --subject "repo:${ORG}/${REPO}:environment:${ENV}" \
  --audiences "api://AzureADTokenExchange"

az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "<least-privileged role>" --scope "<resource id>"

# Store identifiers (not secrets) as GitHub ENVIRONMENT variables:
gh variable set AZURE_CLIENT_ID       --env "$ENV" --body "$CLIENT_ID"
gh variable set AZURE_TENANT_ID       --env "$ENV" --body "$(az account show --query tenantId -o tsv)"
gh variable set AZURE_SUBSCRIPTION_ID --env "$ENV" --body "$(az account show --query id -o tsv)"
```

Hardening:
- Consider GitHub's customizable OIDC subject claims (org/repo IDs) so subjects survive
  repo renames and cannot be reused by a re-created repo with the same name.
- Use **environment** subjects (not branch subjects) so GitHub environment protection
  rules (reviewers, branch policies, wait timers) gate every token issuance.
- Remove any existing client secrets/certificates from app registrations used by CI.
- Alert on changes to federated credentials and role assignments (§17.4).

### 11.3 Workflow usage

```yaml
permissions:
  id-token: write      # request the OIDC token
  contents: read
steps:
  - uses: azure/login@v2
    with:
      client-id: ${{ vars.AZURE_CLIENT_ID }}
      tenant-id: ${{ vars.AZURE_TENANT_ID }}
      subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
```

Terraform uses `ARM_USE_OIDC=true` + `ARM_CLIENT_ID/TENANT_ID/SUBSCRIPTION_ID` env vars
(no `azure/login` needed). Never pass `creds:` to `azure/login`.

---

## 12. Azure Key Vault integration

### 12.1 Principles

1. **Applications read secrets at runtime with managed identity** — the pipeline should
   normally not touch application secrets at all.
   - App Service / Functions: Key Vault references `@Microsoft.KeyVault(SecretUri=https://<kv>.vault.azure.net/secrets/<name>)`.
   - Container Apps: secrets with `keyVaultUrl` + identity; AKS: Secrets Store CSI driver + workload identity.
2. Pipeline reads only what deployment needs, with a dedicated identity holding
   `Key Vault Secrets User` on that vault (or on individual secrets).
3. Key Vault RBAC (not access policies), purge protection, private endpoint/firewall,
   diagnostic logs → Log Analytics (§17), expiry dates and rotation policies on all
   secrets/keys, Event Grid `SecretNearExpiry` notifications.
4. Terraform never stores secret values in state when avoidable: generate secrets
   outside Terraform or use `ephemeral` resources/write-only arguments where the
   Terraform and provider versions support them; otherwise treat state as secret
   (private storage, Entra auth, RBAC, versioning).

### 12.2 Reading a secret in a workflow (only when unavoidable)

```yaml
- name: Read deployment secret from Key Vault (masked)
  env:
    KV_NAME: ${{ vars.KEY_VAULT_NAME }}
  run: |
    set -euo pipefail
    value=$(az keyvault secret show --vault-name "$KV_NAME" --name "db-migration-password" --query value -o tsv)
    echo "::add-mask::${value}"
    {
      echo "DB_MIGRATION_PASSWORD<<__EOF__"
      echo "${value}"
      echo "__EOF__"
    } >> "$GITHUB_ENV"
    unset value
```

Rules: mask **before** any other use; never `set -x` in steps that handle secrets; never
write secrets to files that get uploaded; multi-line secrets must be masked line by line.
If Key Vault has public network access disabled, run on self-hosted runners in the VNet
(or GitHub-hosted runners with Azure private networking).

---

## 13. Software supply chain security

### 13.1 Pin everything

1. **Actions → full commit SHA.** Resolve each tag once and rewrite the workflow:

   ```bash
   # list third-party actions in use
   grep -rhoE 'uses:[[:space:]]+[^./][^@[:space:]]+@[^[:space:]#]+' .github/workflows | sort -u
   # resolve a tag to its commit SHA (repo = first two path segments)
   gh api "repos/actions/checkout/commits/v4" --jq .sha
   ```

   Write as `uses: actions/checkout@<40-char-sha> # v4.x.y`. Tools such as `pinact` or
   `ratchet` automate this; review their output like any other change.
2. **Container images → digest** (`image:tag@sha256:...`), including tool images used
   in workflows (Gitleaks, actionlint).
3. **Tools downloaded in workflows → exact version + checksum** (`sha256sum -c`), never
   `latest` and never `curl | bash`.
4. **Lockfiles committed** for every ecosystem; CI installs with frozen lockfiles
   (`npm ci`, `pip install --require-hashes`, `dotnet restore --locked-mode`,
   `terraform init -lockfile=readonly`).
5. **Organisation policy:** Settings → Actions → allow only GitHub-owned, verified
   creators and an explicit allow-list; enable "require actions to be pinned to a full
   commit SHA" where available; default `GITHUB_TOKEN` permission = read-only.

### 13.2 SBOM

- Generated for every image (§9.3) in **SPDX JSON** and attested to the registry.
  Generate **CycloneDX** as well if consumers need it (`format: cyclonedx-json`).
- For non-container deliverables, generate a source SBOM:
  `anchore/sbom-action` with `path: .` and attach it to the GitHub release.
- GitHub can also export the dependency-graph SBOM:
  `gh api "repos/{owner}/{repo}/dependency-graph/sbom" > sbom-github.spdx.json`.
- SBOMs are retained at least as long as the artifact is deployed (registry attestation
  + release asset).

### 13.3 Provenance

- `actions/attest-build-provenance` creates a signed SLSA provenance statement bound to
  the image digest, the workflow, commit and runner. Moving the build into a reusable
  workflow (`workflow_call`) owned by the platform team raises the guarantee level
  because the build definition cannot be altered by the calling repo.
- Deployment verifies provenance **and** SBOM attestations before release (§15).

### 13.4 Fallback: Cosign keyless signing (if artifact attestations are unavailable)

```bash
cosign sign --yes "${REGISTRY}/${IMAGE}@${DIGEST}"            # uses the workflow OIDC token
cosign attest --yes --type spdxjson --predicate sbom.spdx.json "${REGISTRY}/${IMAGE}@${DIGEST}"
cosign verify "${REGISTRY}/${IMAGE}@${DIGEST}" \
  --certificate-identity-regexp "^https://github.com/<org>/<repo>/.github/workflows/container-security.yml@refs/heads/main$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

### 13.5 OpenSSF Scorecard – `.github/workflows/scorecard.yml`

```yaml
name: Scorecard

on:
  branch_protection_rule:
  schedule:
    - cron: "20 6 * * 1"
  push:
    branches: [main]

permissions: {}

jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      actions: read
      security-events: write
      id-token: write                # publish_results for public repos
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }
      - uses: ossf/scorecard-action@v2.4.0
        with:
          results_file: scorecard.sarif
          results_format: sarif
          publish_results: ${{ github.event.repository.private == false }}
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: scorecard.sarif, category: scorecard }
```

### 13.6 Workflow hardening – `.github/workflows/security-policy.yml`

```yaml
name: Security Policy

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 7 * * *"              # daily: catches exceptions that expired overnight

permissions: {}

jobs:
  policy:
    name: sec-policy-checks
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }

      - name: actionlint
        run: |
          docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.7 -color   # pin by digest

      - name: zizmor (GitHub Actions security linter)
        run: |
          python -m pip install --disable-pip-version-check "zizmor==1.*"
          zizmor --format sarif .github/workflows > zizmor.sarif || true
          zizmor --min-severity medium .github/workflows
      - name: Upload zizmor SARIF
        if: always() && hashFiles('zizmor.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: zizmor.sarif, category: zizmor }

      - name: Enforce SHA-pinned actions
        run: |
          set -euo pipefail
          bad=$(grep -rnE '^\s*-?\s*uses:\s+[^./][^@[:space:]]+@' .github/workflows \
                | grep -vE '@[0-9a-f]{40}([[:space:]]|$)' \
                | grep -vE 'uses:\s+docker://[^@]+@sha256:' || true)
          if [ -n "$bad" ]; then
            echo "::error::Actions must be pinned to a full commit SHA:"; echo "$bad"; exit 1
          fi

      - name: Forbid dangerous patterns
        run: |
          set -euo pipefail
          fail=0
          if grep -rnE '^\s*pull_request_target\s*:' .github/workflows; then
            echo "::error::pull_request_target is forbidden without a security review exception"; fail=1; fi
          if grep -rnE 'creds:\s*\$\{\{\s*secrets\.AZURE_CREDENTIALS' .github/workflows; then
            echo "::error::Use OIDC (client-id/tenant-id/subscription-id), not AZURE_CREDENTIALS"; fail=1; fi
          if grep -rnE '(curl|wget)[^|]*\|\s*(ba)?sh' .github/workflows; then
            echo "::error::curl|bash is forbidden"; fail=1; fi
          if git ls-files | grep -E '\.tfstate(\.backup)?$|(^|/)\.env$|\.pem$|\.pfx$'; then
            echo "::error::State files, .env or key material committed"; fail=1; fi
          exit $fail

      - name: Validate exception register and suppressions
        run: |
          python -m pip install --disable-pip-version-check "pyyaml==6.*"
          python .github/scripts/validate_exceptions.py
```

Note: when the policy job's SHA-pin check is introduced, the policy workflow itself
must already be pinned or it will fail its own check — pin first (§13.1), then enable.

---

## 14. Security policy enforcement

### 14.1 Branch ruleset for `main` and `release/**`

Create with `gh api -X POST "repos/{owner}/{repo}/rulesets" --input ruleset-main.json`
(store the JSON in `docs/security/ruleset-main.json` for drift review):

```json
{
  "name": "protect-main-and-release",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": { "include": ["~DEFAULT_BRANCH", "refs/heads/release/**"], "exclude": [] }
  },
  "bypass_actors": [],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "sec-gitleaks" },
          { "context": "sec-dependency-review" },
          { "context": "sec-trivy-fs" },
          { "context": "sec-ecosystem-audit" },
          { "context": "sec-iac-scan" },
          { "context": "sec-dockerfile-lint" },
          { "context": "sec-image-scan" },
          { "context": "sec-policy-checks" }
        ]
      }
    },
    {
      "type": "code_scanning",
      "parameters": {
        "code_scanning_tools": [
          { "tool": "CodeQL", "security_alerts_threshold": "high_or_higher", "alerts_threshold": "errors" }
        ]
      }
    }
  ]
}
```

- Add the project's build/test job name to `required_status_checks`.
- Jobs skipped by `if:` (e.g., no Dockerfile) report "skipped", which satisfies the
  requirement; do **not** put path filters on the workflow `on:` of required checks
  (a workflow that never starts leaves the check pending forever).
- Remove checks for stacks that do not exist in the repo (from Phase 0).
- Add a tag ruleset protecting `v*` tags from deletion/update, creation restricted to
  release managers.
- Bypass actors: none by default. If an emergency bypass role is required, it must be
  a small team and every bypass is reviewed (§17.3).

### 14.2 `.github/CODEOWNERS`

```
# Security-sensitive paths require security team review
/.github/                       @<org>/platform-security
/.security/                     @<org>/platform-security
/.gitleaks.toml                 @<org>/platform-security
/.trivyignore.yaml              @<org>/platform-security
/.checkov.yaml                  @<org>/platform-security
/.tflint.hcl                    @<org>/platform-security
/infra/                         @<org>/platform-security @<org>/cloud-infra
**/Dockerfile*                  @<org>/platform-security
/SECURITY.md                    @<org>/platform-security
```

### 14.3 GitHub environments

| Environment | Protection | Deployment branches | Used by |
|---|---|---|---|
| `infra-plan` | none (read-only identity) | all same-repo branches | `iac-plan` |
| `acr-push` | none | `main`, tags `v*` | image publish |
| `infra-dev`, `dev` | none / optional wait timer | `main` | apply/deploy |
| `infra-staging`, `staging` | 1 required reviewer | `main` | apply/deploy |
| `infra-prod`, `prod` | 2 required reviewers (not the author; "prevent self-review"), wait timer 10 min | `main` only | apply/deploy |

Configure via Settings → Environments or `gh api -X PUT repos/{owner}/{repo}/environments/<name>`.

### 14.4 Repository settings baseline

- Default workflow permissions: **read repository contents**; "Allow GitHub Actions to
  create and approve pull requests" **off** (turn on only if Dependabot auto-merge
  opt-in is used, and document it).
- Fork PR workflows from outside collaborators require approval.
- Private vulnerability reporting enabled; `SECURITY.md` present.
- Secret scanning, push protection, Dependabot alerts/security updates, code scanning enabled.

### 14.5 Policy-as-code for Terraform plans (optional, recommended for prod)

Use Conftest/OPA on `plan.json` for organisation rules Checkov does not cover:

```rego
# policy/terraform/storage.rego
package main

import rego.v1

deny contains msg if {
  rc := input.resource_changes[_]
  rc.type == "azurerm_storage_account"
  rc.change.after.public_network_access_enabled == true
  msg := sprintf("%s: public network access must be disabled", [rc.address])
}

deny contains msg if {
  rc := input.resource_changes[_]
  rc.change.actions[_] == "delete"
  rc.type in {"azurerm_key_vault", "azurerm_storage_account", "azurerm_mssql_server"}
  msg := sprintf("%s: deleting stateful resource requires a change exception", [rc.address])
}
```

Run with `conftest test plan.json -p policy/terraform` in the plan and apply jobs.

### 14.6 `SECURITY.md`

Include: supported versions, how to report a vulnerability (GitHub private vulnerability
reporting link — never public issues), response SLAs (§4.3), and a pointer to
`docs/security/` for internal runbooks.

---

## 15. Deployment security validation

### 15.1 Gates before any deployment

1. Image referenced **by digest**, digest format validated (`^sha256:[a-f0-9]{64}$`).
2. `gh attestation verify` succeeds for **build provenance** (built by this repo's
   `container-security.yml` on `main`/tag) and **SBOM** attestation.
3. Release vulnerability gate (Trivy, release thresholds §4.2) passes on the digest
   pulled from the registry, honouring only valid, unexpired exceptions.
4. Exception register valid (`validate_exceptions.py`).
5. GitHub environment protection rules satisfied (reviewers for staging/prod).
6. Azure access via OIDC identity scoped to that environment only.
7. Post-deploy: health check passes; deployed image digest equals the approved digest.

### 15.2 `.github/workflows/deploy.yml`

Example for **Azure Container Apps**; replace the deploy step with the target detected
in Phase 0 (App Service: `azure/webapps-deploy` with `images: <reg>/<img>@<digest>`;
AKS: update manifests to the digest and apply via GitOps).
Environment variables per environment: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
`AZURE_SUBSCRIPTION_ID`, `ACR_NAME` (source), `PROD_ACR_NAME` (prod only, optional),
`IMAGE_NAME`, `APP_NAME`, `APP_RESOURCE_GROUP`, `APP_HEALTH_URL`.

```yaml
name: Deploy

on:
  workflow_run:
    workflows: ["Container Security"]
    types: [completed]
    branches: [main]
  workflow_dispatch:
    inputs:
      environment:
        description: Target environment
        type: choice
        options: [dev, staging, prod]
        required: true
      digest:
        description: "Image digest to deploy (sha256:...) - must already be in the dev ACR"
        type: string
        required: true

permissions: {}

jobs:
  resolve:
    name: Resolve artifact
    if: >-
      github.event_name == 'workflow_dispatch' ||
      (github.event.workflow_run.conclusion == 'success' &&
       github.event.workflow_run.event == 'push' &&
       github.event.workflow_run.head_repository.full_name == github.repository)
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      actions: read
    outputs:
      digest: ${{ steps.out.outputs.digest }}
      environment: ${{ steps.out.outputs.environment }}
    steps:
      - name: Download digest from triggering run
        if: github.event_name == 'workflow_run'
        uses: actions/download-artifact@v4
        with:
          name: image-digest
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
      - id: out
        env:
          EVENT: ${{ github.event_name }}
          INPUT_DIGEST: ${{ inputs.digest }}
          INPUT_ENV: ${{ inputs.environment }}
        run: |
          set -euo pipefail
          if [ "$EVENT" = "workflow_run" ]; then digest=$(tr -d '[:space:]' < image-digest.txt); env=dev
          else digest="$INPUT_DIGEST"; env="$INPUT_ENV"; fi
          if ! [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]; then echo "::error::Invalid digest"; exit 1; fi
          echo "digest=$digest" >> "$GITHUB_OUTPUT"
          echo "environment=$env" >> "$GITHUB_OUTPUT"

  deploy:
    name: Deploy to ${{ needs.resolve.outputs.environment }}
    needs: resolve
    runs-on: ubuntu-latest
    timeout-minutes: 30
    environment:
      name: ${{ needs.resolve.outputs.environment }}
      url: ${{ vars.APP_HEALTH_URL }}
    concurrency:
      group: deploy-${{ needs.resolve.outputs.environment }}
      cancel-in-progress: false
    permissions:
      contents: read
      id-token: write
      attestations: read
    env:
      DIGEST: ${{ needs.resolve.outputs.digest }}
      TARGET_ENV: ${{ needs.resolve.outputs.environment }}
      ACR_NAME: ${{ vars.ACR_NAME }}
      PROD_ACR_NAME: ${{ vars.PROD_ACR_NAME }}
      IMAGE_NAME: ${{ vars.IMAGE_NAME }}
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }

      - name: Azure login (OIDC, environment-scoped identity)
        uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}

      - name: Registry login
        run: az acr login --name "$ACR_NAME" > /dev/null

      - name: Verify build provenance and SBOM attestations
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          ref="oci://${ACR_NAME}.azurecr.io/${IMAGE_NAME}@${DIGEST}"
          gh attestation verify "$ref" --repo "$GITHUB_REPOSITORY" \
            --signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/container-security.yml" > /dev/null
          gh attestation verify "$ref" --repo "$GITHUB_REPOSITORY" \
            --predicate-type "https://spdx.dev/Document/v2.3" > /dev/null
          echo "Provenance and SBOM attestations verified for ${DIGEST}" >> "$GITHUB_STEP_SUMMARY"

      - name: Validate exception register
        run: |
          python -m pip install --disable-pip-version-check "pyyaml==6.*"
          python .github/scripts/validate_exceptions.py

      - name: Release vulnerability gate
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: image
          image-ref: ${{ vars.ACR_NAME }}.azurecr.io/${{ vars.IMAGE_NAME }}@${{ needs.resolve.outputs.digest }}
          trivy-config: trivy.yaml
          scanners: vuln,secret
          severity: ${{ vars.SEC_RELEASE_FAIL_SEVERITY || 'CRITICAL,HIGH' }}
          ignore-unfixed: ${{ vars.SEC_RELEASE_IGNORE_UNFIXED || 'false' }}
          exit-code: "1"

      - name: Promote to production registry (by digest)
        id: promote
        run: |
          set -euo pipefail
          registry="${ACR_NAME}.azurecr.io"
          if [ "$TARGET_ENV" = "prod" ] && [ -n "${PROD_ACR_NAME}" ]; then
            az acr import --name "$PROD_ACR_NAME" \
              --source "${registry}/${IMAGE_NAME}@${DIGEST}" \
              --image "${IMAGE_NAME}:sha-${DIGEST:7:12}" --force > /dev/null
            registry="${PROD_ACR_NAME}.azurecr.io"
          fi
          echo "image=${registry}/${IMAGE_NAME}@${DIGEST}" >> "$GITHUB_OUTPUT"

      - name: Deploy (Azure Container Apps, by digest)
        env:
          IMAGE: ${{ steps.promote.outputs.image }}
          APP_NAME: ${{ vars.APP_NAME }}
          APP_RG: ${{ vars.APP_RESOURCE_GROUP }}
        run: |
          set -euo pipefail
          az containerapp update -n "$APP_NAME" -g "$APP_RG" --image "$IMAGE" > /dev/null
          deployed=$(az containerapp show -n "$APP_NAME" -g "$APP_RG" --query "properties.template.containers[0].image" -o tsv)
          [ "$deployed" = "$IMAGE" ] || { echo "::error::Deployed image does not match approved digest"; exit 1; }

      - name: Smoke test
        env:
          HEALTH_URL: ${{ vars.APP_HEALTH_URL }}
        run: |
          set -euo pipefail
          for i in $(seq 1 20); do
            if curl -fsS --max-time 5 -o /dev/null "$HEALTH_URL"; then echo "Healthy"; exit 0; fi
            sleep 10
          done
          echo "::error::Health check failed - roll back to the previous digest"; exit 1

      - name: Deployment evidence
        if: always()
        env:
          IMAGE: ${{ steps.promote.outputs.image }}
        run: |
          {
            echo "### Deployment evidence"
            echo "- Environment: \`${TARGET_ENV}\`"
            echo "- Image: \`${IMAGE}\`"
            echo "- Commit: \`${GITHUB_SHA}\` · Run: ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
          } >> "$GITHUB_STEP_SUMMARY"
```

Rollback: re-run `deploy.yml` via `workflow_dispatch` with the previous known-good
digest (from the last successful deployment's evidence). Rollbacks pass the same gates.
After deployment, Defender for Cloud continuously re-assesses running images; findings
flow to §16 and §17.

---

## 16. Vulnerability reporting and remediation

### 16.1 Where findings live

| Source | Location | Machine-readable |
|---|---|---|
| CodeQL, Gitleaks, Trivy, Checkov, Hadolint, zizmor, Scorecard | Security → Code scanning (by `category`) | SARIF, REST `code-scanning/alerts` |
| Dependabot | Security → Dependabot | REST `dependabot/alerts` |
| GitHub secret scanning | Security → Secret scanning | REST `secret-scanning/alerts` |
| Trivy JSON, SBOMs | Workflow artifacts (30–90 days) + registry attestations | JSON / SPDX |
| Defender for Cloud (incl. DevOps security connector for GitHub) | Defender recommendations | Azure Resource Graph |

### 16.2 Triage workflow

1. **New finding** → owner = CODEOWNER of the affected path (security team for shared
   config). Triage within 2 business days (Critical: same day).
2. Classify: true positive / false positive / not exploitable / accepted risk.
3. True positive → fix PR referencing the alert (`Fixes code-scanning alert #N`,
   `GHSA-...`) within SLA (§4.3). Use Copilot Autofix / Dependabot PR where available;
   the fix PR passes all gates like any other.
4. False positive / not exploitable → dismiss with reason and comment containing an
   exception id; tool suppression + register entry (§4.5).
5. Verify closure: the alert closes automatically when the fixed code reaches the
   default branch; for deployed artifacts, the next deploy re-scan must be clean.
6. Metrics: open count by severity, SLA breaches, mean time to remediate, exceptions
   expiring within 14 days, push-protection bypasses.

### 16.3 `.github/workflows/security-report.yml`

```yaml
name: Security Report

on:
  schedule:
    - cron: "0 6 * * 1"              # weekly, Monday 06:00 UTC
  workflow_dispatch:

permissions: {}

jobs:
  posture:
    name: Weekly security posture
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      issues: write
      security-events: read          # code scanning + Dependabot alerts
    env:
      GH_TOKEN: ${{ github.token }}
      REPO: ${{ github.repository }}
    steps:
      - name: Collect alert counts and SLA breaches (no secret values)
        run: |
          set -euo pipefail
          sla='{"critical":3,"high":14,"medium":60,"low":180}'
          cs=$(gh api --paginate "repos/${REPO}/code-scanning/alerts?state=open&per_page=100" \
                 --jq '.[] | {sev: (.rule.security_severity_level // .rule.severity // "unknown"), created: .created_at}' | jq -s '.' || echo '[]')
          db=$(gh api --paginate "repos/${REPO}/dependabot/alerts?state=open&per_page=100" \
                 --jq '.[] | {sev: .security_advisory.severity, created: .created_at}' | jq -s '.' || echo '[]')
          summarize() {
            jq -r --argjson sla "$sla" '
              def age: ((now - (.created | fromdateiso8601)) / 86400 | floor);
              (group_by(.sev) | map("| \(.[0].sev) | \(length) | \(map(select(($sla[.sev] // 99999) < age)) | length) |") | .[])'
          }
          {
            echo "## Weekly security posture – $(date -u +%F)"
            echo ""
            echo "### Code scanning (CodeQL, Trivy, Checkov, Gitleaks, …)"
            echo "| Severity | Open | Past SLA |"; echo "|---|---|---|"
            echo "$cs" | summarize
            echo ""
            echo "### Dependabot"
            echo "| Severity | Open | Past SLA |"; echo "|---|---|---|"
            echo "$db" | summarize
            echo ""
            echo "Secret scanning counts require a GitHub App token with *Secret scanning alerts: read*; see docs/security/DEVSECOPS.md."
            echo ""
            echo "Exceptions expiring within 14 days must be renewed or fixed."
          } > report.md
          cat report.md >> "$GITHUB_STEP_SUMMARY"

      - name: Create or update posture issue
        run: |
          set -euo pipefail
          gh label create security-posture --repo "$REPO" --color B60205 2>/dev/null || true
          num=$(gh issue list --repo "$REPO" --label security-posture --state open --json number --jq '.[0].number // empty')
          if [ -n "$num" ]; then gh issue edit "$num" --repo "$REPO" --body-file report.md
          else gh issue create --repo "$REPO" --title "Security posture report" --label security-posture --body-file report.md; fi
```

- If the repository's `GITHUB_TOKEN` cannot read Dependabot alerts in your setup, use a
  GitHub App installation token with *Dependabot alerts: read*.
- Secret scanning alerts: the REST API returns the secret value. Any job that reads it
  MUST project only safe fields, e.g.
  `--jq '.[] | {number, secret_type, state, created_at}'` — **never** `.secret`.
- Add a job that re-scans the **currently deployed** digest per environment (read it with
  a Reader identity via `az containerapp show ... --query properties.template.containers[0].image`)
  and opens/updates an issue when new Critical/High CVEs appear.

### 16.4 Notifications

- Code scanning / Dependabot / secret scanning alerts → repository watchers and the
  security team (GitHub notifications or security-alert webhooks to Teams).
- Gate failures on `main`, deploy failures and scheduled-scan regressions → issue + Teams
  channel via a webhook stored as an Actions secret (never echo the URL).

---

## 17. Security monitoring and audit logging

### 17.1 GitHub

- Enable organisation/enterprise **audit log streaming** to Azure Event Hubs or Azure
  Blob Storage and ingest into Microsoft Sentinel (GitHub data connector).
- Events to alert on: `secret_scanning_push_protection.bypass`, secret scanning or push
  protection disabled, `repository_ruleset.update`/`destroy`, `protected_branch.policy_override`,
  environment protection changes, new deploy keys, Actions secrets/variables changed,
  repository visibility changed, OIDC subject-claim customisation changed, self-hosted runner registered.
- Use **Security overview** for cross-repo coverage and risk dashboards.

### 17.2 Azure

- Subscription Activity Log → Log Analytics (diagnostic setting at subscription scope).
- Diagnostic settings (all logs) for Key Vault (`AuditEvent`), Storage (blob read/write/delete),
  ACR (`ContainerRegistryRepositoryEvents`, `ContainerRegistryLoginEvents`), Container
  Apps/App Service, SQL auditing. Enforce with Azure Policy `DeployIfNotExists`.
- Microsoft Defender for Cloud plans: Containers, Key Vault, Storage, Resource Manager,
  App Service, Databases as relevant; **DevOps security** connector for GitHub to surface
  GHAS findings and IaC misconfigurations alongside cloud posture.
- Entra ID sign-in logs incl. `AADServicePrincipalSignInLogs` and `AADManagedIdentitySignInLogs`.
- Retention: ≥ 90 days interactive, ≥ 1 year archive (or per regulatory requirement).
- Alerts route to an Action Group (security on-call + Teams).

### 17.3 Review cadence

| What | Who | When |
|---|---|---|
| Push-protection bypasses, ruleset bypasses | Security team | Weekly |
| Role assignments & federated credentials of CI identities | Cloud platform + security | Monthly |
| Exception register | Security approvers | Monthly + on expiry |
| Audit log alert tuning | SecOps | Quarterly |

### 17.4 Starter KQL (validate column names in your workspace; resource-specific tables differ from `AzureDiagnostics`)

```kql
// 1. Role assignments created outside the approved pipeline identities
AzureActivity
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue =~ "Success"
| where Caller !in~ (dynamic(["<pipeline-identity-object-id-1>", "<pipeline-identity-object-id-2>"]))
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, _ResourceId

// 2. Federated identity credential changes (OIDC trust tampering)
AzureActivity
| where OperationNameValue has "FEDERATEDIDENTITYCREDENTIALS"
| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue, _ResourceId

// 3. Storage account key listing / regeneration (shared-key misuse)
AzureActivity
| where OperationNameValue in~ ("MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
                                 "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION")
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId

// 4. Key Vault denied or unusual secret access
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent"
| where OperationName in ("SecretGet", "SecretList", "SecretSet", "SecretDelete")
| summarize Calls = count(), Denied = countif(ResultSignature in ("Forbidden", "Unauthorized"))
          by Resource, OperationName, CallerIPAddress, bin(TimeGenerated, 1h)
| where Denied > 0 or Calls > 100

// 5. Use of a specific (possibly leaked) service principal during an exposure window
AADServicePrincipalSignInLogs
| where AppId == "<app-id>" and TimeGenerated between (datetime(<first-exposure>) .. now())
| project TimeGenerated, IPAddress, Location, ResourceDisplayName, ResultType
```

---

## 18. Validation – prove the pipeline works

Never report the pipeline as working without the evidence below. Record results (with
run URLs) in `docs/security/DEVSECOPS.md` → "Validation evidence".

### 18.1 Static validation (local or in a scratch workflow)

```bash
# YAML syntax for every generated YAML file
python3 - <<'PY'
import pathlib, sys, yaml
bad = 0
for p in list(pathlib.Path('.github').rglob('*.yml')) + list(pathlib.Path('.').glob('*.yaml')):
    try: yaml.safe_load(p.read_text())
    except Exception as e: bad += 1; print(f"YAML error in {p}: {e}")
sys.exit(1 if bad else 0)
PY
docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.7            # workflow lint
zizmor .github/workflows                                                   # workflow security lint
python3 .github/scripts/validate_exceptions.py                             # exception register
docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:v8.24.3 dir /repo --config /repo/.gitleaks.toml --redact  # config loads
terraform fmt -check -recursive && tflint --init && tflint --recursive      # if Terraform
checkov --config-file .checkov.yaml                                        # if IaC/Dockerfiles
hadolint --config .hadolint.yaml Dockerfile                                # if Dockerfile
trivy config --config trivy.yaml .                                         # misconfig
bash -n .github/scripts/security_summary.sh                                # script syntax
```

Dependabot config: after pushing, check Insights → Dependency graph → Dependabot for
parse errors (`gh api "repos/{owner}/{repo}/dependabot/..."` does not validate config;
the UI and the first scheduled run do).

### 18.2 Functional "canary" tests (each gate must FAIL when it should)

Run on a throwaway branch, one canary per PR, then close the PR and delete the branch.
**Never use a real credential** — generate random fake values.

| Gate | Canary change | Expected result |
|---|---|---|
| Push protection | Commit a fake value in a provider format GitHub detects | `git push` rejected with push-protection message (do not bypass) |
| Gitleaks | Fake Azure storage connection string (random 86-char base64 key) in a config file | `sec-gitleaks` fails; SARIF shows `REDACTED`; log shows no value |
| CodeQL | Add a string-concatenated SQL query / command injection in app language | Code scanning alert on the PR; merge blocked by code scanning rule |
| Dependency review / Trivy fs | Add a dependency at a version with a known High/Critical CVE | `sec-dependency-review` and `sec-trivy-fs` fail and list the patched version |
| Container | Remove `USER` line (or use an outdated base) | `sec-image-scan` fails on root user / Critical-High CVEs |
| IaC | Storage account with `public_network_access_enabled = true` + NSG allowing `0.0.0.0/0:22` | `sec-iac-scan` fails (Checkov + Trivy) |
| Policy | Unpinned `uses: actions/checkout@v4`; expired exception | `sec-policy-checks` fails |
| Deploy | Dispatch `deploy.yml` with a digest not built by this repo | Attestation verification fails; nothing deployed |
| Dependabot | Wait for/trigger a Dependabot PR | All required checks run on it; no secrets exposed; no auto-merge unless opted in |

Also confirm the happy path: a clean PR passes all required checks, a merge to `main`
publishes a digest with provenance + SBOM attestations, and `deploy.yml` deploys it to dev.

### 18.3 Settings verification

```bash
gh api "repos/{owner}/{repo}" --jq '.security_and_analysis'
gh api "repos/{owner}/{repo}/rulesets" --jq '.[] | {name, enforcement}'
gh api "repos/{owner}/{repo}/environments" --jq '.environments[] | {name, protection_rules}'
gh api "repos/{owner}/{repo}/actions/permissions/workflow"
az identity federated-credential list --identity-name <id> -g <rg> --query "[].{name:name, subject:subject}" -o table
az role assignment list --assignee <principal-id> --all --query "[].{role:roleDefinitionName, scope:scope}" -o table
```

Expected: all security features `enabled`; ruleset `active`; prod environment has
reviewers + `main`-only branch policy; default workflow permissions `read`; each CI
identity has exactly one environment subject and least-privilege roles; no client secrets
on CI app registrations (`az ad app credential list --id <appId>` returns `[]`).

---

## 19. Maintenance and continuous improvement

| Cadence | Task |
|---|---|
| Continuous | Dependabot PRs (incl. action SHA and image digest bumps) reviewed within SLA |
| Weekly | Posture issue triage; push-protection bypass review; CodeQL scheduled scan review |
| Monthly | Exception register review; CI identity role/federation review; Scorecard trend |
| Quarterly | Tool version review (Trivy DB/policies, Checkov, TFLint rulesets, Gitleaks rules); gate threshold review; secret-incident tabletop exercise |
| On new stack/component | Re-run Phase 0; add CodeQL language, Dependabot ecosystem, audit step, required check |
| On incident | Post-incident review → new custom pattern / policy / test |

Change management for this pipeline: changes to `.github/`, `.security/` and scanner
configs require security CODEOWNER approval, must keep all gates at least as strict,
and must update `docs/security/DEVSECOPS.md`.

---

## 20. Definition of done (acceptance checklist)

- [ ] Phase 0 inventory recorded; only detected ecosystems configured.
- [ ] CodeQL (advanced setup) runs on PR, push to `main`, weekly; SARIF in Code Scanning; `actions` language included.
- [ ] `.github/dependabot.yml` covers app ecosystem(s), `github-actions`, `docker`, `terraform` as applicable; security updates enabled; grouping + limits set; auto-merge disabled or explicitly opted-in with documented policy.
- [ ] Secret scanning + push protection (+ validity checks, non-provider patterns, custom patterns where licensed) enabled; Gitleaks gate with redaction; weekly full-history scan.
- [ ] `docs/security/secret-incident-response.md` present with revoke → rotate → remove → history → review → record.
- [ ] SCA: dependency review, Trivy fs (SARIF + JSON + gate), ecosystem audit; severity gates via repo variables.
- [ ] Container: Hadolint, Trivy config/image, non-root/port/latest checks, optional read-only runtime test, SBOM, push by digest, tag lock, provenance + SBOM attestations, post-publish scan.
- [ ] IaC: fmt, validate, TFLint (azurerm ruleset), Checkov (code + plan), Trivy config; OIDC plan on PR (same-repo), environment-gated apply; no plan/state artifacts.
- [ ] OIDC only: no `AZURE_CREDENTIALS`, no client secrets; one identity per purpose/environment with least privilege.
- [ ] Key Vault: RBAC, purge protection, network restricted, logs on; workloads use managed identity; pipeline reads masked.
- [ ] All actions SHA-pinned; tool images digest-pinned; policy workflow enforces it; Scorecard running.
- [ ] Ruleset active with required checks + code scanning merge protection; CODEOWNERS; environments with reviewers.
- [ ] Deployment verifies attestations, re-scans by digest, deploys by digest, smoke tests, records evidence.
- [ ] Weekly posture report issue; SLAs and exception process documented.
- [ ] Audit logging: GitHub audit stream (if Enterprise), Activity Log + resource diagnostics to Log Analytics, Defender plans, starter KQL alerts.
- [ ] §18 static validation passes and every §18.2 canary failed as expected (evidence linked).
- [ ] No secret value appears in any log, summary, SARIF, artifact, issue or commit.
