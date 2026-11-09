# DevSecOps pipeline (GitHub Actions + GitHub Advanced Security + Azure)

These are the security pipeline files defined by [`skills.md`](skills.md) §2. Copy them
into your repository to add automated security checks to pull requests, pushes, builds,
dependency updates and deployments to Azure.

`skills.md` is the full standard. This README tells you how to put the files to use.

## What's included

| Path | Purpose | skills.md |
|---|---|---|
| `.github/workflows/codeql.yml` | CodeQL SAST; languages auto-detected; PR, `main`, weekly | §5 |
| `.github/workflows/secret-scan.yml` | Gitleaks with output redacted; PR range, push, weekly full history | §7 |
| `.github/workflows/sca.yml` | Dependency review, Trivy filesystem scan, ecosystem audits | §8 |
| `.github/workflows/iac-security.yml` | Terraform fmt/validate, TFLint, Checkov, Trivy; OIDC plan and gated apply | §10 |
| `.github/workflows/container-security.yml` | Hadolint, image build and scan, non-root checks, SBOM, push to ACR by digest, attestations | §9, §13 |
| `.github/workflows/deploy.yml` | Verifies attestations, re-scans, deploys to Azure Container Apps by digest | §15 |
| `.github/workflows/security-policy.yml` | actionlint, zizmor, SHA-pinning check, exception register validation | §13.6 |
| `.github/workflows/scorecard.yml` | OpenSSF Scorecard | §13.5 |
| `.github/workflows/security-report.yml` | Weekly posture issue with SLA breaches | §16 |
| `.github/workflows/dependabot-auto-merge.yml` | Opt-in only (`DEPENDABOT_AUTOMERGE_ENABLED=true`) | §6.5 |
| `.github/dependabot.yml` | Dependency updates (only `github-actions` is on until you detect your stack) | §6 |
| `.github/CODEOWNERS`, `docs/security/ruleset-main.json` | Review and merge enforcement | §14 |
| `.gitleaks.toml`, `trivy.yaml`, `.checkov.yaml`, `.tflint.hcl`, `.hadolint.yaml`, `.pre-commit-config.yaml` | Scanner configuration | §7–§10 |
| `.security/exceptions.yaml` | The only place a finding may be accepted (starts empty) | §4.5 |
| `SECURITY.md`, `docs/security/*.md` | Policy, runbooks and implementation record | §4, §7.7 |

## Quick start

1. **Copy** every file in this folder into the root of your repository.
2. **Detect your stack** with the commands in `skills.md` §1, and record the results in
   `docs/security/DEVSECOPS.md`. Then:
   - uncomment the matching blocks in `.github/dependabot.yml`;
   - set `TF_ROOTS` and the Docker variables if you have Terraform or a Dockerfile.
3. **Pin every action to a commit SHA** (§13.1). `security-policy.yml` fails until you do.
4. **Replace the placeholders** in `.github/CODEOWNERS` (`@your-org/...`).
5. **Turn on GitHub security features and Azure OIDC.** Run the commands in §6.1 and §7.1,
   set up OIDC identities and environment variables (§11), create the environments (§14.3),
   then apply the ruleset:
   ```bash
   gh api -X POST "repos/{owner}/{repo}/rulesets" --input docs/security/ruleset-main.json
   ```
   Add your build/test job to the ruleset's required checks first.
6. **Prove it works.** Run the static checks and the deliberately failing test changes in
   §18, and record the run URLs in `docs/security/DEVSECOPS.md`.

The full list of repository and environment variables is in
`docs/security/DEVSECOPS.md`. No secrets are needed: Azure access uses OIDC only.

## Security gates (defaults)

| Severity | Pull request | Release / production |
|---|---|---|
| Critical | Block | Block unless an approved exception exists |
| High | Block if a fix exists | Block unless fixed or excepted |
| Medium / Low | Report | Report and track against the SLA |
| Any secret | Block, then follow `docs/security/secret-incident-response.md` | Block |

You can change the thresholds with repository variables (`SEC_PR_FAIL_SEVERITY`,
`SEC_RELEASE_FAIL_SEVERITY`, …). See §4.2.

## Rules that must not be broken

- Never print, log or commit secrets. Gitleaks always runs with `--redact`.
- No long-lived Azure credentials: use OIDC only, never `AZURE_CREDENTIALS`.
- Don't weaken a gate to make a build pass. Use a registered, expiring exception instead.
- Removing a secret from Git history doesn't replace revoking and rotating it.
