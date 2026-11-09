# DevSecOps implementation record

Implements `skills.md`. Update this file whenever the stack, gates or decisions change.

## Repository inventory (skills.md Phase 0)

No application code, Dockerfile or Terraform existed when these files were generated, so
**no stack is assumed**. Run the Phase 0 commands (§1.1–1.4) once code is added, record the
results here, and enable the matching configuration.

| Item | Value | Effect on the pipeline |
|---|---|---|
| Languages | _TBD_ | `codeql.yml` auto-detects languages at runtime (always scans `actions`) |
| Package manifests | _TBD_ | Uncomment matching blocks in `.github/dependabot.yml`; `sca.yml` ecosystem-audit steps run only when their manifest exists |
| Dockerfile(s) | _TBD_ | `container-security.yml` runs only when `Dockerfile` (or `vars.DOCKERFILE`) exists |
| Terraform roots | _TBD_ | `iac-security.yml` runs only when `*.tf` exists; set `vars.TF_ROOTS` |
| Azure deployment target | _TBD_ | `deploy.yml` targets Azure Container Apps; change the deploy step for other targets (§15.2) |
| GitHub plan / GHAS availability | _TBD_ | See §1.4 fallbacks |

## Required GitHub configuration

| Kind | Name | Where | Used by |
|---|---|---|---|
| Variable | `SEC_PR_FAIL_SEVERITY` (`CRITICAL,HIGH`), `SEC_PR_IGNORE_UNFIXED` (`true`) | repo | sca, container-security |
| Variable | `SEC_RELEASE_FAIL_SEVERITY` (`CRITICAL,HIGH`), `SEC_RELEASE_IGNORE_UNFIXED` (`false`) | repo | deploy |
| Variable | `SEC_DEP_REVIEW_FAIL_SEVERITY` (`high`) | repo | sca |
| Variable | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | each environment | OIDC login (§11) |
| Variable | `ACR_NAME`, `IMAGE_NAME`, `DOCKERFILE`, `DOCKER_CONTEXT`, `CONTAINER_SMOKE_TEST` | repo / `acr-push` | container-security |
| Variable | `TF_ROOTS`, `TF_ROOT`, `TFSTATE_RG`, `TFSTATE_ACCOUNT`, `TFSTATE_CONTAINER` | repo / `infra-*` | iac-security |
| Variable | `APP_NAME`, `APP_RESOURCE_GROUP`, `APP_HEALTH_URL`, `PROD_ACR_NAME` | `dev` / `staging` / `prod` | deploy |
| Variable | `DEPENDABOT_AUTOMERGE_ENABLED` (unset = off) | repo | dependabot-auto-merge |
| Environments | `infra-plan`, `infra-dev`, `infra-staging`, `infra-prod`, `acr-push`, `dev`, `staging`, `prod` | repo | §14.3 protections |
| Ruleset | `docs/security/ruleset-main.json` | repo | §14.1 |

No secrets are required: Azure access is OIDC only.

## Decisions and defaults

| Decision | Reason |
|---|---|
| Only `github-actions` active in Dependabot | No other ecosystem detected yet (§6.2: an entry without a manifest fails) |
| `.security/exceptions.yaml` starts empty | No accepted risks exist |
| Auto-merge disabled | §6.5 requires explicit opt-in |
| Actions referenced by tag in the generated files | Must be converted to commit SHAs before committing (§13.1); `security-policy.yml` enforces it |

## Validation evidence (§18)

| Gate | Canary (§18.2) | Run URL | Result |
|---|---|---|---|
| | | | |
