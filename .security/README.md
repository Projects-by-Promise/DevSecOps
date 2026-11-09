# Security exceptions

`exceptions.yaml` is the only place a security finding may be accepted (`skills.md` §4.5).

- Every Checkov `#checkov:skip=<ID>:EXC-NNNN reason`, `.trivyignore.yaml` entry (with
  `expired_at` and the id in `statement`) and `.gitleaksignore` fingerprint must reference
  a registered, unexpired `EXC-NNNN`.
- Maximum duration: Critical 30 days, High 90 days, Medium/Low 180 days.
- The owner cannot approve their own exception; approvers are CODEOWNERS of `/.security/`.
- Live secrets can never be excepted - follow `docs/security/secret-incident-response.md`.
- Dismissed GitHub alerts must include the exception id in the dismissal comment.
