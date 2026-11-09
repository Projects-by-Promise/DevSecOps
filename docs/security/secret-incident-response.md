# Secret incident response

Source: `skills.md` §7.7. **Contain first, clean up second.** Removing a secret from Git history never replaces revoking and rotating it.

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
