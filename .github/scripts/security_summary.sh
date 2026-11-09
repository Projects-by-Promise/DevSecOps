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
