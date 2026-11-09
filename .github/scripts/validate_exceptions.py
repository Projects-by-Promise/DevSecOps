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
