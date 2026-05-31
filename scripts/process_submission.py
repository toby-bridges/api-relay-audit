#!/usr/bin/env python3
"""
Process an audit-submission GitHub Issue and update the relay leaderboard data.

Called by the process-submission.yml GitHub Action. Reads issue metadata from
environment variables set by the action, validates the submission, and appends
to web/data/relays.json. Writes status to $GITHUB_OUTPUT for workflow routing.

Usage (by GitHub Action):
  python scripts/process_submission.py

Environment variables (set by the Action):
  ISSUE_BODY        — full issue body text
  ISSUE_AUTHOR      — GitHub username of the submitter
  ISSUE_NUMBER      — issue number
  ISSUE_CREATED_AT  — ISO timestamp of issue creation
  AUTHOR_CREATED_AT — ISO timestamp of the author's GitHub account creation
  GITHUB_OUTPUT     — path to output file (set by GitHub Actions runtime)
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

RELAYS_JSON = Path(__file__).resolve().parent.parent / "web" / "data" / "relays.json"
ACCOUNT_AGE_WARN_DAYS = 30
MAX_SUBMISSIONS_PER_RELAY_24H = 10
MAX_RED_FLAGS = 10
MAX_FLAG_LENGTH = 500
MAX_IMAGES = 4
MAX_VERSION_LENGTH = 20
HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MARKDOWN_IMAGE_RE = re.compile(r"!\[[^\]\r\n]*\]\((https://[^\s)]+)\)")


def _set_output(key, value):
    """Write a key=value pair to $GITHUB_OUTPUT (no-op outside Actions)."""
    path = os.environ.get("GITHUB_OUTPUT", "")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{key}={value}\n")


def parse_issue_body(body):
    """Extract structured fields from the GitHub Issue form body."""
    fields = {}

    patterns = {
        "relay_domain": r"### Relay Domain.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "profile": r"### Audit Profile.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "tool_version": r"### Tool Version.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "overall_rating": r"### Overall Rating.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "red_flags": r"### Key Findings.*?\n\n(.+?)(?:\n###|\Z)",
        "report_image": r"### Report Screenshot.*?\n\n(.+?)(?:\n###|\Z)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, body, re.DOTALL | re.IGNORECASE)
        if match:
            fields[key] = match.group(1).strip()

    return fields


def normalize_domain(domain):
    """Lowercase, strip whitespace and trailing dots."""
    return domain.lower().strip().rstrip(".")


def is_valid_hostname(hostname):
    """Return True for canonical ASCII hostnames without ports or URL syntax."""
    if not hostname:
        return False
    if len(hostname) > 253:
        return False
    if not hostname.isascii():
        return False
    if any(ch in hostname for ch in "/\\:@?#[]"):
        return False

    labels = hostname.split(".")
    return all(HOSTNAME_LABEL_RE.fullmatch(label) for label in labels)


def validate_fields(fields):
    """Return list of error messages. Empty list = valid."""
    errors = []

    required = ["relay_domain", "profile", "tool_version", "overall_rating", "report_image"]
    for f in required:
        if not fields.get(f):
            errors.append(f"Missing required field: {f}")

    if fields.get("overall_rating", "").upper() not in ("LOW", "MEDIUM", "HIGH"):
        errors.append(f"Invalid overall_rating: {fields.get('overall_rating')}")

    if fields.get("profile", "").lower() not in ("general", "web3", "full"):
        errors.append(f"Invalid profile: {fields.get('profile')}")

    version = fields.get("tool_version", "")
    if version:
        if len(version) > MAX_VERSION_LENGTH:
            errors.append(f"tool_version too long (max {MAX_VERSION_LENGTH}): {version}")
        elif not re.fullmatch(r"v?\d+\.\d+(?:\.\d+)?", version):
            errors.append(f"Invalid tool_version format: {version}")

    domain = fields.get("relay_domain", "")
    if domain:
        canonical_domain = normalize_domain(domain)
        if not is_valid_hostname(canonical_domain):
            errors.append(f"Invalid relay_domain (hostname only, no port/path): {domain}")

    report_image = fields.get("report_image", "")
    if report_image and not extract_image_urls(report_image):
        errors.append("report_image must contain at least one image URL (![alt](https://...))")

    return errors


def check_account_age(author_created_at):
    """Return True if account is younger than ACCOUNT_AGE_WARN_DAYS."""
    if not author_created_at:
        return True
    try:
        created = datetime.fromisoformat(author_created_at.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - created).days
        return age < ACCOUNT_AGE_WARN_DAYS
    except (ValueError, TypeError):
        print(f"WARNING: could not parse author_created_at: {author_created_at!r}")
        return True


def check_rate_limit(domain, relays_data):
    """Return True if domain has >= MAX_SUBMISSIONS_PER_RELAY_24H in last 24h."""
    now = datetime.now(timezone.utc)
    count = 0
    canonical_domain = normalize_domain(domain)
    for entry in relays_data:
        if normalize_domain(entry.get("domain", "")) != canonical_domain:
            continue
        try:
            submitted = datetime.fromisoformat(
                entry.get("submittedAt", "2000-01-01").replace("Z", "+00:00")
            )
            if (now - submitted).total_seconds() < 86400:
                count += 1
        except (ValueError, TypeError):
            pass
    return count >= MAX_SUBMISSIONS_PER_RELAY_24H


def extract_image_urls(text):
    """Extract strict HTTPS image URLs from markdown image syntax."""
    urls = []
    for match in MARKDOWN_IMAGE_RE.finditer(text):
        url = match.group(1)
        parsed = urlparse(url)
        if parsed.scheme == "https" and parsed.netloc:
            urls.append(url)
    return urls


def build_relay_entry(fields, issue_author, issue_number, now=None):
    """Build a relay data entry from validated fields."""
    rating_map = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}
    rating_label_map = {
        "LOW": "\U0001f7e2 Low Risk",
        "MEDIUM": "\U0001f7e1 Medium Risk",
        "HIGH": "\U0001f534 High Risk",
    }

    if now is None:
        now = datetime.now(timezone.utc)

    overall = fields["overall_rating"].upper()
    image_urls = extract_image_urls(fields.get("report_image", ""))[:MAX_IMAGES]

    red_flags = []
    if fields.get("red_flags"):
        for line in fields["red_flags"].split("\n"):
            line = line.strip().lstrip("- ")[:MAX_FLAG_LENGTH]
            if line:
                red_flags.append(line)
            if len(red_flags) >= MAX_RED_FLAGS:
                break

    return {
        "domain": normalize_domain(fields["relay_domain"]),
        "rating": rating_map.get(overall, "yellow"),
        "ratingLabel": rating_label_map.get(overall, overall),
        "testDate": now.strftime("%Y-%m-%d"),
        "submittedAt": now.isoformat(),
        "submittedBy": issue_author,
        "issueNumber": int(issue_number) if issue_number else None,
        "toolVersion": fields.get("tool_version", ""),
        "profile": fields.get("profile", "general").lower(),
        "redFlags": red_flags,
        "reportImages": image_urls,
        "source": "community",
    }


def main():
    body = os.environ.get("ISSUE_BODY", "")
    author = os.environ.get("ISSUE_AUTHOR", "")
    issue_number = os.environ.get("ISSUE_NUMBER", "")
    author_created_at = os.environ.get("AUTHOR_CREATED_AT", "")

    if not body:
        print("ERROR: ISSUE_BODY is empty")
        _set_output("status", "ERROR")
        sys.exit(1)

    fields = parse_issue_body(body)
    errors = validate_fields(fields)
    if errors:
        print("VALIDATION_ERRORS:")
        for e in errors:
            print(f"  - {e}")
        _set_output("status", "VALIDATION_ERRORS")
        sys.exit(2)

    if check_account_age(author_created_at):
        print("NEEDS_REVIEW: account younger than 30 days")
        _set_output("status", "NEEDS_REVIEW")
        sys.exit(3)

    if RELAYS_JSON.exists():
        relays_data = json.loads(RELAYS_JSON.read_text(encoding="utf-8"))
    else:
        relays_data = []

    domain = normalize_domain(fields["relay_domain"])
    if check_rate_limit(domain, relays_data):
        print(f"RATE_LIMITED: {domain} has >= {MAX_SUBMISSIONS_PER_RELAY_24H} submissions in 24h")
        _set_output("status", "RATE_LIMITED")
        sys.exit(4)

    entry = build_relay_entry(fields, author, issue_number)
    relays_data.append(entry)

    RELAYS_JSON.parent.mkdir(parents=True, exist_ok=True)
    RELAYS_JSON.write_text(
        json.dumps(relays_data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    _set_output("status", "OK")
    print(f"OK: added {domain} (#{issue_number}) by @{author}")
    print(f"Total entries: {len(relays_data)}")


if __name__ == "__main__":
    main()
