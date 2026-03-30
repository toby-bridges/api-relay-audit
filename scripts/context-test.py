#!/usr/bin/env python3
"""
Standalone context length truncation test.

Places 5 canary markers at equal intervals in progressively longer texts,
uses coarse scan + binary search to find the exact truncation boundary.

Usage:
  python scripts/context-test.py --key YOUR_KEY --url https://relay.example.com/v1
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api_relay_audit.client import APIClient
from api_relay_audit.context import run_context_scan


def parse_args():
    p = argparse.ArgumentParser(description="API context length truncation test")
    p.add_argument("--key", required=True, help="API Key")
    p.add_argument("--url", required=True, help="Base URL (e.g. https://xxx.com/v1)")
    p.add_argument("--model", default="claude-opus-4-6", help="Model name")
    p.add_argument("--timeout", type=int, default=120, help="Request timeout (seconds)")
    return p.parse_args()


def main():
    args = parse_args()
    client = APIClient(args.url, args.key, args.model, timeout=args.timeout)

    print(f"Context truncation test | {client.base_url} | {args.model}")
    print("=" * 50)

    results = run_context_scan(client)

    print(f"\n{'=' * 50}\nSummary:")
    for k, found, total, tokens, status, _elapsed in results:
        icon = "OK  " if status == "ok" else "FAIL"
        print(f"  {icon} {k:>5}K chars | {str(tokens or '?'):>8} tokens | {found}/{total}")

    ok = [r[0] for r in results if r[4] == "ok"]
    fail = [r[0] for r in results if r[4] != "ok"]
    if ok and fail:
        print(f"\nTruncation boundary: {max(ok)}K ~ {min(fail)}K chars")
    elif not fail and ok:
        print(f"\nAll passed, no truncation! Max tested: {max(ok)}K chars")


if __name__ == "__main__":
    main()
