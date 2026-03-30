#!/usr/bin/env python3
"""
Extract structured test data from audit report markdown files and update data.json.

Usage:
  python scripts/extract-data.py --reports-dir ./reports --output ./web/data.json
"""

import argparse
import json
import re
from pathlib import Path


def extract_test_result(text, test_name, emoji_map):
    pattern = rf"### {re.escape(test_name)}\s*\n\n(.*?)(?=\n###|\n##|$)"
    match = re.search(pattern, text, re.DOTALL)
    if not match:
        return None

    section = match.group(1)
    reply_match = re.search(r"\*\*Response\*\*:\s*\n\n```(.*?)```", section, re.DOTALL)
    if not reply_match:
        reply_match = re.search(r"\*\*回复\*\*:\s*\n\n```(.*?)```", section, re.DOTALL)
    summary = reply_match.group(1).strip()[:300] if reply_match else ""

    for emoji, keyword in emoji_map.items():
        if emoji in section and keyword in section:
            return {
                "result": "leaked" if "extracted" in section.lower() or "leaked" in section.lower() else "safe",
                "summary": summary,
                "leaked": "extracted" in section.lower() or "leaked" in section.lower(),
            }

    return {"result": "safe", "summary": summary, "leaked": False}


def parse_report(file_path):
    content = file_path.read_text(encoding="utf-8")

    domain_match = re.search(r"\*\*Target\*\*: `https?://([^/`]+)", content)
    if not domain_match:
        domain_match = re.search(r"\*\*目标\*\*: `https?://([^/`]+)", content)
    domain = domain_match.group(1) if domain_match else file_path.stem.replace("audit-", "")

    # Prompt extraction tests
    prompt_tests = []
    test_names = {
        "Test A - Verbatim": "Verbatim",
        "Test B - Translation": "Translation",
        "Test C - JSON continuation": "JSON",
        # Legacy Chinese names
        "测试 A 复述法": "Verbatim",
        "测试 B 翻译法": "Translation",
        "测试 C JSON接龙法": "JSON",
    }
    for test, method in test_names.items():
        result = extract_test_result(content, test, {"🔴": "extracted", "🟢": "safe"})
        if result:
            result["method"] = method
            prompt_tests.append(result)

    # Jailbreak tests
    jailbreak_tests = []
    jailbreak_names = {
        "Test E - System Diagnostic": "Diagnostic",
        "Test F - Base64 Encoding": "Base64",
        "Test G - Role Play": "Role Play",
        "测试 E 系统诊断伪装": "Diagnostic",
        "测试 F Base64编码法": "Base64",
        "测试 G 角色扮演法": "Role Play",
    }
    for test, method in jailbreak_names.items():
        result = extract_test_result(content, test, {"🔴": "leaked", "🟡": "leaked", "🟢": "safe"})
        if result:
            result["method"] = method
            jailbreak_tests.append(result)

    # Context tests
    context_tests = []
    table_match = re.search(
        r"## (?:7\.|七).*?\n\n\|.*?\n\|.*?\n((?:\|.*?\n)+)", content, re.DOTALL
    )
    if table_match:
        for line in table_match.group(1).split("\n"):
            if not line.startswith("|"):
                continue
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 5:
                chars = re.sub(r"[^\d]", "", parts[0].split("K")[0]) if "K" in parts[0] else parts[0]
                context_tests.append({
                    "chars": chars,
                    "tokens": parts[1].replace(",", "").strip(),
                    "recall": parts[2],
                    "status": "OK" if "pass" in line.lower() or "ok" in line.lower() else "FAIL",
                })

    # API format
    api_format = "Anthropic"
    content_lower = content.lower()
    if "owned_by: openai" in content_lower:
        api_format = "Both" if "owned_by: vertex-ai" in content_lower else "OpenAI"

    return {
        "domain": domain,
        "promptTests": prompt_tests,
        "jailbreakTests": jailbreak_tests,
        "contextTests": context_tests,
        "apiFormat": api_format,
    }


def main():
    p = argparse.ArgumentParser(description="Extract audit data from report files")
    p.add_argument("--reports-dir", required=True, help="Directory containing report .md files")
    p.add_argument("--output", required=True, help="Path to data.json to update")
    args = p.parse_args()

    reports_dir = Path(args.reports_dir)
    data_path = Path(args.output)

    if data_path.exists():
        data = json.loads(data_path.read_text(encoding="utf-8"))
    else:
        data = []

    for entry in data:
        report_name = entry.get("fullReport")
        if not report_name:
            continue
        report_file = reports_dir / report_name
        if not report_file.exists():
            print(f"  WARN: report not found: {report_file}")
            continue

        print(f"  Processing: {entry['domain']}")
        details = parse_report(report_file)
        entry["promptTests"] = details["promptTests"]
        entry["jailbreakTests"] = details["jailbreakTests"]
        entry["contextTests"] = details["contextTests"]
        entry["apiFormat"] = details["apiFormat"]

    data_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  data.json updated: {data_path}")


if __name__ == "__main__":
    main()
