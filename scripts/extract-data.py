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

    # Tool-call package substitution (Step 8, AC-1.a)
    tool_substitution = {"detected": False, "probes": []}
    sub_section_match = re.search(
        r"## 8\. Tool-Call Package Substitution.*?(?=\n## |\Z)",
        content, re.DOTALL,
    )
    if sub_section_match:
        section = sub_section_match.group(0)
        # Detection verdict from the flag line
        if "SUBSTITUTED" in section or "substitution detected" in section.lower():
            tool_substitution["detected"] = True
        # Parse the per-probe table rows
        for line in section.split("\n"):
            if not line.startswith("| "):
                continue
            # Skip the header and separator rows
            if "Manager" in line or "---" in line:
                continue
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 4:
                verdict_cell = parts[3]
                if "exact" in verdict_cell:
                    verdict = "exact"
                elif "whitespace" in verdict_cell:
                    verdict = "whitespace"
                elif "SUBSTITUTED" in verdict_cell:
                    verdict = "substituted"
                elif "skipped" in verdict_cell:
                    verdict = "error"
                else:
                    continue
                tool_substitution["probes"].append({
                    "manager": parts[0],
                    "expected": parts[1].strip("`"),
                    "received": parts[2].strip("`"),
                    "verdict": verdict,
                })

    # Error response leakage (Step 9, AC-2 adjacent)
    error_leakage = {"severity": "none", "triggers": []}
    leak_section_match = re.search(
        r"## 9\. Error Response Leakage.*?(?=\n## |\Z)",
        content, re.DOTALL,
    )
    if leak_section_match:
        section = leak_section_match.group(0)
        # Overall severity from the flag line / table
        if "CRITICAL" in section:
            error_leakage["severity"] = "critical"
        elif "🔴 HIGH" in section or "partial credentials" in section.lower():
            error_leakage["severity"] = "high"
        elif "🟡 MEDIUM" in section or "filesystem paths" in section.lower():
            error_leakage["severity"] = "medium"
        elif "INCONCLUSIVE" in section:
            error_leakage["severity"] = "inconclusive"
        # Parse the per-trigger table rows
        for line in section.split("\n"):
            if not line.startswith("| "):
                continue
            if "Trigger" in line or "---" in line:
                continue
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 4:
                sev_cell = parts[2]
                if "CRITICAL" in sev_cell:
                    sev = "critical"
                elif "HIGH" in sev_cell:
                    sev = "high"
                elif "MEDIUM" in sev_cell:
                    sev = "medium"
                else:
                    sev = "none"
                error_leakage["triggers"].append({
                    "trigger": parts[0],
                    "status": parts[1],
                    "severity": sev,
                    "leaks": parts[3],
                })

    return {
        "domain": domain,
        "promptTests": prompt_tests,
        "jailbreakTests": jailbreak_tests,
        "contextTests": context_tests,
        "apiFormat": api_format,
        "toolSubstitution": tool_substitution,
        "errorLeakage": error_leakage,
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
        entry["toolSubstitution"] = details["toolSubstitution"]
        entry["errorLeakage"] = details["errorLeakage"]

    data_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  data.json updated: {data_path}")


if __name__ == "__main__":
    main()
