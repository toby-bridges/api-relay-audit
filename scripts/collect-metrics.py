#!/usr/bin/env python3
"""Collect machine-derivable metrics about api-relay-audit.

Writes:
- docs/_metrics.json (machine-readable)
- docs/_metrics.md   (human-readable, with self-consistency checks)

Run before publishing any external comparison/blog/X long-form post that
quotes step counts, test counts, version numbers, or Codex review tallies.

Coverage contract (~70% of typical doc drift):
  version, step count, test count, CLI flag count, profile choices,
  Codex review rounds + cumulative bugs, test-count progression, git HEAD.

Out of scope (~30% of drift, requires human review per docs/_metrics.md):
  external competitor intel, narrative completeness, tone/framing.

Pareto-frontier rationale: see chosen-method discussion in the originating
2026-05-05 session. Single-author, monthly-release project; CI/template-
rendering ROI insufficient — this script is the smallest mechanism that
prevents the failure mode that triggered its creation (comparison doc
drifting 21 days behind code).
"""

import json
import argparse
import difflib
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
METRICS_JSON = DOCS_DIR / "_metrics.json"
METRICS_MD = DOCS_DIR / "_metrics.md"


STEP_PATTERNS = [
    (r'\b(\d+)-step audit\b', "N-step audit"),
    (r'\bfull (\d+)-step audit\b', "full N-step audit"),
    (r'\bruns? all (\d+) steps\b', "runs all N steps"),
    (r'\b(\d+) steps\b', "N steps"),
    (r'\[Step \d+/(\d+)\]', "Step X/N terminal text"),
    (r'(\d+) 步审计', "N 步审计"),
    (r'(\d+) 步检测', "N 步检测"),
    (r'运行 (\d+) 步审计', "运行 N 步审计"),
    (r'运行 (\d+) 步检测', "运行 N 步检测"),
    (r'覆盖 (\d+) 个审计步骤', "覆盖 N 个审计步骤"),
]



def read(path):
    return path.read_text(encoding="utf-8")


def get_version(audit_path):
    m = re.search(r'API Relay Security Audit Tool (v[\d.]+)', read(audit_path))
    return m.group(1) if m else "unknown"


def get_step_count(audit_path):
    nums = {int(m.group(1)) for m in re.finditer(r'Step (\d+)', read(audit_path))}
    return max(nums) if nums else 0


def get_test_count_pytest():
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        m = re.search(r'(\d+) tests collected', result.stdout)
        return int(m.group(1)) if m else None
    except Exception as e:
        print(f"  [warn] pytest collect failed: {e}", file=sys.stderr)
        return None


def get_test_count_static(tests_dir):
    count = 0
    for path in tests_dir.glob("test_*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if re.match(r'^\s*def test_\w+', line):
                count += 1
    return count


def get_cli_flag_count(audit_path):
    return len(re.findall(r'add_argument\(["\']--[\w-]+', read(audit_path)))


def get_profile_choices(audit_path):
    m = re.search(r'"--profile",\s*choices=\[([^\]]+)\]', read(audit_path))
    if not m:
        return []
    return [s.strip().strip('"\'') for s in m.group(1).split(',')]


def get_roadmap_metrics(roadmap_path):
    text = read(roadmap_path)
    out = {}

    m = re.search(r'\*\*Last updated\*\*:\s*(\d{4}-\d{2}-\d{2})', text)
    out["roadmap_last_updated"] = m.group(1) if m else None

    # Find the boundary between Shipped and not-Shipped sections
    boundary = re.search(r'## (?:🔜|🛠|🤔|🚫)', text)
    shipped = text[:boundary.start()] if boundary else text

    rounds = re.findall(r'Codex review (?:cycle|round)\b', shipped)
    out["codex_review_phrase_mentions"] = len(rounds)

    cumulative = re.findall(r'cumulative (\d+) real bug', text)
    out["codex_bugs_cumulative_latest"] = int(cumulative[-1]) if cumulative else None

    progression = re.findall(r'Final test count.*?(\d+)/(\d+)\s+passing', text)
    out["test_count_progression"] = sorted({int(p) for p, t in progression})
    out["test_count_progression_latest"] = (
        max(out["test_count_progression"])
        if out["test_count_progression"]
        else None
    )

    # Extract "Nth Codex review round" / "Nth round" if present
    nth = re.findall(r'(\d+)(?:st|nd|rd|th) Codex review round', text)
    out["last_numbered_review_round"] = max(int(n) for n in nth) if nth else None

    return out


def get_git_metadata(ref="HEAD"):
    out = {}
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "--short", ref],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10
        )
        if sha.returncode == 0:
            out["head_sha"] = sha.stdout.strip()
        date = subprocess.run(
            ["git", "log", "-1", "--format=%cd", "--date=short", ref],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10
        )
        if date.returncode == 0:
            out["head_date"] = date.stdout.strip()
    except Exception:
        pass
    return out


def build_markdown(m):
    lines = [
        "# api-relay-audit — Machine-derivable metrics",
        "",
        "**自动生成 — 不要手动编辑。** 跑 `python scripts/collect-metrics.py` 重新生成。",
        "生成时间戳保存在 `_metrics.json` 的 `generated_at` 字段，不写入本文件——避免每次 commit 产生噪音 diff。",
        "",
        "## 用法",
        "",
        "对外发布任何 comparison / blog / X 长文前，先跑此脚本，对照本文件核对所有数字声明。",
        "脚本覆盖约 70% 常见 drift（结构化指标）；剩余 30% 列在文末「人工 review 边界」。",
        "",
        "## 当前指标",
        "",
        "| 项 | 值 | 来源 |",
        "|---|---|---|",
        f"| 模块版版本 | `{m['version_modular']}` | `scripts/audit.py` docstring |",
        f"| 单文件版版本 | `{m['version_standalone']}` | `audit.py` docstring |",
        f"| 步骤数 (Step N) | **{m['step_count_modular']}** | grep `Step N` in `scripts/audit.py` |",
        f"| 步骤数 (单文件版) | {m['step_count_standalone']} | grep `Step N` in `audit.py` |",
        f"| 测试数 (pytest) | **{m['test_count_pytest']}** | `pytest --collect-only` |",
        f"| 测试数 (static) | {m['test_count_static']} | grep `def test_*` in tests/ |",
        f"| CLI flag 数 | {m['cli_flag_count']} | grep `add_argument(\"--*\")` |",
        f"| profile 选项 | {', '.join(m['profile_choices']) or '(unknown)'} | argparse choices |",
        f"| ROADMAP 上次更新 | {m.get('roadmap_last_updated') or 'unknown'} | `ROADMAP.md` 头部 |",
        f"| Codex review 提及次数 | {m.get('codex_review_phrase_mentions', '?')} | grep `Codex review (cycle\\|round)` 在 Shipped 节 |",
        f"| Codex review 已编号轮次（最大） | {m.get('last_numbered_review_round') or '(无)'} | grep `Nth Codex review round` |",
        f"| Codex bug 累计（最新声称） | {m.get('codex_bugs_cumulative_latest') or '(未声明)'} | grep `cumulative N real bug` |",
        f"| 测试数演进 (ROADMAP) | {m.get('test_count_progression') or []} | grep `Final test count: N/N passing` |",
    ]
    if "head_sha" in m:
        lines.append(
            f"| Recorded commit SHA | `{m['head_sha']}` | recent reachable commit; "
            "`--check` allows follow-up metrics commits |"
        )
    if "head_date" in m:
        lines.append(
            f"| Recorded commit date | {m['head_date']} | recent reachable commit; "
            "`--check` allows follow-up metrics commits |"
        )

    lines += ["", "## 一致性自检", ""]
    if m["version_modular"] != m["version_standalone"]:
        lines.append(
            f"- ⚠️ 版本不一致：模块版 `{m['version_modular']}` vs 单文件版 "
            f"`{m['version_standalone']}`。dual-distribution 允许两者独立 bump，但跨度 >0.1 时值得审视。"
        )
    else:
        lines.append(f"- ✅ 版本一致：两份都是 `{m['version_modular']}`。")

    if m["step_count_modular"] != m["step_count_standalone"]:
        lines.append(
            f"- ⚠️ 步骤数不一致：模块版 {m['step_count_modular']} vs 单文件版 "
            f"{m['step_count_standalone']}。"
        )
    else:
        lines.append(f"- ✅ 步骤数一致：{m['step_count_modular']}。")

    if (
        m["test_count_pytest"]
        and abs(m["test_count_pytest"] - m["test_count_static"]) > 20
    ):
        lines.append(
            f"- ℹ️ pytest ({m['test_count_pytest']}) vs 静态 ({m['test_count_static']}) "
            f"差距 >20，多出来的来自 parametrize/fixture——以 pytest 为准。"
        )

    progression = m.get("test_count_progression") or []
    progression_latest = m.get("test_count_progression_latest")
    if progression_latest and m["test_count_pytest"] and progression_latest != m["test_count_pytest"]:
        lines.append(
            f"- ⚠️ ROADMAP 最新记录 {progression_latest} 个测试，但当前 pytest 是 "
            f"{m['test_count_pytest']}。要么 ROADMAP 漏更新，要么有未记录的新测试。"
        )

    lines += [
        "",
        "## 人工 review 边界（脚本抓不到，每次发布要人工核对）",
        "",
        "1. **外部竞品情报变化**：cctest.ai / hvoy.ai 的检测维度数、模型列表、价格——靠 `~/.claude/projects/.../memory/reference_*.md` 同步",
        "2. **新 feature 是否在文章里被提及**：脚本能列 CLI flags，但无法判断对外文章是否覆盖 `--transparent-log` 这类能力",
        "3. **措辞精度**：例如「11 维度」vs「14 步 / 9 进风险矩阵 / 2 informational」",
        "4. **日期 stamp**：文章 byline 日期 vs 实际发布日期",
        "5. **图/表内容完整性**：脚本不解析对外文档的表格",
        "",
        "## 历史",
        "",
        "由 `scripts/collect-metrics.py` 在 2026-05-05 引入。源起：",
        "`docs/comparison-api-relay-audit-vs-hvoy-vs-cctest.md` (stamp 2026-04-14) 漂了 21 天后",
        "在准备 X 推特发布时被发现约 10 处过期数字。选型走帕累托前沿，选「反推/内省式生成」",
        "（覆盖结构化指标 ~70%、维护成本接近零）。",
    ]
    return "\n".join(lines) + "\n"


def collect_metrics():
    standalone = REPO_ROOT / "audit.py"
    modular = REPO_ROOT / "scripts" / "audit.py"
    roadmap = REPO_ROOT / "ROADMAP.md"
    tests_dir = REPO_ROOT / "tests"

    metrics = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version_standalone": get_version(standalone),
        "version_modular": get_version(modular),
        "step_count_modular": get_step_count(modular),
        "step_count_standalone": get_step_count(standalone),
        "test_count_pytest": get_test_count_pytest(),
        "test_count_static": get_test_count_static(tests_dir),
        "cli_flag_count": get_cli_flag_count(modular),
        "profile_choices": get_profile_choices(modular),
    }
    metrics.update(get_roadmap_metrics(roadmap))
    metrics.update(get_git_metadata())
    return metrics


def write_metrics(metrics):
    DOCS_DIR.mkdir(exist_ok=True)
    METRICS_JSON.write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    METRICS_MD.write_text(build_markdown(metrics), encoding="utf-8")

    print(f"Wrote {METRICS_JSON.relative_to(REPO_ROOT)}")
    print(f"Wrote {METRICS_MD.relative_to(REPO_ROOT)}")


def print_summary(metrics):
    print()
    print(f"  version (modular):    {metrics['version_modular']}")
    print(f"  version (standalone): {metrics['version_standalone']}")
    print(f"  step count:           {metrics['step_count_modular']} (standalone: {metrics['step_count_standalone']})")
    print(f"  test count (pytest):  {metrics['test_count_pytest']}")
    print(f"  CLI flags:            {metrics['cli_flag_count']}")
    print(f"  profile choices:      {metrics['profile_choices']}")
    print(f"  Codex review mentions: {metrics.get('codex_review_phrase_mentions')} (last numbered: {metrics.get('last_numbered_review_round')})")
    print(f"  Codex bugs (cumulative): {metrics.get('codex_bugs_cumulative_latest')}")


def _line_number(text, index):
    return text.count("\n", 0, index) + 1


def _metrics_with_git_ref(metrics, ref):
    git_metadata = get_git_metadata(ref)
    if "head_sha" not in git_metadata:
        return None
    out = dict(metrics)
    out.pop("head_sha", None)
    out.pop("head_date", None)
    out.update(git_metadata)
    return out


def _recent_metrics_with_git_refs(metrics, max_count=50):
    try:
        result = subprocess.run(
            ["git", "rev-list", f"--max-count={max_count}", "HEAD"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return []
    if result.returncode != 0:
        return []

    out = []
    seen = set()
    for ref in result.stdout.splitlines():
        candidate = _metrics_with_git_ref(metrics, ref.strip())
        if not candidate:
            continue
        key = (candidate.get("head_sha"), candidate.get("head_date"))
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate)
    return out


def _check_file_matches_any(path, expected_texts, diff_expected):
    if not path.exists():
        return [f"{path.relative_to(REPO_ROOT)} is missing; run scripts/collect-metrics.py"]
    current = read(path)
    if current in expected_texts:
        return []

    diff = "\n".join(
        difflib.unified_diff(
            current.splitlines(),
            diff_expected.splitlines(),
            fromfile=f"{path.relative_to(REPO_ROOT)} (current)",
            tofile=f"{path.relative_to(REPO_ROOT)} (expected)",
            lineterm="",
            n=3,
        )
    )
    return [
        f"{path.relative_to(REPO_ROOT)} is stale; run scripts/collect-metrics.py",
        diff,
    ]


def _check_numeric_mentions(path, patterns, expected, metric_name):
    if expected is None:
        return []
    text = read(path)
    failures = []
    for pattern, description in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = int(match.group(1))
            if value != expected:
                line = _line_number(text, match.start(1))
                failures.append(
                    f"{path.relative_to(REPO_ROOT)}:{line}: {description} "
                    f"uses {value}, expected {expected} for {metric_name}"
                )
    return failures


def check_public_doc_drift(metrics):
    failures = []

    # Website claims are checked in the standalone website repository against
    # its pinned public release source; this collector owns tool documentation.
    readme = REPO_ROOT / "README.md"
    failures.extend(
        _check_numeric_mentions(
            readme, STEP_PATTERNS, metrics["step_count_modular"], "step count"
        )
    )
    return failures


def check_metrics(metrics):
    failures = []
    # A committed metrics file cannot embed its own final commit SHA because
    # changing the file changes the commit. Accept recent reachable commits
    # so a follow-up docs/CI-only commit does not fail solely because the
    # metrics file records the last metrics-bearing commit. Older HEAD stamps
    # still fail once they fall outside the bounded checkout history.
    expected_metrics = _recent_metrics_with_git_refs(metrics)
    if not expected_metrics:
        expected_metrics = [metrics]
    expected_texts = [build_markdown(m) for m in expected_metrics]
    failures.extend(
        _check_file_matches_any(METRICS_MD, expected_texts, build_markdown(metrics))
    )
    failures.extend(check_public_doc_drift(metrics))
    return failures


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Collect or check machine-derivable project metrics."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Do not write files. Fail if docs/_metrics.md or README.md "
            "has stale step/test/version/HEAD-derived metrics."
        ),
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    metrics = collect_metrics()

    if args.check:
        failures = check_metrics(metrics)
        if failures:
            print("Metrics drift detected:", file=sys.stderr)
            for failure in failures:
                print(failure, file=sys.stderr)
            print("\nRegenerate with: python3 scripts/collect-metrics.py", file=sys.stderr)
            sys.exit(1)
        print("Metrics drift check passed.")
        print_summary(metrics)
        return

    write_metrics(metrics)
    print_summary(metrics)


if __name__ == "__main__":
    main()
