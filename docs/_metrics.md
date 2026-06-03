# api-relay-audit — Machine-derivable metrics

**自动生成 — 不要手动编辑。** 跑 `python scripts/collect-metrics.py` 重新生成。
生成时间戳保存在 `_metrics.json` 的 `generated_at` 字段，不写入本文件——避免每次 commit 产生噪音 diff。

## 用法

对外发布任何 comparison / blog / X 长文前，先跑此脚本，对照本文件核对所有数字声明。
脚本覆盖约 70% 常见 drift（结构化指标）；剩余 30% 列在文末「人工 review 边界」。

## 当前指标

| 项 | 值 | 来源 |
|---|---|---|
| 模块版版本 | `v2.3` | `scripts/audit.py` docstring |
| 单文件版版本 | `v2.3` | `audit.py` docstring |
| 步骤数 (Step N) | **14** | grep `Step N` in `scripts/audit.py` |
| 步骤数 (单文件版) | 14 | grep `Step N` in `audit.py` |
| 测试数 (pytest) | **708** | `pytest --collect-only` |
| 测试数 (static) | 689 | grep `def test_*` in tests/ |
| CLI flag 数 | 20 | grep `add_argument("--*")` |
| profile 选项 | general, web3, full | argparse choices |
| ROADMAP 上次更新 | 2026-06-01 | `ROADMAP.md` 头部 |
| Codex review 提及次数 | 4 | grep `Codex review (cycle\|round)` 在 Shipped 节 |
| Codex review 已编号轮次（最大） | 6 | grep `Nth Codex review round` |
| Codex bug 累计（最新声称） | 18 | grep `cumulative N real bug` |
| 测试数演进 (ROADMAP) | [546, 560, 562, 586, 642, 700] | grep `Final test count: N/N passing` |
| Recorded commit SHA | `af580a6` | recent reachable commit; `--check` allows follow-up metrics commits |
| Recorded commit date | 2026-06-03 | recent reachable commit; `--check` allows follow-up metrics commits |

## 一致性自检

- ✅ 版本一致：两份都是 `v2.3`。
- ✅ 步骤数一致：14。
- ⚠️ ROADMAP 最新记录 700 个测试，但当前 pytest 是 708。要么 ROADMAP 漏更新，要么有未记录的新测试。

## 人工 review 边界（脚本抓不到，每次发布要人工核对）

1. **外部竞品情报变化**：cctest.ai / hvoy.ai 的检测维度数、模型列表、价格——靠 `~/.claude/projects/.../memory/reference_*.md` 同步
2. **新 feature 是否在文章里被提及**：脚本能列 CLI flags，但无法判断对外文章是否覆盖 `--transparent-log` 这类能力
3. **措辞精度**：例如「11 维度」vs「14 步 / 9 进风险矩阵 / 2 informational」
4. **日期 stamp**：文章 byline 日期 vs 实际发布日期
5. **图/表内容完整性**：脚本不解析对外文档的表格

## 历史

由 `scripts/collect-metrics.py` 在 2026-05-05 引入。源起：
`docs/comparison-api-relay-audit-vs-hvoy-vs-cctest.md` (stamp 2026-04-14) 漂了 21 天后
在准备 X 推特发布时被发现约 10 处过期数字。选型走帕累托前沿，选「反推/内省式生成」
（覆盖结构化指标 ~70%、维护成本接近零）。
