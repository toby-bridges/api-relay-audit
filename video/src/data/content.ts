export const THREATS = [
  {
    code: "INJECT",
    title: "隐藏提示注入",
    detail: "Invisible instructions",
    color: "#ef4444",
  },
  {
    code: "SIGNAL",
    title: "模型身份异常",
    detail: "Identity mismatch signals",
    color: "#a78bfa",
  },
  {
    code: "TRUNCATE",
    title: "上下文截断",
    detail: "Missing canary markers",
    color: "#f59e0b",
  },
  {
    code: "REWRITE",
    title: "安装命令改写",
    detail: "Changed install commands",
    color: "#fb7185",
  },
] as const;

export const AUDIT_STEPS = [
  "Infra",
  "Models",
  "Injection",
  "Extraction",
  "Identity",
  "Jailbreak",
  "Context",
  "Packages",
  "Leakage",
  "SSE",
  "Web3",
  "Fingerprint",
  "Latency",
  "Channel",
] as const;

export const TERMINAL_LINES = [
  "[01/14] Infrastructure recon",
  "[03/14] Token injection detection",
  "[07/14] Context canary search",
  "[08/14] Package text",
  "[09/14] Error response leakage",
  "[10/14] SSE stream integrity",
  "[14/14] Upstream channel signals",
] as const;

export const REPORT_ROWS = [
  {
    step: "03",
    label: "Token injection",
    verdict: "ANOMALY",
    evidence: "+108 synthetic tokens",
    color: "#ef4444",
  },
  {
    step: "07",
    label: "Context length",
    verdict: "INCONCLUSIVE",
    evidence: "Boundary not established",
    color: "#f59e0b",
  },
  {
    step: "08",
    label: "Package text",
    verdict: "CLEAN",
    evidence: "Pinned command unchanged",
    color: "#10b981",
  },
  {
    step: "09",
    label: "Error leakage",
    verdict: "ANOMALY",
    evidence: "[redacted path]",
    color: "#ef4444",
  },
  {
    step: "10",
    label: "SSE integrity",
    verdict: "CLEAN",
    evidence: "Event invariants pass",
    color: "#10b981",
  },
] as const;
