# JSON reports

Development checkouts support `--format json` in both `scripts/audit.py` and
the generated standalone `audit.py`. It is not available in release v2.4.1.
Markdown remains the default.

```bash
export API_RELAY_AUDIT_KEY=your-relay-key
python scripts/audit.py --key-env API_RELAY_AUDIT_KEY --url https://relay.example.com/v1 --format json --output report.json
```

Omit `--output` to pipe exactly one JSON document from stdout. Progress and
diagnostics go to stderr. With `--output`, stdout is empty and the document
is written as UTF-8. No additional requests or retries are performed.

## Schema version 1

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1`. |
| `report_type` | `audit` or `connectivity`. |
| `generated_at` | UTC timestamp shared with the embedded audit Markdown. |
| `target`, `model`, `profile` | Requested relay, model, and audit profile. |
| `tool_version`, `tool_commit` | Run provenance; commit is empty outside a verified checkout. |
| `risk_level` | Existing final `LOW`, `MEDIUM`, or `HIGH`; `null` when no audit rating was produced. |
| `flags` | Ordered objects containing the original `level` and `message`. Colors do not determine `risk_level`. |
| `coverage` | Audit coverage fields below; `null` for connectivity checks. |
| `markdown` | Complete human-readable evidence, including per-step findings and operational errors. |
| `connectivity` | Connectivity-only verdict, success, successful formats, and sanitized probe records. No client object or request credentials are serialized. |

Audit `coverage` contains:

- `skipped_steps`: optional steps omitted by flags or the selected profile.
- `risk_matrix_inconclusive_steps`: Steps 3, 5, 8, 9, 10, or 11 whose
  inconclusive state enters the existing risk matrix. This list does not
  classify every informational probe; inspect `flags` and `markdown` too.
- `crashed_steps`: all steps caught by the existing continuation wrapper.

For example, weak prompt-related wording in Step 4 remains `INCONCLUSIVE`
in `flags` and `markdown`; it is not confirmed prompt extraction and does
not enter the existing six-dimension rating. Read the evidence alongside
`risk_level`, including when the final rating is `LOW`.

Skipped probes are not evidence of clean behavior. A connectivity check has
`risk_level: null` even when both chat formats respond successfully; its exit
code remains 0 for connectivity success and 1 for failure.

This is a direct run-report schema, separate from the dashboard schema
produced by `scripts/extract-data.py`. Both formats are local reports and may
contain private relay URLs, model responses, or other sensitive evidence.
Review and redact them before sharing.

The JSON output concept was proposed in
[@ythx-101's PR #2](https://github.com/toby-bridges/api-relay-audit/pull/2),
at revision `495e910be9bc14bef15d651a02f4fd7d5d57159c` (MIT snapshot).
This implementation is independently written against the current upstream
architecture and retains the existing rating rules and AGPL-3.0-only license.
