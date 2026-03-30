# API Relay Audit

## Overview
Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override, and context truncation.

## Tech Stack
- Python 3.7+ with httpx
- Single-page HTML dashboard (vanilla JS)
- Docker (nginx) for deployment

## Project Structure
```
api_relay_audit/         # Shared Python modules
  client.py              # API client (Anthropic + OpenAI + curl fallback)
  reporter.py            # Markdown report generator
scripts/
  audit.py               # Main 7-step audit CLI
  context-test.py        # Standalone context length test
  extract-data.py        # Extract structured data from reports
web/                     # Dashboard
deploy/                  # NAS deployment script
```

## Key Commands
```bash
# Run full audit
python scripts/audit.py --key <KEY> --url <BASE_URL> --model claude-opus-4-6

# Context length test only
python scripts/context-test.py --key <KEY> --url <BASE_URL>

# Extract report data
python scripts/extract-data.py --reports-dir ./reports --output data.json
```

## Development Notes
- All API calls go through `api_relay_audit.client.APIClient`
- Supports both Anthropic native and OpenAI-compatible formats (auto-detect)
- Falls back to curl when Python SSL fails
