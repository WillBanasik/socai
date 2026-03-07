# SOC-AI Quick Cheat Sheet

## Setup
```bash
pip install -r requirements.txt
playwright install chromium          # optional; falls back to requests
cp .env.example .env                 # add your API keys
```

## Core Workflow

| What | Command |
|------|---------|
| **Full investigation** | `python3 socai.py investigate --case C001 --title "Phishing lure" --severity high --url "https://evil.com" --logs ./logs --zip sample.zip --zip-pass infected` |
| **List cases** | `python3 socai.py list` |
| **Close a case** | `python3 socai.py close --case C001` |

## Re-run Individual Stages
```bash
python3 socai.py report  --case C001       # regenerate report
python3 socai.py enrich  --case C001       # re-enrich IOCs (tiered for IPv4: ASN→fast→deep)
python3 socai.py secarch --case C001       # security architecture review
python3 socai.py queries --case C001 --platforms kql \
    --tables DeviceNetworkEvents SecurityEvent
```

## Run Tools Directly
```bash
python3 tools/web_capture.py "https://example.com" --case C001
python3 tools/extract_iocs.py --case C001
python3 tools/score_verdicts.py --case C001
python3 tools/generate_report.py --case C001
python3 tools/generate_pptx.py --case C001
```

## Ad-hoc LLM Query (no case created)
```bash
python3 socai.py client-query \
    --prompt "Was folder 2026 created on SERVER01?" \
    --platforms kql --tables DeviceFileEvents DeviceEvents
```

## Weekly Rollup
```bash
python3 socai.py weekly --year 2026 --week 08 --include-open
```

## Key Env Vars
| Variable | What it does |
|----------|-------------|
| `SOCAI_BROWSER` | `playwright` (default) or `requests` |
| `SOCAI_LLM_MODEL` | Claude model for LLM steps (default `claude-sonnet-4-6`) |
| `SOCAI_ENRICH_CACHE_TTL` | Cache TTL in hours (default 24, 0 = off) |
| `ANTHROPIC_API_KEY` | Required for LLM steps |

## Enrichment API Keys (set in `.env`)
`SOCAI_VT_KEY` (VirusTotal), `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `GREYNOISE_API_KEY`, `INTEZER_API_KEY`, `URLSCAN_API_KEY`, `PROXYCHECK_API_KEY`, `OPENCTI_API_KEY`

## Where Things Live
| Path | Contents |
|------|----------|
| `cases/<ID>/reports/` | Investigation report (Markdown) |
| `cases/<ID>/iocs/iocs.json` | Extracted IOCs |
| `cases/<ID>/artefacts/` | Web captures, enrichment, analysis |
| `registry/case_index.json` | Master case registry |
| `registry/ioc_index.json` | Cross-case IOC index |
| `registry/audit.log` | Append-only audit trail (JSONL) |

## Testing
```bash
python3 -m pytest tests/ -v                                    # all tests
python3 -m pytest tests/test_tools.py::test_extract_iocs_from_text -v  # single test
```

## Tips
- All commands must be run from the **repo root**
- Re-running `investigate` is safe — it skips already-completed steps
- A failing pipeline step doesn't abort the rest
- Use `SOCAI_BROWSER=requests` to skip Playwright entirely
