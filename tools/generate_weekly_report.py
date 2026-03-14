"""
tool: generate_weekly_report
----------------------------
Rolls up all closed cases from the registry that fall within the
specified ISO week and produces a summary Markdown report.

Writes:
  reports/weekly/weekly_<YYYY>_W<WW>.md
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, REGISTRY_FILE, WEEKLY_REPORTS
from tools.common import load_json, log_error, utcnow, write_artefact, write_report


def _week_bounds(year: int, week: int) -> tuple[datetime, datetime]:
    """Return (Monday 00:00 UTC, Sunday 23:59:59 UTC) for ISO year/week."""
    monday = datetime.fromisocalendar(year, week, 1).replace(
        hour=0, minute=0, second=0, tzinfo=timezone.utc
    )
    sunday = monday + timedelta(days=6, hours=23, minutes=59, seconds=59)
    return monday, sunday


def _parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _load_iocs_for_case(case_dir: Path) -> dict:
    iocs_path = Path(case_dir) / "iocs" / "iocs.json"
    if iocs_path.exists():
        try:
            return load_json(iocs_path).get("total", {})
        except Exception as exc:
            log_error("", "generate_weekly_report.load_iocs", str(exc),
                      severity="warning", context={"path": str(iocs_path)})
    return {}


def _severity_badge(severity: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
        severity.lower(), "⚪"
    )


def generate_weekly_report(
    year: int | None = None,
    week: int | None = None,
    include_open: bool = False,
) -> dict:
    """
    Generate a weekly rollup report.
    If year/week not specified, uses the current ISO week.
    """
    now = datetime.now(timezone.utc)
    if year is None:
        year = now.isocalendar().year
    if week is None:
        week = now.isocalendar().week

    week_start, week_end = _week_bounds(year, week)
    week_label = f"{year}_W{week:02d}"

    WEEKLY_REPORTS.mkdir(parents=True, exist_ok=True)

    if not REGISTRY_FILE.exists():
        return {"error": "Registry not found", "path": str(REGISTRY_FILE)}

    registry = load_json(REGISTRY_FILE)
    all_cases = registry.get("cases", {})

    # Filter cases
    included: list[dict] = []
    skipped: list[str]   = []
    for cid, cdata in all_cases.items():
        status    = cdata.get("status", "open")
        updated   = _parse_ts(cdata.get("updated_at", ""))
        if not include_open and status not in ("closed", "archived"):
            skipped.append(cid)
            continue
        if updated and not (week_start <= updated <= week_end):
            skipped.append(cid)
            continue
        included.append({"case_id": cid, **cdata})

    # Aggregate stats
    total_iocs: dict[str, int] = {}
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for c in included:
        sev = c.get("severity", "medium").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        ioc_totals = c.get("ioc_totals") or _load_iocs_for_case(c.get("case_dir", ""))
        for k, v in ioc_totals.items():
            total_iocs[k] = total_iocs.get(k, 0) + int(v)

    # Build report
    lines: list[str] = []
    lines.append(f"# Weekly SOC Summary – {year} Week {week:02d}")
    lines.append(f"\n_Period: {week_start.strftime('%Y-%m-%d')} to {week_end.strftime('%Y-%m-%d')} UTC_")
    lines.append(f"\n_Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}_\n")

    # Headline stats
    lines.append("## Headline Statistics\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Cases in this report | {len(included)} |")
    lines.append(f"| Critical | {sev_counts.get('critical', 0)} |")
    lines.append(f"| High | {sev_counts.get('high', 0)} |")
    lines.append(f"| Medium | {sev_counts.get('medium', 0)} |")
    lines.append(f"| Low | {sev_counts.get('low', 0)} |")
    for k, v in sorted(total_iocs.items()):
        if v:
            lines.append(f"| Total {k.upper()} IOCs | {v} |")
    lines.append("")

    # Case summaries
    lines.append("## Case Summaries\n")
    if not included:
        lines.append("_No qualifying cases found for this week._\n")
    for c in sorted(included, key=lambda x: x.get("severity", "medium")):
        cid      = c["case_id"]
        title    = c.get("title", cid)
        sev      = c.get("severity", "medium")
        status   = c.get("status", "?")
        badge    = _severity_badge(sev)
        rpath    = c.get("report_path", "N/A")
        updated  = c.get("updated_at", "?")
        lines.append(f"### {badge} {cid} – {title}\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Severity | {sev.upper()} |")
        lines.append(f"| Status | {status} |")
        lines.append(f"| Last Updated | {updated} |")
        lines.append(f"| Report | `{rpath}` |")
        ioc_t = c.get("ioc_totals") or {}
        ioc_parts = [f"{v} {k}" for k, v in ioc_t.items() if int(v) > 0]
        lines.append(f"| IOCs | {', '.join(ioc_parts) or 'none extracted'} |")
        lines.append("")

    # Trend notes (basic)
    lines.append("## Analyst Notes\n")
    lines.append("_Add analyst commentary and trend observations here._\n")
    lines.append("### Recurring IOC Themes\n")
    lines.append("_Cross-case IOC overlap analysis not yet implemented – review iocs.json files manually._\n")
    lines.append("### Recommended Actions for Next Week\n")
    lines.append("- Review any cases still in OPEN status.\n")
    lines.append("- Populate enrichment API keys to improve IOC coverage.\n")
    lines.append("- Ensure all CRITICAL cases have been escalated or formally closed.\n")

    report_text = "\n".join(lines)
    report_path = WEEKLY_REPORTS / f"weekly_{week_label}.md"
    write_report(report_path, report_text, title=f"Weekly Report — {week_label}")
    print(f"[generate_weekly_report] Report written to {report_path} "
          f"({len(included)} case(s))")
    return {
        "report_path": str(report_path),
        "week_label":  week_label,
        "cases_included": len(included),
        "cases_skipped":  len(skipped),
        "ts": utcnow(),
    }


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Generate weekly SOC rollup report.")
    p.add_argument("--year",  type=int, default=None)
    p.add_argument("--week",  type=int, default=None)
    p.add_argument("--include-open", action="store_true",
                   help="Include open cases (not just closed/archived).")
    args = p.parse_args()

    result = generate_weekly_report(args.year, args.week, args.include_open)
    print(json.dumps(result, indent=2))
