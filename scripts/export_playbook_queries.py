#!/usr/bin/env python3
"""
scripts/export_playbook_queries.py
----------------------------------
Export every socai playbook query into a single, neatly-formatted Markdown
reference for human consumption.

Reads straight from the source-of-truth query files so the output never drifts
from what the tools actually run:

  1. Multi-stage v2 investigation playbooks
     config/playbooks/<id>.yaml      (stage metadata)
     config/playbooks/<id>/sentinel/<stage>.kql   (Microsoft Sentinel / KQL)
     config/playbooks/<id>/logscale/<stage>.cql   (CrowdStrike NG-SIEM / CQL)

  2. Composite single-shot Sentinel scenarios
     config/kql_playbooks/sentinel/<id>.kql

Usage:
    python3 scripts/export_playbook_queries.py            # writes docs/playbook-queries.md
    python3 scripts/export_playbook_queries.py --out FILE # custom output path
    python3 scripts/export_playbook_queries.py --stdout   # print to stdout

Run from the repo root.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.sentinel_queries import list_scenarios, load_scenario  # noqa: E402
from tools.playbooks import _resolve_query_body  # reuse the real resolver  # noqa: E402
from tools.platforms import Platform, get_platform, list_platforms  # noqa: E402

PLAYBOOKS_DIR = REPO_ROOT / "config" / "playbooks"

# Generated as a static snapshot — the timestamp is intentionally omitted so
# re-running on an unchanged tree produces an identical file (clean git diffs).


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_platforms() -> list[Platform]:
    """Return the Platform adapters, Sentinel first then the rest (analyst order)."""
    platforms = [get_platform(p["id"]) for p in list_platforms()]
    platforms = [p for p in platforms if p is not None]
    platforms.sort(key=lambda p: (p.id != "sentinel", p.id))
    return platforms


_FENCES = {"kql": "kql", "cql": "cql"}


def _fence(platform: Platform) -> str:
    return _FENCES.get(platform.query_file_ext, "")


def _clean(text: str | None) -> str:
    """Collapse YAML multi-line / folded scalars into a single tidy paragraph."""
    if not text:
        return ""
    return " ".join(str(text).split())


def _read_query(playbook_id: str, stage: dict, platform: Platform) -> str | None:
    """Resolve a stage's query body for *platform* via the real loader.

    Delegates to tools.playbooks._resolve_query_body so this export honours the
    same query_file rules the running tool does — string stems, per-platform
    dict overrides, and the descriptive-filename glob fallback.
    """
    body = _resolve_query_body(playbook_id, stage, platform)
    return body.strip() if body else None


def _slug(heading_text: str) -> str:
    """Replicate GitHub's heading-anchor algorithm (github-slugger).

    Lowercase, strip every character that is not a word char / whitespace /
    hyphen, then map spaces to hyphens. Crucially it does NOT collapse runs of
    hyphens — "A & B" becomes "a--b" — so the TOC links match the anchors a
    GitHub-flavoured renderer derives from the headings verbatim.
    """
    s = heading_text.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)   # \w keeps underscores + unicode letters
    return s.replace(" ", "-")


def _toc_entry(heading_text: str) -> str:
    """A bullet linking to *heading_text*'s own anchor."""
    return f"- [{heading_text}](#{_slug(heading_text)})"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render() -> str:
    platforms = _load_platforms()
    lines: list[str] = []
    w = lines.append

    w("# socai — Playbook Query Reference")
    w("")
    w("A complete, human-readable export of every investigation query shipped with socai. "
      "Each query is reproduced verbatim from its source file; `{{placeholder}}` tokens are "
      "the parameters you substitute at run time (the tools do this for you via "
      "`render_stage_for_platform` / `generate_sentinel_query`).")
    w("")
    w("This file is **generated** — do not hand-edit. Regenerate with:")
    w("")
    w("```bash")
    w("python3 scripts/export_playbook_queries.py")
    w("```")
    w("")
    w("Two query families are covered:")
    w("")
    w("- **Part 1 — Multi-stage investigation playbooks** (`config/playbooks/`): "
      "vendor-agnostic stages, each with a per-platform query body. Platforms exported here: "
      + ", ".join(f"**{p.name}**" for p in platforms) + ".")
    w("- **Part 2 — Composite single-shot Sentinel scenarios** (`config/kql_playbooks/sentinel/`): "
      "monolithic KQL queries that return a full investigation picture in one execution.")
    w("")

    playbook_files = sorted(PLAYBOOKS_DIR.glob("*.yaml"))
    scenarios = list_scenarios()

    # ---- Table of contents -------------------------------------------------
    w("## Contents")
    w("")
    w("**Part 1 — Multi-stage investigation playbooks**")
    w("")
    for path in playbook_files:
        data = yaml.safe_load(path.read_text()) or {}
        name = data.get("name", data.get("id", path.stem))
        pid = data.get("id", path.stem)
        w(_toc_entry(f"{name} (`{pid}`)"))
    w("")
    w("**Part 2 — Composite single-shot Sentinel scenarios**")
    w("")
    for sc in scenarios:
        w(_toc_entry(f"{sc['name']} (`{sc['id']}`)"))
    w("")
    w("---")
    w("")

    # ---- Part 1 ------------------------------------------------------------
    w("# Part 1 — Multi-stage investigation playbooks")
    w("")
    for path in playbook_files:
        data = yaml.safe_load(path.read_text()) or {}
        pid = data.get("id", path.stem)
        name = data.get("name", pid)
        w(f"## {name} (`{pid}`)")
        w("")
        desc = _clean(data.get("description"))
        if desc:
            w(desc)
            w("")

        params = data.get("parameters") or []
        if params:
            w("**Parameters**")
            w("")
            w("| Name | Type | Default | Description |")
            w("| --- | --- | --- | --- |")
            for p in params:
                w("| `{}` | {} | {} | {} |".format(
                    p.get("name", ""),
                    p.get("type", ""),
                    f"`{p['default']}`" if p.get("default") not in (None, "") else "—",
                    _clean(p.get("description")),
                ))
            w("")

        stages = sorted(data.get("stages") or [], key=lambda s: s.get("id", 0))
        for st in stages:
            sid = st.get("id")
            sname = st.get("name", "")
            w(f"### Stage {sid} — {sname}")
            w("")
            run = _clean(st.get("run"))
            sdesc = _clean(st.get("description"))
            if run:
                w(f"- **Run:** {run}")
            if sdesc and sdesc.lower() != "see query block.":
                w(f"- **Purpose:** {sdesc}")
            if run or (sdesc and sdesc.lower() != "see query block."):
                w("")

            for plat in platforms:
                body = _read_query(pid, st, plat)
                w(f"**{plat.name}**")
                w("")
                if body:
                    w(f"```{_fence(plat)}")
                    w(body)
                    w("```")
                else:
                    w(f"_No {plat.name} query for this stage._")
                w("")

        defs = data.get("definitions") or []
        glossary = [d for d in defs
                    if _clean(d.get("definition")) and _clean(d.get("definition")) != ">"]
        if glossary:
            w("**Definitions**")
            w("")
            for d in glossary:
                w(f"- **{d.get('term', '')}** — {_clean(d.get('definition'))}")
            w("")

        w("---")
        w("")

    # ---- Part 2 ------------------------------------------------------------
    w("# Part 2 — Composite single-shot Sentinel scenarios")
    w("")
    w("These are monolithic KQL queries (multiple `let` sections unioned together) that "
      "produce a full-picture result in a single execution. A missing section number in the "
      "output means zero results for that section.")
    w("")
    for sc in scenarios:
        scenario = load_scenario(sc["id"])
        if not scenario:
            continue
        w(f"## {scenario['name']} (`{scenario['id']}`)")
        w("")
        desc = _clean(scenario.get("description"))
        if desc:
            w(desc)
            w("")

        params = scenario.get("parameters") or []
        if params:
            w("**Parameters**")
            w("")
            w("| Name | Required | Description |")
            w("| --- | --- | --- |")
            for p in params:
                w("| `{}` | {} | {} |".format(
                    p.get("name", ""),
                    "yes" if p.get("required") else "no",
                    _clean(p.get("description")),
                ))
            w("")

        tables = scenario.get("tables") or []
        if tables:
            w("**Tables:** " + ", ".join(f"`{t}`" for t in tables))
            w("")

        body = (scenario.get("query_template") or "").strip()
        w("```kql")
        w(body if body else "// (empty)")
        w("```")
        w("")
        w("---")
        w("")

    # ---- Footer ------------------------------------------------------------
    w(f"_Exported {len(playbook_files)} multi-stage playbooks and {len(scenarios)} "
      f"composite scenarios from `config/`._")
    w("")

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(REPO_ROOT / "docs" / "playbook-queries.md"),
                    help="Output path (default: docs/playbook-queries.md)")
    ap.add_argument("--stdout", action="store_true", help="Print to stdout instead of writing")
    args = ap.parse_args()

    content = render()

    if args.stdout:
        print(content)
        return 0

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")
    print(f"Wrote {out_path} ({len(content):,} chars)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
