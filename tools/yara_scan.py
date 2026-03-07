"""
tool: yara_scan
---------------
YARA scanning tool for case artefacts.

Scans extracted files, email attachments, and web captures against built-in
and external YARA rules. Optionally generates custom YARA rules via LLM
based on PE analysis and enrichment verdicts.

yara-python is optional — if not installed, returns status "yara_not_installed".

Output:
  cases/<case_id>/artefacts/yara/yara_results.json
  cases/<case_id>/artefacts/yara/generated_rules.yar  (when generate_rules=True)

Usage (standalone):
  python3 tools/yara_scan.py --case C001
  python3 tools/yara_scan.py --case C001 --generate-rules
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR
from tools.common import get_model, load_json, log_error, save_json, utcnow, write_artefact

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

# ---------------------------------------------------------------------------
# Built-in YARA rules
# ---------------------------------------------------------------------------

_BUILTIN_SOURCE = r"""
rule SuspiciousPE {
    meta:
        description = "PE with suspicious characteristics"
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
        $upx0 = "UPX0"
        $upx1 = "UPX1"
    condition:
        $mz at 0 and $pe and ($upx0 or $upx1)
}

rule PowerShellObfuscation {
    meta:
        description = "Obfuscated PowerShell patterns"
    strings:
        $enc1 = "FromBase64String" nocase
        $enc2 = "-EncodedCommand" nocase
        $enc3 = "[Convert]::" nocase
        $iex1 = "Invoke-Expression" nocase
        $iex2 = "IEX" fullword
        $bypass = "-ExecutionPolicy Bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $download = "DownloadString" nocase
        $webclient = "Net.WebClient" nocase
    condition:
        2 of them
}

rule C2Patterns {
    meta:
        description = "Common C2 communication patterns"
    strings:
        $ua1 = "Mozilla/5.0"
        $beacon = /sleep\s*\(\s*\d{4,}\s*\)/
        $b64pe = "TVqQAA"
        $shell1 = "cmd.exe /c"
        $shell2 = "powershell.exe -"
        $pipe = "\\\\.\\pipe\\"
    condition:
        3 of them
}

rule Base64PEHeader {
    meta:
        description = "Base64-encoded PE header"
    strings:
        $b64mz1 = "TVpTAQ"
        $b64mz2 = "TVqQAA"
        $b64mz3 = "TVpQAA"
        $b64mz4 = "TVoAAAA"
    condition:
        any of them
}

rule CommonRATStrings {
    meta:
        description = "Strings common in Remote Access Trojans"
    strings:
        $s1 = "keylogger" nocase
        $s2 = "screenshot" nocase
        $s3 = "webcam" nocase
        $s4 = "reverse_shell" nocase
        $s5 = "bind_shell" nocase
        $s6 = "file_manager" nocase
        $s7 = "persistence" nocase
        $s8 = "privilege_escalation" nocase
    condition:
        3 of them
}
"""

# ---------------------------------------------------------------------------
# External rule directory
# ---------------------------------------------------------------------------

_EXTERNAL_RULES_DIR = Path(__file__).resolve().parent.parent / "config" / "yara_rules"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_printable(data: bytes) -> bool:
    """Return True if bytes are printable ASCII."""
    try:
        data.decode("ascii")
        return True
    except (UnicodeDecodeError, ValueError):
        return False


def _format_match_strings(match) -> list[dict]:
    """Convert YARA match string tuples to serialisable dicts."""
    results = []
    for offset, identifier, data in match.strings:
        if _is_printable(data):
            data_repr = data.decode("ascii")
        else:
            data_repr = data.hex()
        results.append({
            "offset": offset,
            "identifier": identifier,
            "data": data_repr,
        })
    return results


def _collect_scan_targets(case_id: str) -> list[Path]:
    """Collect all files to scan under the case directory."""
    case_dir = Path(CASES_DIR) / case_id
    targets: list[Path] = []

    # Extracted ZIP contents
    zip_dir = case_dir / "artefacts" / "zip"
    if zip_dir.is_dir():
        for p in zip_dir.rglob("*"):
            if p.is_file():
                targets.append(p)

    # Email attachments
    att_dir = case_dir / "artefacts" / "email" / "attachments"
    if att_dir.is_dir():
        for p in att_dir.rglob("*"):
            if p.is_file():
                targets.append(p)

    # Web capture HTML files
    web_dir = case_dir / "artefacts" / "web"
    if web_dir.is_dir():
        for p in web_dir.glob("*/page.html"):
            if p.is_file():
                targets.append(p)

    return targets


def _compile_builtin_rules():
    """Compile built-in YARA rules from embedded source."""
    return yara.compile(source=_BUILTIN_SOURCE)


def _compile_external_rules() -> tuple[list, int]:
    """
    Compile external .yar/.yara files from config/yara_rules/.
    Returns (list of compiled rule objects, count loaded).
    """
    compiled = []
    if not _EXTERNAL_RULES_DIR.is_dir():
        return compiled, 0

    rule_files = list(_EXTERNAL_RULES_DIR.glob("*.yar")) + list(
        _EXTERNAL_RULES_DIR.glob("*.yara")
    )
    for rf in rule_files:
        try:
            rules = yara.compile(filepath=str(rf))
            compiled.append(rules)
        except yara.SyntaxError as exc:
            log_error(
                case_id="",
                step="yara_scan",
                error=f"Syntax error in {rf.name}: {exc}",
                severity="warning",
            )
    return compiled, len(rule_files)


def _scan_with_rules(rules, targets: list[Path], case_dir: Path) -> list[dict]:
    """Run a compiled YARA ruleset against all targets, returning match dicts."""
    matches: list[dict] = []
    for path in targets:
        try:
            hits = rules.match(filepath=str(path))
        except Exception as exc:
            log_error(
                case_id="",
                step="yara_scan",
                error=f"Error scanning {path.name}: {exc}",
                severity="warning",
            )
            continue
        for hit in hits:
            try:
                rel = str(path.relative_to(case_dir))
            except ValueError:
                rel = str(path)
            matches.append({
                "file": rel,
                "rule": hit.rule,
                "tags": list(hit.tags),
                "meta": dict(hit.meta),
                "strings": _format_match_strings(hit),
            })
    return matches


# ---------------------------------------------------------------------------
# LLM rule generation
# ---------------------------------------------------------------------------

_RULE_GEN_SYSTEM = """You are an expert YARA rule author for malware detection.
Given PE analysis data and threat intelligence verdicts, write well-formed YARA
rules that target the specific threat characteristics observed.

Guidelines:
- Each rule must have a meta section with description and author="socai-generated"
- Use meaningful rule names prefixed with "Generated_"
- Include both string-based and structural conditions where applicable
- Target specific imports, section names, or byte patterns from the PE analysis
- Incorporate known-bad IOCs (domains, IPs) as string matches where relevant
- Output ONLY valid YARA source code, no markdown fences or commentary
"""


def _generate_rules_llm(case_id: str) -> str | None:
    """Use Claude to generate custom YARA rules from case artefacts."""
    import anthropic

    if not ANTHROPIC_KEY:
        return None

    case_dir = Path(CASES_DIR) / case_id

    # Gather context for LLM
    context_parts: list[str] = []

    pe_analysis = load_json(case_dir / "artefacts" / "analysis" / "pe_analysis.json")
    if pe_analysis:
        context_parts.append(f"PE Analysis:\n{_safe_json_str(pe_analysis)}")

    verdict_summary = load_json(
        case_dir / "artefacts" / "enrichment" / "verdict_summary.json"
    )
    if verdict_summary:
        # Extract malicious and suspicious IOC values
        mal_iocs = verdict_summary.get("high_priority", [])
        sus_iocs = verdict_summary.get("needs_review", [])
        if mal_iocs or sus_iocs:
            context_parts.append(
                f"Malicious IOCs:\n{_safe_json_str(mal_iocs)}\n"
                f"Suspicious IOCs:\n{_safe_json_str(sus_iocs)}"
            )

    if not context_parts:
        return None

    user_msg = (
        "Based on the following analysis data, generate YARA rules to detect "
        "this specific threat.\n\n" + "\n\n".join(context_parts)
    )

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        try:
            _meta = load_json(CASES_DIR / case_id / "case_meta.json")
        except Exception:
            _meta = {}
        resp = client.messages.create(
            model=get_model("yara", _meta.get("severity", "medium")),
            max_tokens=4096,
            system=[
                {
                    "type": "text",
                    "text": _RULE_GEN_SYSTEM,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_msg}],
        )
        for block in resp.content:
            if block.type == "text":
                return block.text
    except Exception as exc:
        log_error(
            case_id=case_id,
            step="yara_scan_generate",
            error=str(exc),
            severity="warning",
        )
    return None


def _safe_json_str(obj) -> str:
    """JSON-serialise with truncation for LLM context."""
    import json

    text = json.dumps(obj, indent=2, default=str)
    if len(text) > 8000:
        text = text[:8000] + "\n... (truncated)"
    return text


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def yara_scan(case_id: str, generate_rules: bool = False) -> dict:
    """
    Scan case artefacts with YARA rules.

    Parameters
    ----------
    case_id : str
        Case identifier.
    generate_rules : bool
        If True, use LLM to generate custom rules from PE analysis / verdicts.

    Returns
    -------
    dict
        Manifest with matches, rule counts, and scan statistics.
    """
    if not HAS_YARA:
        return {"status": "yara_not_installed"}

    case_dir = Path(CASES_DIR) / case_id
    yara_dir = case_dir / "artefacts" / "yara"
    all_matches: list[dict] = []
    rules_loaded = {"builtin": 5, "external": 0, "generated": 0}
    generated_rules_path: str | None = None

    # -- Compile built-in rules --
    try:
        builtin_rules = _compile_builtin_rules()
    except Exception as exc:
        log_error(case_id=case_id, step="yara_scan", error=f"Built-in compile: {exc}", severity="error")
        return {"status": "error", "error": str(exc)}

    # -- Compile external rules --
    try:
        ext_compiled, ext_count = _compile_external_rules()
        rules_loaded["external"] = ext_count
    except Exception as exc:
        log_error(case_id=case_id, step="yara_scan", error=f"External compile: {exc}", severity="warning")
        ext_compiled = []

    # -- Collect scan targets --
    targets = _collect_scan_targets(case_id)

    # -- Initial scan with built-in + external rules --
    all_matches.extend(_scan_with_rules(builtin_rules, targets, case_dir))
    for ext_rules in ext_compiled:
        all_matches.extend(_scan_with_rules(ext_rules, targets, case_dir))

    # -- LLM rule generation --
    if generate_rules:
        gen_source = _generate_rules_llm(case_id)
        if gen_source:
            # Save generated rules
            gen_path = yara_dir / "generated_rules.yar"
            write_artefact(gen_path, gen_source)
            generated_rules_path = str(gen_path)

            # Compile and scan with generated rules
            try:
                gen_compiled = yara.compile(source=gen_source)
                gen_rule_count = len(gen_compiled)
                rules_loaded["generated"] = gen_rule_count
                all_matches.extend(_scan_with_rules(gen_compiled, targets, case_dir))
            except yara.SyntaxError as exc:
                log_error(
                    case_id=case_id,
                    step="yara_scan_generate",
                    error=f"Generated rules syntax error: {exc}",
                    severity="warning",
                )
            except Exception as exc:
                log_error(
                    case_id=case_id,
                    step="yara_scan_generate",
                    error=str(exc),
                    severity="warning",
                )

    # -- Build manifest --
    manifest = {
        "status": "ok",
        "matches": all_matches,
        "rules_loaded": rules_loaded,
        "files_scanned": len(targets),
        "total_matches": len(all_matches),
        "generated_rules_path": generated_rules_path,
    }

    save_json(yara_dir / "yara_results.json", manifest)
    return manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(description="YARA scan case artefacts.")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--generate-rules", action="store_true", default=False)
    args = p.parse_args()

    result = yara_scan(args.case_id, generate_rules=args.generate_rules)
    print(json.dumps(result, indent=2))
