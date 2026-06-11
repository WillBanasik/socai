"""Regression tests for the 2026-06 bug-sweep P2/P3 fixes (Batch A).

Each test pins one fix from the sweep worklist:
  - msi_analyse.decode_msi_name: canonical 3-range decode (table marker +
    single-char ranges were dead branches; two-char unpack was corrupted).
  - office_analyse._dde_links: plain DDE fields match, not just DDEAUTO.
  - extract_iocs: defanged input is refanged before extraction; .eu/.me TLDs
    extract (proofpoint-simulations.eu was silently dropped).
  - correlate._domain_in_value: hostname-boundary matching (t.co must not
    match inside microsoft.com).
  - timeline_reconstruct._sort_key: RFC2822 email dates interleave correctly
    with ISO timestamps instead of sorting to the end.
  - sentinel_queries.render_query: caller values are escaped before KQL
    substitution.
  - audit_user: the max_events cap keeps the NEWEST events.
  - campaign_cluster: shared IOCs carry first_seen timestamps (campaign
    first_seen was previously a min() over case IDs).
  - eql import_* id guards: traversal-shaped ids are rejected.
  - crowdstrike._send_with_auth_retry: one fresh-token retry on 401.
"""
from __future__ import annotations

import json
import zipfile

import pytest


# ---------------------------------------------------------------------------
# MSI stream-name decode
# ---------------------------------------------------------------------------

def _msi_encode(s: str) -> str:
    from tools.msi_analyse import _MSI_TABLE
    out, i = [], 0
    while i < len(s):
        a = _MSI_TABLE.index(s[i])
        if i + 1 < len(s):
            out.append(chr(0x3800 + (_MSI_TABLE.index(s[i + 1]) << 6 | a)))
            i += 2
        else:
            out.append(chr(0x4800 + a))
            i += 1
    return "".join(out)


def test_msi_decode_table_marker_and_ranges():
    from tools.msi_analyse import decode_msi_name
    # Table marker (0x4840) + two-char range — the !CustomAction table is
    # exactly what the LOLBin detection keys on.
    assert decode_msi_name(chr(0x4840) + _msi_encode("CustomAction")) == "!CustomAction"
    # Odd-length name ends in the single-char range (0x4800-0x483F).
    assert decode_msi_name(_msi_encode("ABC")) == "ABC"
    assert decode_msi_name(_msi_encode("Binary")) == "Binary"
    # Unmangled names pass through untouched.
    assert decode_msi_name("SummaryInformation") == "SummaryInformation"


# ---------------------------------------------------------------------------
# Office DDE field detection
# ---------------------------------------------------------------------------

def test_dde_links_matches_plain_dde(tmp_path):
    from tools.office_analyse import _dde_links
    docx = tmp_path / "t.docx"
    with zipfile.ZipFile(docx, "w") as zf:
        zf.writestr("word/document.xml",
                    '<w:instrText>DDE cmd /c calc.exe</w:instrText>')
    hits = _dde_links(docx)
    assert hits and hits[0].startswith("DDE cmd")


# ---------------------------------------------------------------------------
# IOC extraction: refang + TLD coverage
# ---------------------------------------------------------------------------

def test_extract_iocs_refangs_defanged_input():
    from tools.extract_iocs import _extract_from_text
    r = _extract_from_text(
        "Phish: hxxps://proofpoint-simulations[.]eu/track "
        "C2 185[.]220[.]101[.]45 sender bad[@]evil[.]me"
    )
    assert "https://proofpoint-simulations.eu/track" in r["url"]
    assert "proofpoint-simulations.eu" in r["domain"]
    assert "185.220.101.45" in r["ipv4"]
    assert "bad@evil.me" in r["email"]


# ---------------------------------------------------------------------------
# Correlation domain matching
# ---------------------------------------------------------------------------

def test_correlate_domain_boundary_matching():
    from tools.correlate import _domain_in_value
    assert not _domain_in_value("t.co", "microsoft.com")
    assert _domain_in_value("t.co", "https://t.co/abc")
    assert _domain_in_value("evil.com", "sub.evil.com")          # subdomain ok
    assert not _domain_in_value("evil.com", "evil.com.attacker.net")
    assert _domain_in_value("evil.com", "user@evil.com")


# ---------------------------------------------------------------------------
# Timeline chronological sort over mixed formats
# ---------------------------------------------------------------------------

def test_timeline_sort_mixed_rfc2822_and_iso():
    from tools.timeline_reconstruct import _sort_key
    events = [
        {"timestamp": "2026-06-01T10:00:00Z"},
        {"timestamp": "Mon, 01 Jun 2026 08:00:00 +0000"},  # earlier, RFC2822
        {"timestamp": "not-a-date"},
    ]
    ordered = sorted(events, key=_sort_key)
    assert ordered[0]["timestamp"].startswith("Mon")   # email anchors first
    assert ordered[-1]["timestamp"] == "not-a-date"    # unparseable sorts last


# ---------------------------------------------------------------------------
# Sentinel composite query parameter escaping
# ---------------------------------------------------------------------------

def test_render_query_escapes_quotes():
    from tools.sentinel_queries import list_scenarios, render_query
    scenarios = list_scenarios()
    if not scenarios:
        pytest.skip("no sentinel scenarios on disk")
    r = render_query(scenarios[0]["id"], upn='x" | take 999 //')
    assert "error" not in r
    # The raw breakout sequence must not survive into the rendered KQL.
    assert 'x" | take 999' not in r["query"]
    assert 'x\\"' in r["query"]


def test_render_query_rejects_control_characters():
    from tools.sentinel_queries import list_scenarios, render_query
    scenarios = list_scenarios()
    if not scenarios:
        pytest.skip("no sentinel scenarios on disk")
    r = render_query(scenarios[0]["id"], upn="a@b.com\nSigninLogs | take 1")
    assert "error" in r


# ---------------------------------------------------------------------------
# audit_user keeps the newest events under the cap
# ---------------------------------------------------------------------------

def test_audit_user_cap_keeps_newest(tmp_path, monkeypatch):
    import tools.audit_user as au
    log = tmp_path / "mcp_server.jsonl"
    lines = []
    for i in range(10):
        lines.append(json.dumps({
            "event": "tool_result", "caller": "a@b.c", "tool": f"tool_{i}",
            "ts": f"2026-06-01T00:00:{i:02d}Z", "duration_ms": 1,
        }))
    log.write_text("\n".join(lines) + "\n")
    monkeypatch.setattr(au, "MCP_SERVER_LOG", log)

    result = au.audit_user(max_events=3)
    tools_seen = {e["tool"] for e in result["timeline"]}
    # The cap must retain the newest 3 events, not the oldest.
    assert tools_seen == {"tool_7", "tool_8", "tool_9"}
    assert result["_meta"]["truncated"] is True


# ---------------------------------------------------------------------------
# campaign_cluster first_seen is a timestamp
# ---------------------------------------------------------------------------

def test_shared_iocs_carry_first_seen():
    from tools.campaign_cluster import _extract_shared_iocs
    index = {
        "evil-domain.info": {
            "ioc_type": "domain", "verdict": "malicious", "confidence": "HIGH",
            "cases": ["IV_CASE_900", "IV_CASE_901"],
            "first_seen": "2026-05-01T09:00:00Z",
        },
    }
    shared = _extract_shared_iocs(index, frozenset({"IV_CASE_900", "IV_CASE_901"}))
    assert shared and shared[0]["first_seen"] == "2026-05-01T09:00:00Z"


# ---------------------------------------------------------------------------
# EQL import id traversal guards
# ---------------------------------------------------------------------------

def test_import_ids_reject_traversal():
    from tools.eql import import_vuln_hunt, import_eql_lookup
    r = import_vuln_hunt("../../cases/IV_CASE_001/case_meta", "IV_CASE_000")
    assert "Invalid hunt_id" in r["error"]
    r = import_eql_lookup("../secrets", "IV_CASE_000")
    assert "Invalid lookup_id" in r["error"]


# ---------------------------------------------------------------------------
# Batch D — unbounded reads
# ---------------------------------------------------------------------------

def test_analyse_memory_dump_via_mmap(tmp_path):
    import shutil
    from config.settings import CASES_DIR
    from tools.memory_guidance import analyse_memory_dump

    case_id = "IV_CASE_SWEEP_MEM"
    dump = tmp_path / "proc.dmp"
    dump.write_bytes(
        b"\x00" * 64
        + b"http://sweeptest-c2.example.com/payload\x00"
        + b"kernel32.dll\x00"
        + b"\x00" * 64
    )
    try:
        r = analyse_memory_dump(dump, case_id)
        assert r["status"] == "ok"
        assert r["dump_size_bytes"] == dump.stat().st_size
        assert any("sweeptest-c2" in u for u in r["iocs"]["urls"])
        assert "kernel32.dll" in r["dlls"]["all"]
    finally:
        shutil.rmtree(CASES_DIR / case_id, ignore_errors=True)


def test_static_file_analyse_caps_large_files(tmp_path, monkeypatch):
    import hashlib
    import shutil
    import tools.static_file_analyse as sfa
    from config.settings import CASES_DIR

    monkeypatch.setattr(sfa, "_ANALYSIS_READ_CAP", 1024)
    big = tmp_path / "big.bin"
    payload = b"A" * 5000
    big.write_bytes(payload)
    case_id = "IV_CASE_SWEEP_STATIC"
    try:
        r = sfa.static_file_analyse(big, case_id, dispatch_specialist=False)
        # Reported size and hashes must describe the FULL file...
        assert r["size_bytes"] == 5000
        assert r["hashes"]["sha256"] == hashlib.sha256(payload).hexdigest()
        # ...while the analysis buffer is capped and flagged as such.
        assert r["analysis_bytes"] == 1024
        assert any("ANALYSIS_TRUNCATED" in f for f in r["flags"])
    finally:
        shutil.rmtree(CASES_DIR / case_id, ignore_errors=True)


def test_hashing_sink_streams_and_keeps_head():
    import hashlib
    from tools.disk_image_analyse import _HashingSink

    sink = _HashingSink(keep_limit=10)
    sink.write(b"0123456789")
    sink.write(b"ABCDEF")  # beyond the keep limit — hashed but not retained
    assert sink.size == 16
    assert bytes(sink.head) == b"0123456789"
    assert sink.sha256.hexdigest() == hashlib.sha256(b"0123456789ABCDEF").hexdigest()
    assert sink.md5.hexdigest() == hashlib.md5(b"0123456789ABCDEF").hexdigest()


# ---------------------------------------------------------------------------
# CrowdStrike 401 one-shot token retry
# ---------------------------------------------------------------------------

def test_falcon_401_retries_with_fresh_token(monkeypatch):
    import tools.crowdstrike as cs

    class _Resp:
        def __init__(self, status):
            self.status_code = status

    tokens = iter([("host1", "stale"), ("host1", "fresh")])
    invalidated = []
    monkeypatch.setattr(cs, "_acquire_token", lambda client: next(tokens))
    monkeypatch.setattr(cs, "_invalidate_token",
                        lambda client, host: invalidated.append((client, host)))

    calls = []

    def send(host, token):
        calls.append(token)
        return _Resp(401 if token == "stale" else 200)

    host, resp = cs._send_with_auth_retry("acme", send)
    assert resp.status_code == 200
    assert calls == ["stale", "fresh"]
    assert invalidated == [("acme", "host1")]
