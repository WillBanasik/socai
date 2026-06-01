"""
Tests for caching behaviour fixes.

Covers two regressions fixed in the caching audit:
  1. triage's "skip IOCs with sufficient cached coverage" optimisation — it read
     the provider status from the wrong nesting level, so it never fired.
  2. case_memory incremental upsert — new/closed cases are made searchable
     immediately (via index_case) instead of waiting for the 6h full rebuild,
     and the search parse-cache invalidates on the file mtime change.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.common import utcnow


# ---------------------------------------------------------------------------
# 1. triage skip-enrichment coverage
# ---------------------------------------------------------------------------

def test_triage_skips_iocs_with_cached_coverage(monkeypatch, tmp_path):
    """An IOC with >= 3 fresh OK provider rows is added to skip_enrichment_iocs;
    one with too few is not. Regression guard for the status-shape bug that made
    this optimisation a silent no-op."""
    from tools import triage as triage_mod

    cache_file = tmp_path / "enrichment_cache.json"
    now = utcnow()
    covered = "evil.example"
    thin = "thin.example"
    cache = {
        # entries are {"result": {...,"status":...}, "cached_at": ...} — the
        # provider status lives under "result", which is the bug that was fixed.
        f"virustotal|{covered}": {"result": {"status": "ok"}, "cached_at": now},
        f"abuseipdb|{covered}": {"result": {"status": "ok"}, "cached_at": now},
        f"otx|{covered}": {"result": {"status": "ok"}, "cached_at": now},
        f"virustotal|{thin}": {"result": {"status": "ok"}, "cached_at": now},  # only 1
    }
    cache_file.write_text(json.dumps(cache))

    monkeypatch.setattr(triage_mod, "ENRICH_CACHE_FILE", cache_file)
    monkeypatch.setattr(triage_mod, "ENRICH_CACHE_TTL", 24)  # ensure TTL window is active
    monkeypatch.setattr(triage_mod, "IOC_INDEX_FILE", tmp_path / "no_ioc_index.json")

    res = triage_mod.triage(
        "IV_CASE_000",
        urls=[f"https://{covered}/login", f"https://{thin}/x"],
    )
    skip = res["skip_enrichment_iocs"]
    assert covered in skip, "IOC with 3 fresh providers should be skipped"
    assert thin not in skip, "IOC with only 1 provider must not be skipped"


def test_triage_skip_respects_stale_ttl(monkeypatch, tmp_path):
    """Cached rows older than the TTL do not count toward coverage."""
    from tools import triage as triage_mod

    cache_file = tmp_path / "enrichment_cache.json"
    stale = "2000-01-01T00:00:00Z"
    covered = "old.example"
    cache = {
        f"virustotal|{covered}": {"result": {"status": "ok"}, "cached_at": stale},
        f"abuseipdb|{covered}": {"result": {"status": "ok"}, "cached_at": stale},
        f"otx|{covered}": {"result": {"status": "ok"}, "cached_at": stale},
    }
    cache_file.write_text(json.dumps(cache))
    monkeypatch.setattr(triage_mod, "ENRICH_CACHE_FILE", cache_file)
    monkeypatch.setattr(triage_mod, "ENRICH_CACHE_TTL", 24)
    monkeypatch.setattr(triage_mod, "IOC_INDEX_FILE", tmp_path / "no_ioc_index.json")

    res = triage_mod.triage("IV_CASE_000", urls=[f"https://{covered}/x"])
    assert covered not in res["skip_enrichment_iocs"]


# ---------------------------------------------------------------------------
# 2. case_memory incremental upsert + mtime parse cache
# ---------------------------------------------------------------------------

def test_upsert_makes_case_searchable_without_full_rebuild(monkeypatch, tmp_path):
    from tools import case_memory as cm

    idx = tmp_path / "case_memory.json"
    reg = tmp_path / "registry.json"
    monkeypatch.setattr(cm, "CASE_MEMORY_INDEX_FILE", idx)
    monkeypatch.setattr(cm, "REGISTRY_FILE", reg)
    monkeypatch.setattr(cm, "_parse_cache", None)  # start with a cold parse cache

    reg.write_text(json.dumps({"cases": {
        "CM_001": {"title": "alpha", "status": "closed"},
    }}))
    cm.build_case_memory_index()
    built_ids = [e["case_id"] for e in json.loads(idx.read_text())["entries"]]
    assert "CM_002" not in built_ids  # not in the registry at build time

    # A new case lands in the registry *after* the full build.
    reg.write_text(json.dumps({"cases": {
        "CM_001": {"title": "alpha", "status": "closed"},
        "CM_002": {"title": "beta", "status": "closed"},
    }}))

    # A search now (warms the mtime parse-cache) does NOT see the new case —
    # the scheduled full rebuild hasn't run.
    pre = [r["case_id"] for r in cm.search_case_memory("cm_002")["results"]]
    assert "CM_002" not in pre

    # Incremental upsert adds it in place ...
    assert cm.upsert_case_memory("CM_002")["status"] == "ok"
    entries = [e["case_id"] for e in json.loads(idx.read_text())["entries"]]
    assert "CM_002" in entries
    assert entries.count("CM_001") == 1  # upsert must not duplicate the other case

    # ... and search finds it immediately (mtime change invalidates the parse cache).
    post = [r["case_id"] for r in cm.search_case_memory("cm_002")["results"]]
    assert "CM_002" in post


def test_upsert_replaces_existing_entry_not_duplicates(monkeypatch, tmp_path):
    from tools import case_memory as cm

    idx = tmp_path / "case_memory.json"
    reg = tmp_path / "registry.json"
    monkeypatch.setattr(cm, "CASE_MEMORY_INDEX_FILE", idx)
    monkeypatch.setattr(cm, "REGISTRY_FILE", reg)
    monkeypatch.setattr(cm, "_parse_cache", None)

    reg.write_text(json.dumps({"cases": {
        "CM_010": {"title": "x", "status": "active"},
    }}))
    cm.build_case_memory_index()
    # Re-upsert the same case (e.g. active -> closed transition).
    reg.write_text(json.dumps({"cases": {
        "CM_010": {"title": "x", "status": "closed"},
    }}))
    cm.upsert_case_memory("CM_010")
    entries = json.loads(idx.read_text())["entries"]
    assert [e["case_id"] for e in entries].count("CM_010") == 1
    assert entries[0]["status"] == "closed"


def test_upsert_skips_test_case_id(monkeypatch, tmp_path):
    """The test-suite case id (IV_CASE_000) must never be written to the index."""
    from tools import case_memory as cm

    idx = tmp_path / "case_memory.json"
    monkeypatch.setattr(cm, "CASE_MEMORY_INDEX_FILE", idx)
    idx.write_text(json.dumps({"indexed_at": utcnow(), "case_count": 0, "entries": []}))
    res = cm.upsert_case_memory("IV_CASE_000")
    assert res["status"] == "skipped"
