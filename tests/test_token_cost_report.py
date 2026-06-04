"""
Tests for scripts/token_cost_report.py — API cost projection, session-id
parsing, and live window reconstruction from the per-call usage log.

Run with:  cd socai && python -m pytest tests/test_token_cost_report.py -v
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scripts.token_cost_report as tc
from config.settings import MCP_USAGE_LOG


@pytest.fixture(autouse=True)
def cleanup_usage_log():
    if MCP_USAGE_LOG.exists():
        MCP_USAGE_LOG.unlink()
    yield
    if MCP_USAGE_LOG.exists():
        MCP_USAGE_LOG.unlink()


# ---------------------------------------------------------------------------
# _case_from_session
# ---------------------------------------------------------------------------

class TestCaseFromSession:
    def test_investigation_session(self):
        assert tc._case_from_session("inv_IV_CASE_166_e43f7762") == "IV_CASE_166"

    def test_caseless_session(self):
        assert tc._case_from_session("adhoc_deadbeef") == ""

    def test_garbage(self):
        assert tc._case_from_session("nonsense") == ""


# ---------------------------------------------------------------------------
# _project_api
# ---------------------------------------------------------------------------

class TestProjectApi:
    def test_known_values(self):
        # Hand-computed: payload_resend=200k, sonnet $3/$15, cache_hit=0.9,
        # turns=6, system=25k, output=8k.
        p = tc._project_api(100_000, 300_000, 5, model="sonnet",
                            system_tokens=25_000, cache_hit=0.9,
                            output_tokens=8_000, turns=None, gbp=1.0)
        # point: input (138000 payload + 48750 overhead)*3e-6 + 8000*15e-6
        assert p["assumed_turns"] == 6
        # input (138000 payload + 48750 overhead)*3e-6 = 0.56025 + output 0.12
        assert round(p["projected_cost_usd"], 2) == 0.68
        # range: perfect-cache floor < point < no-cache ceiling
        lo, hi = p["range_gbp"]
        assert lo < p["projected_cost_gbp"] < hi

    def test_cache_hit_monotonic(self):
        # Higher cache hit must never cost more.
        kw = dict(model="sonnet", system_tokens=25_000, output_tokens=8_000,
                  turns=10, gbp=1.0)
        cheap = tc._project_api(100_000, 500_000, 9, cache_hit=0.95, **kw)
        dear = tc._project_api(100_000, 500_000, 9, cache_hit=0.1, **kw)
        assert cheap["projected_cost_usd"] < dear["projected_cost_usd"]

    def test_model_repricing(self):
        kw = dict(system_tokens=25_000, cache_hit=0.9, output_tokens=8_000,
                  turns=6, gbp=1.0)
        opus = tc._project_api(100_000, 300_000, 5, model="opus", **kw)
        sonnet = tc._project_api(100_000, 300_000, 5, model="sonnet", **kw)
        # Opus is 5x Sonnet on both input and output → strictly dearer.
        assert opus["projected_cost_usd"] > sonnet["projected_cost_usd"]


# ---------------------------------------------------------------------------
# _turn_cost_usd — reprice (force_tier) and no_cache
# ---------------------------------------------------------------------------

class TestRepriceCosting:
    TURN = {
        "model": "claude-opus-4-8", "tier": "opus", "sidechain": False,
        "usage": {"input_tokens": 1000, "cache_read_input_tokens": 1000,
                  "output_tokens": 100},
    }

    def test_force_tier_reprices_exactly_5x(self):
        unknown: set = set()
        opus = _turn_cost(self.TURN, unknown)
        sonnet = _turn_cost(self.TURN, unknown, force_tier="sonnet")
        # Opus rates are exactly 5x Sonnet on both input and output.
        assert round(opus["cost_usd"] / sonnet["cost_usd"], 3) == 5.0

    def test_no_cache_dearer_than_cached(self):
        unknown: set = set()
        cached = _turn_cost(self.TURN, unknown)
        no_cache = _turn_cost(self.TURN, unknown, no_cache=True)
        # The 1000 cache-read tokens jump from 0.1x to 1.0x input.
        assert no_cache["cost_usd"] > cached["cost_usd"]

    def test_no_cache_bills_reads_as_fresh(self):
        unknown: set = set()
        nc = _turn_cost(self.TURN, unknown, no_cache=True)
        # opus: (1000 fresh + 1000 read)*15e-6 + 100*75e-6 = 0.03 + 0.0075
        assert round(nc["cost_usd"], 4) == 0.0375


def _turn_cost(turn, unknown, **kw):
    return tc._turn_cost_usd(turn, "sonnet", unknown, **kw)


# ---------------------------------------------------------------------------
# _load_windows_live — reconstruct windows from registry/mcp_usage.jsonl
# ---------------------------------------------------------------------------

class TestLoadWindowsLive:
    def _write(self, records):
        MCP_USAGE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(MCP_USAGE_LOG, "w") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")

    def test_groups_by_session_and_sums_tokens(self):
        self._write([
            {"ts": "2026-06-04T10:00:00Z", "session_id": "inv_IV_CASE_900_aaaaaaaa",
             "caller": "local", "params": {"case_id": "IV_CASE_900"}, "est_tokens": 1000},
            {"ts": "2026-06-04T10:01:00Z", "session_id": "inv_IV_CASE_900_aaaaaaaa",
             "caller": "local", "params": {"case_id": "IV_CASE_900"}, "est_tokens": 3000},
        ])
        wins = tc._load_windows_live(since=None, case_id=None)
        assert len(wins) == 1
        w = wins[0]
        assert w["case_id"] == "IV_CASE_900"
        assert w["step_count"] == 2
        assert w["est_result_tokens"] == 4000          # 1000 + 3000, counted once
        # Re-send weighted: 1000*(2) + 3000*(1) = 5000
        assert w["est_context_input_tokens"] == 5000

    def test_case_filter(self):
        self._write([
            {"ts": "2026-06-04T10:00:00Z", "session_id": "inv_IV_CASE_900_aaaaaaaa",
             "caller": "local", "params": {}, "est_tokens": 1000},
            {"ts": "2026-06-04T10:00:00Z", "session_id": "inv_IV_CASE_901_bbbbbbbb",
             "caller": "local", "params": {}, "est_tokens": 2000},
        ])
        wins = tc._load_windows_live(since=None, case_id="IV_CASE_901")
        assert len(wins) == 1
        assert wins[0]["case_id"] == "IV_CASE_901"
        assert wins[0]["est_result_tokens"] == 2000

    def test_missing_log_returns_empty(self):
        if MCP_USAGE_LOG.exists():
            MCP_USAGE_LOG.unlink()
        assert tc._load_windows_live(since=None, case_id=None) == []
