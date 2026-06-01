"""
Tests for tools/playbooks.py — the unified per-platform playbook renderer.

Focus: the sweep-all host-scoping fix. The shared ``device_name`` parameter
defaults to the ``__NONE__`` sweep-all sentinel. KQL stages guard that inline,
but CQL/LogScale stages apply a bare ``| ComputerName = /{{device_name}}/i``
regex with no guard — and ``/__NONE__/i`` (or the unsubstituted token when the
param is omitted) matches ZERO hosts, silently turning an all-host sweep into an
empty result. ``render_stage_for_platform`` drops the optional host-filter line
in the sweep-all case for CQL only; KQL and scoped (real device) renders must be
left intact.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.playbooks import render_stage_for_platform

# A CQL filter line scoping on a host, e.g. ``| ComputerName = /WEB01/i``.
# Note the ``= /`` — distinguishes a *filter* from a projection like
# ``| groupBy([ComputerName], …)`` or ``| table([…, ComputerName, …])`` which
# merely reference the column and must NOT be stripped.
_HOST_FILTER_RE = re.compile(r"\|\s*ComputerName\s*=\s*/")


def _render(playbook, stage, params, platform):
    out = render_stage_for_platform(playbook, stage, params, platform)
    assert isinstance(out, str), f"render returned an error dict: {out!r}"
    return out


@pytest.mark.parametrize("params", [
    {"device_name": "__NONE__"},   # explicit sweep-all sentinel
    {},                            # param omitted → renderer leaves token unfilled
])
def test_cql_sweep_all_drops_host_filter(params):
    """In the sweep-all case the CQL host *filter* line is removed entirely,
    and no unsubstituted ``{{device_name}}`` token leaks into the query."""
    out = _render("vulnerability-hunting", 1, params, "logscale")
    assert not _HOST_FILTER_RE.search(out), (
        f"sweep-all CQL still contains a host filter line:\n{out}"
    )
    assert "{{device_name}}" not in out
    assert "/__NONE__/" not in out, "match-nothing /__NONE__/ regex leaked into the query"
    # The event-source line and downstream pipeline survive — query is non-empty.
    assert out.strip()
    assert "#event_simpleName" in out


def test_cql_scoped_keeps_host_filter():
    """A real device name must still produce a scoped host filter, unchanged."""
    out = _render("vulnerability-hunting", 1, {"device_name": "WEB01"}, "logscale")
    assert "| ComputerName = /WEB01/i" in out
    assert "{{device_name}}" not in out


def test_cql_multi_filter_stage_drops_all_host_filters():
    """A stage with several sub-queries (multiple host filters) drops every
    host *filter* line on sweep-all, while keeping ``ComputerName`` projections."""
    sweep = _render("vulnerability-hunting", 4, {"device_name": "__NONE__"}, "logscale")
    assert not _HOST_FILTER_RE.search(sweep)
    # Projections referencing the column are retained (table/sort still emit it).
    assert "ComputerName" in sweep

    scoped = _render("vulnerability-hunting", 4, {"device_name": "SRV1"}, "logscale")
    assert len(_HOST_FILTER_RE.findall(scoped)) == 2  # two sub-queries, both scoped


def test_cql_fix_covers_other_playbooks():
    """The renderer fix is generic (keyed on the {{device_name}} token), so the
    same shared LogScale convention is fixed across playbooks, e.g. web-shell."""
    sweep = _render("web-shell", 1, {"device_name": "__NONE__"}, "logscale")
    assert not _HOST_FILTER_RE.search(sweep)
    scoped = _render("web-shell", 1, {"device_name": "IIS01"}, "logscale")
    assert "| ComputerName = /IIS01/i" in scoped


def test_kql_sweep_all_left_intact():
    """KQL stages guard ``__NONE__`` inline (``let device = …; … device ==
    "__NONE__" or DeviceName has device``) — the renderer must NOT strip them."""
    out = _render("vulnerability-hunting", 1, {"device_name": "__NONE__"}, "sentinel")
    assert 'let device = "__NONE__";' in out
    # The inline guard that makes __NONE__ mean "all hosts" must survive.
    assert 'device == "__NONE__"' in out
