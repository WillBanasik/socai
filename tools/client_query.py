"""
tool: client_query
------------------
Stub — direct LLM queries removed.

The local Claude Desktop agent handles ad-hoc SIEM query generation
directly via conversation. No separate API call needed.

Usage:
    # Use the Claude Desktop agent directly instead of this tool.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def client_query(case_id: str = "", query: str = "", **kwargs) -> dict:
    """Stub -- direct LLM queries removed.

    The local Claude Desktop agent handles ad-hoc queries directly
    via conversation. No separate API call needed.
    """
    return {
        "status": "use_prompt",
        "reason": "Ad-hoc queries are handled directly by the local Claude Desktop agent.",
        "case_id": case_id,
    }


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print(json.dumps(client_query(), indent=2))
