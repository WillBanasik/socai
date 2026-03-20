"""
tool: case_memory
-----------------
Semantic case recall — build a BM25 index over all case summaries so
analysts can find similar past investigations by natural-language query
rather than exact IOC match.

Complements tools/recall.py (exact IOC/keyword lookup) with ranked
free-text retrieval over case narrative content: titles, tags, IOCs,
attack types, report excerpts, and analyst notes.

BM25 is implemented inline — no external dependencies required.

Writes:
  registry/case_memory.json

Usage:
    from tools.case_memory import search_case_memory, build_case_memory_index

    result = search_case_memory("DocuSign phishing credential harvest")
    # returns ranked list of similar prior cases
"""
from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASE_MEMORY_INDEX_FILE, CASES_DIR, REGISTRY_FILE
from tools.common import load_json, log_error, utcnow


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

def _tokenise(text: str) -> list[str]:
    """Lowercase, strip non-word characters, split — returns deduplicated tokens."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s\-_./:]", " ", text)
    return [t for t in text.split() if len(t) > 1]


# ---------------------------------------------------------------------------
# BM25 implementation
# ---------------------------------------------------------------------------

class _BM25:
    """Minimal BM25 index over a list of token lists."""

    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75) -> None:
        self.docs = docs
        self.N = len(docs)
        self.k1 = k1
        self.b = b
        self.avg_dl = sum(len(d) for d in docs) / max(self.N, 1)
        self.df: dict[str, int] = {}
        for doc in docs:
            for t in set(doc):
                self.df[t] = self.df.get(t, 0) + 1

    def _score(self, query_tokens: list[str], doc_idx: int) -> float:
        doc = self.docs[doc_idx]
        dl = len(doc)
        tf_map: dict[str, int] = {}
        for t in doc:
            tf_map[t] = tf_map.get(t, 0) + 1
        score = 0.0
        for q in query_tokens:
            tf = tf_map.get(q, 0)
            if tf == 0:
                continue
            idf = math.log((self.N - self.df.get(q, 0) + 0.5) / (self.df.get(q, 0) + 0.5) + 1)
            norm_tf = tf * (self.k1 + 1) / (tf + self.k1 * (1 - self.b + self.b * dl / self.avg_dl))
            score += idf * norm_tf
        return score

    def search(self, query_tokens: list[str], top_k: int = 5) -> list[tuple[int, float]]:
        """Return [(doc_idx, score), ...] sorted descending, scores > 0 only."""
        scores = [(i, self._score(query_tokens, i)) for i in range(self.N)]
        scores.sort(key=lambda x: x[1], reverse=True)
        return [(i, s) for i, s in scores[:top_k] if s > 0.0]


# ---------------------------------------------------------------------------
# Case text extraction
# ---------------------------------------------------------------------------

def _extract_case_text(case_id: str) -> str:
    """Build a searchable text blob from a case directory."""
    case_dir = CASES_DIR / case_id
    parts: list[str] = [case_id]

    # case_meta.json
    meta_path = case_dir / "case_meta.json"
    if meta_path.exists():
        try:
            meta = load_json(meta_path)
            parts.append(meta.get("title", ""))
            parts.extend(meta.get("tags", []))
            if meta.get("attack_type"):
                parts.append(str(meta["attack_type"]))
            if meta.get("client"):
                parts.append(str(meta["client"]))
            if meta.get("disposition"):
                parts.append(str(meta["disposition"]))
        except Exception:
            pass

    # IOCs (raw values help match e.g. "gamblingprice.com" in query)
    iocs_path = case_dir / "iocs" / "iocs.json"
    if iocs_path.exists():
        try:
            iocs_data = load_json(iocs_path)
            ioc_dict = iocs_data.get("iocs", {})
            for vals in ioc_dict.values():
                parts.extend(vals[:20])
        except Exception:
            pass

    # Report excerpt (MDR report preferred over pipeline report)
    for rname in ("mdr_report.md", "investigation_report.md"):
        rpath = case_dir / "reports" / rname
        if rpath.exists():
            try:
                text = rpath.read_text(encoding="utf-8", errors="replace")
                parts.append(text[:3000])
            except Exception:
                pass
            break

    # Analyst notes
    notes_path = case_dir / "notes" / "analyst_input.md"
    if notes_path.exists():
        try:
            parts.append(notes_path.read_text(encoding="utf-8", errors="replace")[:800])
        except Exception:
            pass

    return " ".join(str(p) for p in parts if p)


# ---------------------------------------------------------------------------
# Index build
# ---------------------------------------------------------------------------

def build_case_memory_index(include_open: bool = True) -> dict:
    """
    Walk all cases, extract text, and write a BM25-ready token index to
    registry/case_memory.json.

    Args:
        include_open: Include non-closed cases (default True — useful so
            in-progress cases are also recalled).

    Returns:
        {"status": "ok", "indexed": N, "path": str}
    """
    try:
        registry_data = load_json(REGISTRY_FILE) if REGISTRY_FILE.exists() else {}
        case_registry = registry_data.get("cases", registry_data)
    except Exception as exc:
        log_error("", "case_memory.build_index", str(exc),
                  severity="error", context={})
        return {"status": "error", "reason": str(exc)}

    entries: list[dict] = []
    for case_id, meta in case_registry.items():
        if case_id.startswith("TEST_"):
            continue
        if not include_open and meta.get("status") not in ("closed",):
            continue

        text = _extract_case_text(case_id)
        tokens = _tokenise(text)
        entries.append({
            "case_id": case_id,
            "title": meta.get("title", ""),
            "client": meta.get("client", ""),
            "severity": meta.get("severity", ""),
            "status": meta.get("status", ""),
            "disposition": meta.get("disposition", ""),
            "created_at": meta.get("created_at", ""),
            "tags": meta.get("tags", []),
            "tokens": tokens,
        })

    index = {
        "indexed_at": utcnow(),
        "case_count": len(entries),
        "entries": entries,
    }

    try:
        CASE_MEMORY_INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
        CASE_MEMORY_INDEX_FILE.write_text(
            json.dumps(index, default=str), encoding="utf-8"
        )
    except Exception as exc:
        log_error("", "case_memory.write_index", str(exc),
                  severity="error", context={})
        return {"status": "error", "reason": str(exc)}

    return {
        "status": "ok",
        "indexed": len(entries),
        "path": str(CASE_MEMORY_INDEX_FILE),
    }


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def search_case_memory(
    query: str,
    *,
    top_k: int = 5,
    client_filter: str = "",
) -> dict:
    """
    Semantic case recall via BM25.

    Finds prior cases similar to the query by ranked text similarity — not
    just exact IOC/keyword matches.  Best for queries like:
      "credential phishing DocuSign" or "account takeover Egypt login"

    Builds the index automatically on first call if it doesn't exist.

    Args:
        query:         Natural-language description of what you're looking for.
        top_k:         Maximum number of results (default 5).
        client_filter: If set, restrict to cases for this client only.

    Returns:
        {
            "status": "ok",
            "query": str,
            "results": [{"case_id", "title", "client", "severity",
                         "status", "disposition", "created_at", "tags",
                         "relevance_score"}, ...],
            "total_indexed": int,
            "index_built_at": str,
        }
    """
    if not query.strip():
        return {"status": "error", "reason": "query is required"}

    # Auto-build index if missing
    if not CASE_MEMORY_INDEX_FILE.exists():
        built = build_case_memory_index()
        if built.get("status") != "ok":
            return built

    try:
        raw = json.loads(CASE_MEMORY_INDEX_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        log_error("", "case_memory.search", str(exc), severity="error", context={})
        return {"status": "error", "reason": str(exc)}

    entries = raw.get("entries", [])
    if not entries:
        return {
            "status": "ok",
            "query": query,
            "results": [],
            "total_indexed": 0,
            "index_built_at": raw.get("indexed_at", ""),
        }

    # Client filter
    if client_filter:
        cf = client_filter.strip().lower()
        entries = [e for e in entries if (e.get("client") or "").lower() == cf]

    if not entries:
        return {
            "status": "ok",
            "query": query,
            "results": [],
            "total_indexed": len(raw.get("entries", [])),
            "index_built_at": raw.get("indexed_at", ""),
        }

    token_lists = [e["tokens"] for e in entries]
    bm25 = _BM25(token_lists)
    query_tokens = _tokenise(query)
    hits = bm25.search(query_tokens, top_k=top_k)

    results = [
        {
            "case_id": entries[idx]["case_id"],
            "title": entries[idx]["title"],
            "client": entries[idx]["client"],
            "severity": entries[idx]["severity"],
            "status": entries[idx]["status"],
            "disposition": entries[idx]["disposition"],
            "created_at": entries[idx]["created_at"],
            "tags": entries[idx]["tags"],
            "relevance_score": round(score, 3),
        }
        for idx, score in hits
    ]

    return {
        "status": "ok",
        "query": query,
        "results": results,
        "total_indexed": len(raw.get("entries", [])),
        "index_built_at": raw.get("indexed_at", ""),
    }
