"""
tool: pdf_analyse
-----------------
Deep static analysis of PDF documents — complements pymupdf metadata in
``static_file_analyse`` with object-level extraction of active content.

Extracts:
  - JavaScript object bodies (`/JS`, `/JavaScript`)
  - Action triggers (`/OpenAction`, `/AA` - Additional Actions)
  - Launch / URI / SubmitForm / GoToR / ImportData action targets
  - Embedded files (`/EmbeddedFile`) with hashes and types
  - Form fields with submission targets
  - URI annotations
  - Object/keyword counts (PDFiD-style)

Writes:
  cases/<case_id>/artefacts/analysis/<filename>.pdf_analysis.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import eprint, log_error, save_json, utcnow

try:
    import pikepdf
    HAS_PIKEPDF = True
except ImportError:
    HAS_PIKEPDF = False


_LLM_SYSTEM_PROMPT = (
    "You are a malware analyst reviewing static analysis of a PDF document. "
    "Given extracted JavaScript, action triggers, embedded files, and URI "
    "targets, assess:\n"
    "- Verdict: malicious / suspicious / clean\n"
    "- Confidence: high / medium / low\n"
    "- Capabilities: credential phishing, exploit delivery, dropper, lure\n"
    "- IOCs: URLs, embedded payload hashes, command lines\n"
    "Only make claims supported by the supplied data."
)


_PDFID_KEYWORDS = [
    "/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/URI",
    "/SubmitForm", "/GoToR", "/GoToE", "/ImportData", "/EmbeddedFile",
    "/RichMedia", "/ObjStm", "/XFA", "/AcroForm", "/JBIG2Decode",
    "/Encrypt", "/Colors > 2^24",
]


def _pdfid_keyword_counts(data: bytes) -> dict[str, int]:
    """Quick byte-level keyword tally over the raw PDF stream."""
    raw = data
    counts: dict[str, int] = {}
    for kw in _PDFID_KEYWORDS:
        token = kw.encode("latin-1")
        counts[kw] = raw.count(token)
    return counts


def _safe_str(obj) -> str:
    try:
        return str(obj)
    except Exception:
        return "<unprintable>"


def _resolve_text(obj) -> str:
    """Walk a pikepdf object that may be a stream, string, or array of
    strings, returning a concatenated text representation."""
    if obj is None:
        return ""
    if isinstance(obj, pikepdf.String):
        return str(obj)
    if isinstance(obj, pikepdf.Stream):
        try:
            return obj.read_bytes().decode("utf-8", errors="replace")
        except Exception:
            return ""
    if isinstance(obj, pikepdf.Array):
        return "\n".join(_resolve_text(o) for o in obj)
    if isinstance(obj, pikepdf.Dictionary):
        # Some JS objects nest under /JS
        try:
            inner = obj.get("/JS")
        except Exception:
            inner = None
        if inner is not None:
            return _resolve_text(inner)
    return _safe_str(obj)


def _collect_action(action, sink: dict) -> None:
    """Recursively pull triggers from an action dictionary."""
    if action is None or not isinstance(action, pikepdf.Dictionary):
        return
    try:
        action_type = _safe_str(action.get("/S", ""))
    except Exception:
        action_type = ""

    entry = {"type": action_type}
    if "/URI" in action:
        entry["uri"] = _resolve_text(action["/URI"])
    if "/F" in action:
        entry["target_file"] = _resolve_text(action["/F"])
    if "/Win" in action:
        win = action["/Win"]
        if isinstance(win, pikepdf.Dictionary) and "/F" in win:
            entry["target_file"] = _resolve_text(win["/F"])
            if "/P" in win:
                entry["parameters"] = _resolve_text(win["/P"])
    if "/JS" in action:
        body = _resolve_text(action["/JS"])
        entry["js"] = body[:8000]
    if "/D" in action:
        entry["destination"] = _safe_str(action["/D"])

    sink.setdefault("actions", []).append(entry)

    # /Next can be a single action dict or array of actions
    nxt = action.get("/Next") if "/Next" in action else None
    if isinstance(nxt, pikepdf.Array):
        for child in nxt:
            _collect_action(child, sink)
    elif isinstance(nxt, pikepdf.Dictionary):
        _collect_action(nxt, sink)


def _collect_embedded_files(pdf: "pikepdf.Pdf") -> list[dict]:
    """Walk the names tree for `/EmbeddedFiles` and return per-attachment info."""
    out: list[dict] = []
    try:
        root = pdf.Root
        names = root.get("/Names") if "/Names" in root else None
        if names is None:
            return out
        emb = names.get("/EmbeddedFiles") if "/EmbeddedFiles" in names else None
        if emb is None:
            return out
    except Exception:
        return out

    # Names tree: /Names is array [name, fileSpec, name, fileSpec, ...]
    def _walk(node):
        try:
            if "/Names" in node:
                pairs = node["/Names"]
                for i in range(0, len(pairs), 2):
                    try:
                        nm = _safe_str(pairs[i])
                        spec = pairs[i + 1]
                    except IndexError:
                        continue
                    out.append(_describe_filespec(nm, spec))
            if "/Kids" in node:
                for kid in node["/Kids"]:
                    _walk(kid)
        except Exception as exc:
            log_error("", "pdf_analyse.embedded_walk", str(exc), severity="warning")

    _walk(emb)
    return out


def _describe_filespec(name: str, spec) -> dict:
    info: dict = {"name": name, "filename": None, "size": None, "sha256": None,
                  "mime": None}
    try:
        info["filename"] = _safe_str(spec.get("/F", spec.get("/UF", name)))
    except Exception:
        pass

    ef = None
    try:
        ef = spec.get("/EF")
    except Exception:
        ef = None
    if isinstance(ef, pikepdf.Dictionary):
        stream = ef.get("/F", ef.get("/UF"))
        if isinstance(stream, pikepdf.Stream):
            try:
                blob = stream.read_bytes()
                info["size"] = len(blob)
                info["sha256"] = hashlib.sha256(blob).hexdigest()
            except Exception as exc:
                log_error("", "pdf_analyse.embedded_read", str(exc), severity="warning")
            try:
                params = stream.get("/Params")
                if isinstance(params, pikepdf.Dictionary):
                    info["mime"] = _safe_str(params.get("/Subtype", ""))
            except Exception:
                pass
    return info


def _collect_javascript(pdf: "pikepdf.Pdf") -> list[dict]:
    """Find /JavaScript entries in the names tree."""
    out: list[dict] = []
    try:
        root = pdf.Root
        names = root.get("/Names") if "/Names" in root else None
        if names is None or "/JavaScript" not in names:
            return out
        node = names["/JavaScript"]
    except Exception:
        return out

    def _walk(n):
        try:
            if "/Names" in n:
                pairs = n["/Names"]
                for i in range(0, len(pairs), 2):
                    nm = _safe_str(pairs[i])
                    js_obj = pairs[i + 1]
                    body = _resolve_text(js_obj)
                    out.append({"name": nm, "js": body[:8000],
                                "js_chars": len(body)})
            if "/Kids" in n:
                for kid in n["/Kids"]:
                    _walk(kid)
        except Exception as exc:
            log_error("", "pdf_analyse.js_walk", str(exc), severity="warning")

    _walk(node)
    return out


def _collect_uri_annotations(pdf: "pikepdf.Pdf") -> list[str]:
    """Walk every page's /Annots and pull /URI link targets."""
    uris: set[str] = set()
    for page in pdf.pages:
        annots = page.get("/Annots") if "/Annots" in page else None
        if annots is None:
            continue
        try:
            iterable = list(annots)
        except Exception:
            continue
        for ann in iterable:
            if not isinstance(ann, pikepdf.Dictionary):
                continue
            action = ann.get("/A") if "/A" in ann else None
            if isinstance(action, pikepdf.Dictionary) and "/URI" in action:
                uris.add(_resolve_text(action["/URI"]))
    return sorted(uris)


def pdf_analyse(file_path: str | Path, case_id: str) -> dict:
    """Deep PDF analysis. Returns and persists a manifest under the case."""
    file_path = Path(file_path)
    if not file_path.exists():
        return {"status": "error", "reason": f"file not found: {file_path}"}

    data = file_path.read_bytes()
    filename = file_path.name

    out_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)

    result: dict = {
        "status": "ok",
        "filename": filename,
        "source_path": str(file_path),
        "case_id": case_id,
        "ts": utcnow(),
        "file_size": len(data),
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "pdfid_keywords": _pdfid_keyword_counts(data),
        "page_count": None,
        "encrypted": False,
        "javascript": [],
        "embedded_files": [],
        "uri_annotations": [],
        "actions": [],
        "flags": [],
    }

    if not HAS_PIKEPDF:
        result["status"] = "skipped"
        result["reason"] = "pikepdf not installed"
        log_error(case_id, "pdf_analyse", "pikepdf missing", severity="warning")
        save_json(out_dir / f"{filename}.pdf_analysis.json", result)
        return result

    try:
        with pikepdf.open(file_path, allow_overwriting_input=False) as pdf:
            result["page_count"] = len(pdf.pages)
            result["encrypted"] = bool(pdf.is_encrypted)
            try:
                result["pdf_version"] = pdf.pdf_version
            except Exception:
                result["pdf_version"] = None

            # OpenAction (catalog-level)
            try:
                root = pdf.Root
                if "/OpenAction" in root:
                    sink: dict = {}
                    _collect_action(root["/OpenAction"], sink)
                    result["actions"].extend(sink.get("actions", []))
            except Exception:
                pass

            # AdditionalActions on catalog
            try:
                aa = pdf.Root.get("/AA") if "/AA" in pdf.Root else None
                if isinstance(aa, pikepdf.Dictionary):
                    for key in aa.keys():
                        sub_sink: dict = {}
                        _collect_action(aa[key], sub_sink)
                        for act in sub_sink.get("actions", []):
                            act["trigger"] = _safe_str(key)
                            result["actions"].append(act)
            except Exception:
                pass

            # Per-page actions / annotations / link triggers
            for idx, page in enumerate(pdf.pages):
                try:
                    paa = page.get("/AA") if "/AA" in page else None
                    if isinstance(paa, pikepdf.Dictionary):
                        for key in paa.keys():
                            sub_sink: dict = {}
                            _collect_action(paa[key], sub_sink)
                            for act in sub_sink.get("actions", []):
                                act["trigger"] = f"page_{idx}_{_safe_str(key)}"
                                result["actions"].append(act)
                except Exception:
                    continue

            result["javascript"] = _collect_javascript(pdf)
            result["embedded_files"] = _collect_embedded_files(pdf)
            result["uri_annotations"] = _collect_uri_annotations(pdf)
    except pikepdf.PasswordError:
        result["encrypted"] = True
        result["parse_error"] = "password protected"
    except Exception as exc:
        log_error(case_id, "pdf_analyse.open", str(exc),
                  severity="warning", context={"file": str(file_path)})
        result["parse_error"] = str(exc)

    # ---- Heuristic flags -------------------------------------------------
    flags = result["flags"]
    if result["javascript"]:
        flags.append(f"JAVASCRIPT: {len(result['javascript'])} JS object(s)")
    if any(a.get("type") == "/Launch" for a in result["actions"]):
        flags.append("LAUNCH_ACTION: PDF can execute external program")
    if any(a.get("type") == "/URI" for a in result["actions"]):
        flags.append("URI_ACTION: auto-opens URL")
    if any(a.get("type") == "/SubmitForm" for a in result["actions"]):
        flags.append("SUBMITFORM: form submission action present")
    if result["embedded_files"]:
        flags.append(f"EMBEDDED_FILES: {len(result['embedded_files'])} attachment(s)")
    if any(t in (result.get("pdfid_keywords") or {}) and result["pdfid_keywords"][t]
           for t in ("/XFA", "/JBIG2Decode")):
        flags.append("EXPLOIT_VECTOR_KEYWORDS: /XFA or /JBIG2Decode present")
    if result["encrypted"]:
        flags.append("ENCRYPTED: PDF is encrypted")

    out_path = out_dir / f"{filename}.pdf_analysis.json"
    save_json(out_path, result)
    eprint(f"[pdf_analyse] {filename}: js={len(result['javascript'])}, "
           f"actions={len(result['actions'])}, "
           f"embedded={len(result['embedded_files'])}, "
           f"flags={len(flags)}")
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Deep static analysis of a PDF.")
    parser.add_argument("file_path")
    parser.add_argument("--case", required=True, dest="case_id")
    args = parser.parse_args()

    out = pdf_analyse(args.file_path, args.case_id)
    print(json.dumps(out, indent=2, default=str))
