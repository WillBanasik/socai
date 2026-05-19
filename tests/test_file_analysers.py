"""Tests for new file-format analysers.

The optional analyser libraries (oletools, pikepdf, LnkParse3, macholib,
pycdlib, olefile, volatility3) are listed as hard requirements in
``requirements.txt``. Tests gracefully skip when a library is missing so
the suite still runs in lean dev environments.
"""
from __future__ import annotations

import json
import shutil
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_CASE = "IV_CASE_000"


# ---------------------------------------------------------------------------
# Per-test isolation (matches the convention in test_tools.py)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_case():
    from config.settings import CASES_DIR, REGISTRY_FILE

    def _rm():
        case_dir = CASES_DIR / TEST_CASE
        if case_dir.exists():
            shutil.rmtree(case_dir)
        if REGISTRY_FILE.exists():
            data = json.loads(REGISTRY_FILE.read_text())
            data.get("cases", {}).pop(TEST_CASE, None)
            REGISTRY_FILE.write_text(json.dumps(data, indent=2))

    _rm()
    yield
    _rm()


# ---------------------------------------------------------------------------
# _detect_type
# ---------------------------------------------------------------------------

def test_detect_type_new_signatures():
    from tools.static_file_analyse import _detect_type

    cases = [
        (b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 60, "x.lnk",
         "Windows shell link (.lnk)"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 60, "x.doc",
         "Office legacy (DOC)"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 60, "x.msi",
         "MSI installer"),
        (b"PK\x03\x04" + b"\x00" * 60, "x.docx", "ZIP archive"),
        (b"\xfe\xed\xfa\xcf" + b"\x00" * 60, "x", "Mach-O executable"),
        (b"\xca\xfe\xba\xbe" + b"\x00" * 60, "x", "Mach-O universal binary"),
        (b"{\\rtf1\\ansi" + b"\x00" * 60, "x.rtf", "RTF document"),
        (b"MDMP" + b"\x00" * 60, "x.dmp", "Windows minidump"),
        (b"vhdxfile" + b"\x00" * 60, "x.vhdx", "VHDX disk image"),
        (b"random", "x.vmem", "VMware memory dump (.vmem)"),
        (b"random", "x.hta", "HTML Application (HTA)"),
    ]
    for data, fname, expected in cases:
        # Pad small inputs so the ISO9660 LBA-16 check has room to fail safely
        padded = data + b"\x00" * max(0, 33000 - len(data))
        got = _detect_type(padded, fname)
        assert got == expected, f"{fname}: got {got!r}, want {expected!r}"


def test_detect_type_vhd_footer():
    """VHD footer cookie is in the last 512 bytes, not the head."""
    from tools.static_file_analyse import _detect_type

    # Build a fake VHD: 1 KB of zeros then 512-byte footer starting "conectix"
    footer = b"conectix" + b"\x00" * (512 - 8)
    blob = b"\x00" * 1024 + footer
    assert _detect_type(blob, "image.vhd") == "VHD disk image"


def test_detect_type_iso_volume_descriptor():
    from tools.static_file_analyse import _detect_type

    # Volume descriptor at LBA 16 (offset 32768): byte 0 = type (1), bytes
    # 1..6 = "CD001", byte 6 = version (1).
    blob = b"\x00" * 32768
    blob += b"\x01" + b"CD001" + b"\x01" + b"\x00" * 2041
    blob += b"\x00" * 2048
    assert _detect_type(blob, "image.iso") == "ISO 9660 disk image"


# ---------------------------------------------------------------------------
# OneNote: synthetic FileDataStoreObject
# ---------------------------------------------------------------------------

def test_onenote_extract_embedded_payload(tmp_path):
    from tools.onenote_analyse import (
        _FILEDATASTORE_GUID,
        _HEADER_SIZE,
        onenote_analyse,
    )

    # Two embeds: one MZ "executable", one HTML
    payload_a = b"MZ" + b"\x90" * 64
    payload_b = b"<html><body>hello</body></html>"

    def _wrap(payload: bytes) -> bytes:
        return (
            _FILEDATASTORE_GUID
            + struct.pack("<Q", len(payload))
            + b"\x00" * (_HEADER_SIZE - len(_FILEDATASTORE_GUID) - 8)
            + payload
        )

    blob = b"\x00" * 64 + _wrap(payload_a) + b"\x00" * 16 + _wrap(payload_b)
    note = tmp_path / "lure.one"
    note.write_bytes(blob)

    out = onenote_analyse(note, TEST_CASE)
    assert out["status"] == "ok"
    assert len(out["embeds"]) == 2
    kinds = {e["extension_guess"] for e in out["embeds"]}
    assert "exe" in kinds
    assert "html" in kinds
    assert any("EXECUTABLE_PAYLOADS" in f for f in out["flags"])


# ---------------------------------------------------------------------------
# Mach-O detection branch (no macholib needed for magic detection)
# ---------------------------------------------------------------------------

def test_macho_detection_magic_only(tmp_path):
    from tools.macho_analyse import is_macho

    assert is_macho(b"\xfe\xed\xfa\xcf" + b"\x00" * 60) == "MH_MAGIC_64 (64-bit BE)"
    assert is_macho(b"\xca\xfe\xba\xbe" + b"\x00" * 60) == "FAT_MAGIC (universal)"
    assert is_macho(b"MZ" + b"\x00" * 60) is None


# ---------------------------------------------------------------------------
# PDF deep analysis — needs pikepdf
# ---------------------------------------------------------------------------

def test_pdf_active_content_extraction(tmp_path):
    pikepdf = pytest.importorskip("pikepdf")
    from tools.pdf_analyse import pdf_analyse

    pdf_path = tmp_path / "phish.pdf"
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(72, 72))

    js_action = pikepdf.Dictionary(
        Type=pikepdf.Name("/Action"),
        S=pikepdf.Name("/JavaScript"),
        JS=pikepdf.String("app.alert('payload');"),
    )
    pdf.Root.OpenAction = pdf.make_indirect(js_action)
    pdf.save(pdf_path)
    pdf.close()

    out = pdf_analyse(pdf_path, TEST_CASE)
    assert out["status"] == "ok"
    assert out["pdfid_keywords"]["/JS"] >= 1
    assert out["pdfid_keywords"]["/OpenAction"] >= 1
    assert any(a.get("type") == "/JavaScript" for a in out["actions"])


# ---------------------------------------------------------------------------
# LNK header detection (full parse needs LnkParse3)
# ---------------------------------------------------------------------------

def test_lnk_header_detected(tmp_path):
    pytest.importorskip("LnkParse3")
    from tools.lnk_analyse import lnk_analyse

    # Real LNKs are non-trivial; just ensure the parse path doesn't blow up
    # on an invalid shortcut and still produces a manifest with hashes.
    lnk = tmp_path / "fake.lnk"
    lnk.write_bytes(b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 200)
    out = lnk_analyse(lnk, TEST_CASE)
    # Parser may report error on a malformed body, but the wrapper writes
    # a manifest either way.
    assert "hashes" in out
    assert out["filename"] == "fake.lnk"


# ---------------------------------------------------------------------------
# Office analyser — graceful skip when oletools missing
# ---------------------------------------------------------------------------

def test_office_analyse_no_macros_in_zip(tmp_path):
    pytest.importorskip("oletools")
    import zipfile

    from tools.office_analyse import office_analyse

    # Build a minimal OOXML-like zip; no macros expected
    docx = tmp_path / "clean.docx"
    with zipfile.ZipFile(docx, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns='
            '"http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        zf.writestr("word/document.xml",
                    '<?xml version="1.0"?><document/>')

    out = office_analyse(docx, TEST_CASE)
    assert out["status"] in ("ok", "skipped")
    assert out["macro_count"] == 0
    assert out["external_relationships"] == []


# ---------------------------------------------------------------------------
# Volatility wrapper — skip if vol CLI absent
# ---------------------------------------------------------------------------

def test_memory_volatility_skips_without_cli(tmp_path, monkeypatch):
    from tools import memory_volatility

    monkeypatch.setattr(memory_volatility, "_vol_executable", lambda: None)

    dump = tmp_path / "fake.dmp"
    dump.write_bytes(b"\x00" * 1024)

    out = memory_volatility.analyse_memory_volatility(dump, TEST_CASE)
    assert out["status"] == "skipped"
    assert "volatility3" in out["reason"].lower()


# ---------------------------------------------------------------------------
# Specialist dispatch wiring inside static_file_analyse
# ---------------------------------------------------------------------------

def test_static_file_dispatches_to_lnk(tmp_path):
    pytest.importorskip("LnkParse3")
    from tools.static_file_analyse import static_file_analyse

    lnk = tmp_path / "shortcut.lnk"
    lnk.write_bytes(b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 200)
    out = static_file_analyse(lnk, TEST_CASE)
    assert out["file_type"] == "Windows shell link (.lnk)"
    # Specialist analysis is attached even on parse error
    assert out["specialist_analysis"] is not None
