"""
tool: geoip
-----------
Local MaxMind GeoLite2 IP geolocation.

Maintains a local copy of GeoLite2-City.mmdb (refreshed weekly) so IP
geolocation is fast, offline, and doesn't consume API quota.

Requires:
  MAXMIND_LICENSE_KEY in .env  (free registration at maxmind.com)
  geoip2 Python package         (pip install geoip2)

Without a license key or geoip2, all lookups return {"available": False}
and enrichment continues normally via existing API providers.

Database path:  registry/geoip/GeoLite2-City.mmdb
Metadata path:  registry/geoip/meta.json

Usage:
    from tools.geoip import lookup_ip, refresh_geoip_db

    info = lookup_ip("185.220.101.45")
    # {"available": True, "country": "Germany", "country_code": "DE", ...}

    refresh_geoip_db()   # downloads / updates the database
"""
from __future__ import annotations

import io
import json
import sys
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import GEOIP_DB_PATH, MAXMIND_LICENSE_KEY
from tools.common import get_session, log_error, utcnow

_META_PATH = GEOIP_DB_PATH.parent / "meta.json"
_DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-City&license_key={key}&suffix=tar.gz"
)


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------

def _load_meta() -> dict:
    if not _META_PATH.exists():
        return {}
    try:
        return json.loads(_META_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_meta(meta: dict) -> None:
    try:
        _META_PATH.parent.mkdir(parents=True, exist_ok=True)
        _META_PATH.write_text(json.dumps(meta, default=str, indent=2), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Database management
# ---------------------------------------------------------------------------

def db_available() -> bool:
    """Return True if the local GeoIP database file exists."""
    return GEOIP_DB_PATH.exists()


def refresh_geoip_db(force: bool = False) -> dict:
    """
    Download or refresh the MaxMind GeoLite2-City database.

    The database is ~70 MB compressed.  Skipped if already updated within
    the past 7 days unless force=True.

    Args:
        force: Re-download even if recently updated.

    Returns:
        {"status": "ok", "path": str, "updated": bool}
    """
    if not MAXMIND_LICENSE_KEY:
        return {
            "status": "error",
            "reason": (
                "MAXMIND_LICENSE_KEY not set. Add it to .env to enable local GeoIP. "
                "Free registration at https://www.maxmind.com/en/geolite2/signup"
            ),
        }

    # Skip if recently updated
    if not force and db_available():
        meta = _load_meta()
        last_updated = meta.get("updated_at", "")
        if last_updated:
            try:
                updated = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) - updated < timedelta(days=7):
                    return {
                        "status": "ok",
                        "path": str(GEOIP_DB_PATH),
                        "updated": False,
                        "note": "Database is current (updated within 7 days).",
                    }
            except Exception:
                pass

    url = _DOWNLOAD_URL.format(key=MAXMIND_LICENSE_KEY)
    try:
        session = get_session()
        response = session.get(url, timeout=120, stream=True)
        response.raise_for_status()

        content = response.content
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("GeoLite2-City.mmdb"):
                    f = tar.extractfile(member)
                    if f:
                        GEOIP_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
                        GEOIP_DB_PATH.write_bytes(f.read())
                        _save_meta({"updated_at": utcnow(), "source": "maxmind-geolite2"})
                        return {
                            "status": "ok",
                            "path": str(GEOIP_DB_PATH),
                            "updated": True,
                        }

        return {
            "status": "error",
            "reason": "GeoLite2-City.mmdb not found in downloaded archive.",
        }
    except Exception as exc:
        log_error("", "geoip.refresh", str(exc), severity="error", context={})
        return {"status": "error", "reason": str(exc)}


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

def lookup_ip(ip: str) -> dict:
    """
    Geolocate an IP address using the local MaxMind database.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        {
            "available": bool,
            "ip": str,
            "country": str,
            "country_code": str,
            "city": str,
            "latitude": float | None,
            "longitude": float | None,
            "timezone": str,
        }

    When the database is not present or geoip2 is not installed, returns
    {"available": False, "ip": ip, "note": "<reason>"} so callers can
    degrade gracefully.
    """
    if not ip or not ip.strip():
        return {"available": False, "ip": ip, "note": "empty IP"}

    if not db_available():
        return {
            "available": False,
            "ip": ip,
            "note": "GeoIP database not present. Call refresh_geoip_db() to download it.",
        }

    try:
        import geoip2.database  # type: ignore
        import geoip2.errors    # type: ignore
    except ImportError:
        return {
            "available": False,
            "ip": ip,
            "note": "geoip2 not installed. Run: pip install geoip2",
        }

    try:
        with geoip2.database.Reader(str(GEOIP_DB_PATH)) as reader:
            r = reader.city(ip)
            return {
                "available": True,
                "ip": ip,
                "country": r.country.name or "",
                "country_code": r.country.iso_code or "",
                "city": r.city.name or "",
                "latitude": r.location.latitude,
                "longitude": r.location.longitude,
                "timezone": r.location.time_zone or "",
            }
    except Exception as exc:
        # AddressNotFoundError is normal for private IPs — not an error
        return {"available": True, "ip": ip, "not_found": str(exc)}


def bulk_lookup(ips: list[str]) -> dict[str, dict]:
    """
    Geolocate multiple IPs. Returns {ip: lookup_result}.
    """
    return {ip: lookup_ip(ip) for ip in ips}
