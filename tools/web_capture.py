"""
tool: web_capture
-----------------
Fetches a URL, following redirects, captures:
  - redirect chain (JSON) with type field (http, js_navigation, meta_refresh, final)
  - final HTML source
  - plain-text render
  - screenshot (PNG) via Playwright if available, else skipped
  - page title and final URL
  - intermediate hop captures (HTML, text, screenshot per hop)

All outputs are written to cases/<case_id>/artefacts/web/<safe_hostname>/

Dependencies (optional but recommended):
  pip install playwright requests beautifulsoup4
  playwright install chromium
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import atexit
import threading

from config.settings import BROWSER_BACKEND, CAPTURE_SPA_DWELL, CAPTURE_TIMEOUT, CAPTURE_UA, CASES_DIR, SOCAI_BROWSER_POOL_IDLE_SECS, SOCAI_BROWSER_POOL_MAX_USES
from tools.common import log_error, sha256_bytes, utcnow, write_artefact


# ---------------------------------------------------------------------------
# Persistent browser pool (Playwright sync reuse)
# ---------------------------------------------------------------------------

class _BrowserPool:
    """Module-level singleton that keeps a sync Playwright browser alive across
    multiple capture calls.  Each caller gets a fresh *context* (isolated
    cookies, storage) from the shared browser.

    The browser is recycled after ``max_uses`` context creations to prevent
    memory leaks.  An idle reaper thread automatically shuts down the browser
    after ``idle_secs`` of inactivity, freeing ~400 MB of RAM.

    Thread-safe via ``_lock``.
    """

    def __init__(self, max_uses: int | None = None, idle_secs: int | None = None):
        self._lock = threading.Lock()
        self._sync_pw = None
        self._sync_browser = None
        self._use_count = 0
        self._max_uses = max_uses or SOCAI_BROWSER_POOL_MAX_USES
        self._idle_secs = idle_secs if idle_secs is not None else SOCAI_BROWSER_POOL_IDLE_SECS
        self._last_used: float = 0.0
        self._reaper: threading.Thread | None = None
        self._reaper_stop = threading.Event()

    def _start_reaper(self):
        """Start the idle reaper thread if not already running (must hold _lock)."""
        if self._reaper is not None and self._reaper.is_alive():
            return
        if self._idle_secs <= 0:
            return
        self._reaper_stop.clear()
        self._reaper = threading.Thread(
            target=self._reaper_loop, daemon=True, name="browser-pool-reaper",
        )
        self._reaper.start()

    def _reaper_loop(self):
        """Periodically check if the browser has been idle too long."""
        while not self._reaper_stop.is_set():
            self._reaper_stop.wait(timeout=30)
            if self._reaper_stop.is_set():
                break
            with self._lock:
                if (self._sync_browser is not None
                        and self._last_used > 0
                        and time.monotonic() - self._last_used >= self._idle_secs):
                    print(f"[browser_pool] Idle for {self._idle_secs}s — shutting down pooled browser")
                    self._teardown()

    def _teardown(self):
        """Tear down browser and Playwright (must hold _lock)."""
        if self._sync_browser is not None:
            try:
                self._sync_browser.close()
            except Exception:
                pass
            self._sync_browser = None
        if self._sync_pw is not None:
            try:
                self._sync_pw.stop()
            except Exception:
                pass
            self._sync_pw = None
        self._use_count = 0

    def _ensure_browser(self):
        """Create or recreate the browser if needed (must hold _lock)."""
        needs_new = (
            self._sync_browser is None
            or not self._sync_browser.is_connected()
            or self._use_count >= self._max_uses
        )
        if not needs_new:
            return

        # Tear down old browser if it exists
        self._teardown()

        from playwright.sync_api import sync_playwright  # type: ignore
        self._sync_pw = sync_playwright().start()
        self._sync_browser = self._sync_pw.chromium.launch(headless=True)
        self._use_count = 0
        self._start_reaper()

    def get_sync_context(self):
        """Return a new browser context from the pooled browser.

        The caller MUST close the context when done (but NOT the browser).
        """
        with self._lock:
            self._ensure_browser()
            self._use_count += 1
            self._last_used = time.monotonic()
            return self._sync_browser.new_context(
                user_agent=CAPTURE_UA,
                extra_http_headers={"Accept-Language": "en-GB,en;q=0.9"},
            )

    def cleanup(self):
        """Shut down the pooled browser and Playwright (called at process exit)."""
        self._reaper_stop.set()
        with self._lock:
            self._teardown()


_browser_pool = _BrowserPool()
atexit.register(_browser_pool.cleanup)


# ---------------------------------------------------------------------------
# TLS certificate extraction
# ---------------------------------------------------------------------------

def _extract_tls_cert(hostname: str, port: int = 443) -> dict | None:
    """
    Connect to hostname:port and extract TLS certificate details.
    Returns dict with issuer, subject, SAN, validity, self_signed flag,
    or None on failure.
    """
    import ssl
    import socket
    from datetime import datetime, timezone

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # accept self-signed / expired
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = ssl.DER_cert_to_PEM_cert(cert_bin)

                # Re-decode with validation disabled to get parsed dict
                # Use a second context that loads the DER cert for parsing
                import ssl as _ssl
                pem_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                pem_ctx.check_hostname = False
                pem_ctx.verify_mode = _ssl.CERT_NONE
                # Parse via getpeercert on the already-connected socket
                cert_dict = ssock.getpeercert()

        if not cert_dict and cert_bin:
            # Fallback: minimal info from binary cert
            return {"raw_available": True, "parse_failed": True, "hostname": hostname}

        if not cert_dict:
            return None

        # Extract fields
        subject = dict(x[0] for x in cert_dict.get("subject", ()))
        issuer = dict(x[0] for x in cert_dict.get("issuer", ()))

        san_list = []
        for typ, val in cert_dict.get("subjectAltName", ()):
            san_list.append(val)

        not_before = cert_dict.get("notBefore", "")
        not_after = cert_dict.get("notAfter", "")

        # Parse dates
        cert_age_days = None
        days_remaining = None
        try:
            fmt = "%b %d %H:%M:%S %Y %Z"
            nb = datetime.strptime(not_before, fmt).replace(tzinfo=timezone.utc)
            na = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            cert_age_days = (now - nb).days
            days_remaining = (na - now).days
        except (ValueError, TypeError):
            pass

        issuer_org = issuer.get("organizationName", "")
        subject_cn = subject.get("commonName", "")
        issuer_cn = issuer.get("commonName", "")

        self_signed = (subject == issuer)

        return {
            "hostname": hostname,
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "issuer_org": issuer_org,
            "san": san_list,
            "not_before": not_before,
            "not_after": not_after,
            "cert_age_days": cert_age_days,
            "days_remaining": days_remaining,
            "self_signed": self_signed,
            "serial_number": cert_dict.get("serialNumber", ""),
        }

    except Exception as exc:
        log_error("", "web_capture.tls_cert", str(exc),
                  severity="info", context={"hostname": hostname})
        return None

# ---------------------------------------------------------------------------
# Cloudflare challenge detection
# ---------------------------------------------------------------------------

_CF_TITLE_RE = re.compile(
    r"just a moment|attention required|checking your browser|"
    r"please wait\.\.\.|access denied|ddos protection",
    re.IGNORECASE,
)
_CF_HTML_RE = re.compile(
    r"cf-challenge|cf_chl_opt|cloudflare-challenge|"
    r"chl-warning|cf-error-type|cf-mitigated|"
    r"cdn-cgi/challenge-platform|Ray ID:",
    re.IGNORECASE,
)
_CF_TEXT_RE = re.compile(
    r"checking your browser|just a moment|"
    r"enable javascript and cookies to continue|"
    r"cloudflare ray id|one more step|"
    r"please turn javascript on|"
    r"this process is automatic|"
    r"your browser will redirect",
    re.IGNORECASE,
)


def _detect_cloudflare(html: str, text: str, title: str, status_code: int = 200) -> dict:
    """
    Inspect captured content for Cloudflare challenge/block signals.
    Returns {"blocked": bool, "challenge_type": str | None}.
    """
    title_hit = bool(_CF_TITLE_RE.search(title))
    html_hit  = bool(_CF_HTML_RE.search(html))
    text_hit  = bool(_CF_TEXT_RE.search(text))

    if not (title_hit or html_hit or text_hit) and status_code not in (403, 503):
        return {"blocked": False, "challenge_type": None}

    # Identify the specific challenge type
    html_lower = html.lower()
    if "cf_chl_opt" in html_lower or "cdn-cgi/challenge-platform" in html_lower:
        challenge = "managed_challenge"   # Cloudflare Turnstile / managed challenge
    elif "hcaptcha" in html_lower or "cf-captcha" in html_lower:
        challenge = "captcha"
    elif "cf-error-type" in html_lower or status_code in (403, 1020):
        challenge = "block"               # Hard block / 1020 Access Denied
    elif "just a moment" in title.lower() or "checking your browser" in text.lower():
        challenge = "js_challenge"        # Automatic JS challenge (usually passes in real browser)
    else:
        challenge = "unknown"

    return {"blocked": True, "challenge_type": challenge}


def _safe_dirname(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = re.sub(r"[^\w.\-]", "_", parsed.netloc or "unknown")
    return host[:80]


def _capture_with_requests(url: str) -> dict:
    """
    Fallback: use requests to follow redirects and capture HTML/text.
    No screenshot. Detects meta-refresh in final page and flags it in the chain.
    Returns capture dict.
    """
    from bs4 import BeautifulSoup  # type: ignore
    from tools.common import get_session

    headers = {"User-Agent": CAPTURE_UA}
    resp = get_session().get(
        url,
        headers=headers,
        timeout=CAPTURE_TIMEOUT,
        allow_redirects=True,
        verify=True,
    )

    chain = []
    for r in resp.history:
        chain.append(
            {
                "url": r.url,
                "status": r.status_code,
                "location": r.headers.get("Location", ""),
                "type": "http",
            }
        )
    chain.append({"url": resp.url, "status": resp.status_code, "location": "", "type": "final"})

    html = resp.text
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    text = soup.get_text(separator="\n", strip=True)

    # Detect meta-refresh (flag only, no follow)
    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
    if meta_refresh:
        content = meta_refresh.get("content", "")
        m = re.search(r"url=(.+)", content, re.I)
        if m:
            refresh_url = m.group(1).strip().strip("\"'")
            chain.append({
                "url": resp.url,
                "status": "meta-refresh",
                "location": refresh_url,
                "type": "meta_refresh",
            })

    cf = _detect_cloudflare(html, text, title, resp.status_code)

    return {
        "final_url": resp.url,
        "status_code": resp.status_code,
        "title": title,
        "redirect_chain": chain,
        "html": html,
        "text": text,
        "screenshot_path": None,
        "cloudflare": cf,
        "backend": "requests",
    }


def _capture_with_playwright(url: str) -> dict:
    """
    Full headless capture via Playwright using the persistent browser pool.
    For capturing multiple URLs, prefer _capture_with_playwright_context +
    web_capture_batch to share a single browser session.
    """
    context = _browser_pool.get_sync_context()
    try:
        data = _capture_with_playwright_context(url, context)
    finally:
        try:
            context.close()
        except Exception:
            pass

    return data


def _capture_with_playwright_context(url: str, context) -> dict:
    """
    Capture a single URL using an *existing* Playwright browser context.
    Opens and closes only a page, not the whole browser — safe to call
    repeatedly within a web_capture_batch session.

    Tracks all navigations (HTTP 3xx + JS/framenavigated) and captures
    intermediate hops in separate tabs.
    """
    redirect_chain: list[dict] = []
    status_map: dict[str, int] = {}
    all_nav_urls: list[str] = []
    xhr_responses: list[dict] = []

    # Noise patterns to skip when capturing XHR bodies
    _XHR_SKIP = re.compile(
        r"(google-analytics|doubleclick|fonts\.g(static|oogle)|"
        r"bugsnag|amplitude|planhat|analytics|beacon|telemetry|"
        r"\.woff2?|\.ttf|\.png|\.jpg|\.gif|\.ico|\.css)",
        re.IGNORECASE,
    )
    _XHR_MAX_BODY = 512 * 1024  # 512 KB per response

    page = context.new_page()
    try:
        def _on_response(response):
            req = response.request
            if req.is_navigation_request():
                status_map[response.url] = response.status
                if response.status in range(300, 400):
                    redirect_chain.append({
                        "url": response.url,
                        "status": response.status,
                        "location": response.headers.get("location", ""),
                        "type": "http",
                    })
            else:
                ct = response.headers.get("content-type", "")
                if ("json" in ct or "text/plain" in ct) and not _XHR_SKIP.search(response.url):
                    try:
                        cl = int(response.headers.get("content-length", "0") or "0")
                        if cl <= _XHR_MAX_BODY:
                            body = response.text()
                            if body and len(body) > 100:
                                xhr_responses.append({
                                    "url": response.url,
                                    "status": response.status,
                                    "content_type": ct,
                                    "body": body,
                                })
                    except Exception as exc:
                        log_error("", "web_capture.xhr_intercept", str(exc),
                                  severity="warning", context={"url": response.url})

        def _on_frame_navigated(frame):
            if frame.parent_frame is None:  # main frame only
                nav_url = frame.url
                if nav_url and nav_url != "about:blank":
                    if not all_nav_urls or all_nav_urls[-1] != nav_url:
                        all_nav_urls.append(nav_url)

        page.on("response", _on_response)
        page.on("framenavigated", _on_frame_navigated)

        page.goto(url, timeout=CAPTURE_TIMEOUT * 1000, wait_until="networkidle")
        final_url = page.url
        title = page.title()
        html = page.content()
        text = page.evaluate("() => document.body ? document.body.innerText : ''")
        # SPA dwell: if the page rendered no text (JS app not yet painted), wait and re-capture
        if not text.strip() and CAPTURE_SPA_DWELL > 0:
            page.wait_for_timeout(CAPTURE_SPA_DWELL)
            html = page.content()
            text = page.evaluate("() => document.body ? document.body.innerText : ''")
        screenshot_bytes = page.screenshot(full_page=True)

        # Merge JS navigations (framenavigated entries not in HTTP redirect chain)
        http_urls = {r["url"] for r in redirect_chain}
        for nav_url in all_nav_urls[:-1]:  # exclude final
            if nav_url != url and nav_url not in http_urls:
                redirect_chain.append({
                    "url": nav_url,
                    "status": status_map.get(nav_url),
                    "location": "",
                    "type": "js_navigation",
                })

        redirect_chain.append({"url": final_url, "status": 200, "location": "", "type": "final"})

        # Capture intermediate hops in separate tabs
        intermediate_captures = []
        intermediate_urls = [u for u in all_nav_urls if u != url and u != final_url]

        for i, inter_url in enumerate(intermediate_urls):
            inter_page = context.new_page()
            try:
                inter_page.goto(inter_url, timeout=CAPTURE_TIMEOUT * 1000, wait_until="networkidle")
                intermediate_captures.append({
                    "url": inter_url,
                    "hop_index": i + 1,
                    "title": inter_page.title(),
                    "html": inter_page.content(),
                    "text": inter_page.evaluate("() => document.body ? document.body.innerText : ''"),
                    "screenshot_bytes": inter_page.screenshot(full_page=True),
                })
            except Exception as e:
                log_error("", "web_capture.intermediate_hop", str(e),
                          severity="warning", context={"url": inter_url, "hop": i + 1})
                intermediate_captures.append({
                    "url": inter_url,
                    "hop_index": i + 1,
                    "error": str(e),
                })
            finally:
                inter_page.close()

    finally:
        page.close()

    cf = _detect_cloudflare(html, text, title)

    return {
        "final_url": final_url,
        "status_code": 200,
        "title": title,
        "redirect_chain": redirect_chain,
        "html": html,
        "text": text,
        "screenshot_bytes": screenshot_bytes,
        "intermediate_captures": intermediate_captures,
        "xhr_responses": xhr_responses,
        "cloudflare": cf,
        "backend": "playwright",
    }


_PDF_VIEWER_RE = re.compile(
    r"[?&]file=([^&]+\.pdf[^&]*)|"        # PDF.js ?file= param
    r"/(p|view|viewer)/([^?#]+\.pdf)",     # scloud.cv-style /p/name.pdf path
    re.IGNORECASE,
)
_PDF_EMBED_RE = re.compile(
    r'<(?:embed|object|iframe)[^>]+(?:src|data)=["\']([^"\']+\.pdf[^"\']*)["\']',
    re.IGNORECASE,
)


def _try_pdf_download(final_url: str, html: str, out_dir: Path) -> dict | None:
    """
    Detect if a captured page is a PDF viewer and attempt to download the
    underlying PDF.  Returns a manifest dict on success, None if not detected
    or download failed.
    """
    import urllib.parse
    pdf_url: str | None = None

    # 1. PDF.js ?file=<url> query parameter
    m = re.search(r"[?&]file=([^&\s\"']+)", final_url, re.IGNORECASE)
    if m:
        candidate = urllib.parse.unquote(m.group(1))
        if not candidate.startswith("http"):
            candidate = urllib.parse.urljoin(final_url, candidate)
        pdf_url = candidate

    # 2. Embedded PDF in page HTML (<embed src>, <object data>, <iframe src>)
    if not pdf_url:
        em = _PDF_EMBED_RE.search(html)
        if em:
            candidate = em.group(1)
            if not candidate.startswith("http"):
                candidate = urllib.parse.urljoin(final_url, candidate)
            pdf_url = candidate

    # 3. Viewer URL path pattern like /p/name.pdf or /view/name.pdf
    if not pdf_url:
        m2 = re.search(r"/(p|view|viewer)/([^?#\s]+\.pdf)", final_url, re.IGNORECASE)
        if m2:
            # The viewer URL itself may be the PDF — try a direct fetch
            pdf_url = final_url

    if not pdf_url:
        return None

    try:
        from tools.common import get_session
        headers = {
            "User-Agent": CAPTURE_UA,
            "Referer": final_url,
            "Accept": "application/pdf,*/*",
        }
        resp = get_session().get(pdf_url, headers=headers, timeout=30, allow_redirects=True)
        if resp.status_code != 200:
            return None
        ct = resp.headers.get("content-type", "")
        if "pdf" not in ct and not pdf_url.lower().endswith(".pdf"):
            return None
        data_bytes = resp.content
        if len(data_bytes) < 1024:  # not a real PDF
            return None
        result = write_artefact(out_dir / "document.pdf", data_bytes)
        result["source_url"] = pdf_url
        print(f"[web_capture] PDF downloaded: {pdf_url} ({len(data_bytes):,} bytes)")
        return result
    except Exception as exc:
        log_error("", "web_capture.pdf_download", str(exc),
                  severity="warning", context={"pdf_url": pdf_url})
        print(f"[web_capture] PDF download failed for {pdf_url}: {exc}")
        return None


def _write_capture_artefacts(url: str, case_id: str, data: dict) -> dict:
    """Write all artefacts for a captured URL and return the manifest dict."""
    out_dir = CASES_DIR / case_id / "artefacts" / "web" / _safe_dirname(url)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "url": url,
        "case_id": case_id,
        "backend": data["backend"],
        "final_url": data["final_url"],
        "status_code": data["status_code"],
        "title": data.get("title", ""),
        "redirect_chain": data["redirect_chain"],
        "ts": utcnow(),
        "artefacts": {},
    }

    manifest["artefacts"]["redirect_chain"] = write_artefact(
        out_dir / "redirect_chain.json",
        json.dumps(data["redirect_chain"], indent=2),
    )
    manifest["artefacts"]["html"] = write_artefact(out_dir / "page.html", data["html"])
    manifest["artefacts"]["text"] = write_artefact(out_dir / "page.txt", data["text"])

    # Attempt to auto-download underlying PDF if this is a PDF viewer page
    pdf_result = _try_pdf_download(data["final_url"], data["html"], out_dir)
    if pdf_result:
        manifest["artefacts"]["pdf"] = pdf_result

    xhr_responses = data.get("xhr_responses") or []
    if xhr_responses:
        manifest["artefacts"]["xhr_responses"] = write_artefact(
            out_dir / "xhr_responses.json",
            json.dumps(xhr_responses, indent=2),
        )
        manifest["xhr_response_count"] = len(xhr_responses)

    screenshot_bytes = data.get("screenshot_bytes")
    if screenshot_bytes:
        manifest["artefacts"]["screenshot"] = write_artefact(
            out_dir / "screenshot.png", screenshot_bytes
        )
    else:
        manifest["artefacts"]["screenshot"] = None

    # Write intermediate hop subdirectories
    intermediate_captures = data.get("intermediate_captures", [])
    if intermediate_captures:
        manifest["intermediate_captures"] = []
        for ic in intermediate_captures:
            hop_dir = out_dir / f"hop_{ic['hop_index']:02d}"
            hop_dir.mkdir(parents=True, exist_ok=True)
            hop_manifest: dict = {"url": ic["url"], "hop_index": ic["hop_index"]}
            if "error" in ic:
                hop_manifest["error"] = ic["error"]
            else:
                hop_manifest["title"] = ic["title"]
                hop_manifest["html"] = write_artefact(hop_dir / "page.html", ic["html"])
                hop_manifest["text"] = write_artefact(hop_dir / "page.txt", ic["text"])
                if ic.get("screenshot_bytes"):
                    hop_manifest["screenshot"] = write_artefact(
                        hop_dir / "screenshot.png", ic["screenshot_bytes"]
                    )
            manifest["intermediate_captures"].append(hop_manifest)

    # TLS certificate extraction
    final_hostname = _safe_dirname(data["final_url"]).split("_")[0]  # strip port
    try:
        parsed_host = urllib.parse.urlparse(data["final_url"]).hostname
    except Exception:
        parsed_host = final_hostname
    if parsed_host and data["final_url"].startswith("https"):
        tls_cert = _extract_tls_cert(parsed_host)
        if tls_cert:
            manifest["tls_certificate"] = tls_cert

    cf = data.get("cloudflare") or {}
    manifest["cloudflare_blocked"] = cf.get("blocked", False)
    manifest["cloudflare_challenge"] = cf.get("challenge_type")
    if cf.get("blocked"):
        print(
            f"[web_capture] \u26a0\ufe0f  CLOUDFLARE BLOCKED ({cf['challenge_type']}): {url}"
            f" — captured content may be incomplete / challenge page only"
        )

    write_artefact(out_dir / "capture_manifest.json", json.dumps(manifest, indent=2))
    print(f"[web_capture] Captured {url} → {out_dir}")
    return manifest


def web_capture(url: str, case_id: str) -> dict:
    """
    Capture *url* and persist artefacts under the case folder.
    Returns a manifest dict with all artefact paths and SHA-256s.
    """
    try:
        if BROWSER_BACKEND == "playwright":
            data = _capture_with_playwright(url)
        else:
            raise ImportError("forced requests fallback")
    except Exception as pw_err:
        log_error(case_id, "web_capture.playwright", str(pw_err),
                  severity="warning", context={"url": url, "fallback": "requests"})
        print(f"[web_capture] Playwright unavailable ({pw_err}), falling back to requests.")
        try:
            data = _capture_with_requests(url)
        except Exception as req_err:
            log_error(case_id, "web_capture.requests", str(req_err),
                      context={"url": url})
            return {
                "error": str(req_err),
                "url": url,
                "case_id": case_id,
                "ts": utcnow(),
            }

    return _write_capture_artefacts(url, case_id, data)


def _web_capture_batch_sync(urls: list[str], case_id: str) -> list[dict]:
    """Sequential batch capture using the persistent browser pool."""
    results: list[dict] = []
    context = _browser_pool.get_sync_context()
    try:
        for url in urls:
            try:
                data = _capture_with_playwright_context(url, context)
            except Exception as pw_page_err:
                log_error(case_id, "web_capture_batch.playwright_page", str(pw_page_err),
                          severity="warning", context={"url": url, "fallback": "requests"})
                print(
                    f"[web_capture_batch] Playwright failed for {url} "
                    f"({pw_page_err}), trying requests."
                )
                try:
                    data = _capture_with_requests(url)
                except Exception as req_err:
                    log_error(case_id, "web_capture_batch.requests", str(req_err),
                              context={"url": url})
                    results.append({
                        "error": str(req_err),
                        "url": url,
                        "case_id": case_id,
                        "ts": utcnow(),
                    })
                    continue
            results.append(_write_capture_artefacts(url, case_id, data))
    finally:
        try:
            context.close()
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Async Playwright batch — concurrent page loads in a shared browser
# ---------------------------------------------------------------------------
# The async API allows multiple pages to load concurrently via asyncio.gather.
# One browser, one context, N pages loading in parallel.

_BATCH_MAX_CONCURRENT = 4  # avoid hammering targets; adjustable


async def _async_capture_page(url: str, context, semaphore) -> dict:
    """Capture a single URL using an async Playwright context.

    Mirrors the logic in ``_capture_with_playwright_context`` but uses the
    async API so multiple pages can load concurrently.
    """
    import asyncio

    async with semaphore:
        redirect_chain: list[dict] = []
        status_map: dict[str, int] = {}
        all_nav_urls: list[str] = []
        xhr_responses: list[dict] = []

        _XHR_SKIP = re.compile(
            r"(google-analytics|doubleclick|fonts\.g(static|oogle)|"
            r"bugsnag|amplitude|planhat|analytics|beacon|telemetry|"
            r"\.woff2?|\.ttf|\.png|\.jpg|\.gif|\.ico|\.css)",
            re.IGNORECASE,
        )
        _XHR_MAX_BODY = 512 * 1024

        page = await context.new_page()
        try:
            async def _on_response(response):
                req = response.request
                if req.is_navigation_request():
                    status_map[response.url] = response.status
                    if response.status in range(300, 400):
                        redirect_chain.append({
                            "url": response.url,
                            "status": response.status,
                            "location": response.headers.get("location", ""),
                            "type": "http",
                        })
                else:
                    ct = response.headers.get("content-type", "")
                    if ("json" in ct or "text/plain" in ct) and not _XHR_SKIP.search(response.url):
                        try:
                            cl = int(response.headers.get("content-length", "0") or "0")
                            if cl <= _XHR_MAX_BODY:
                                body = await response.text()
                                if body and len(body) > 100:
                                    xhr_responses.append({
                                        "url": response.url,
                                        "status": response.status,
                                        "content_type": ct,
                                        "body": body,
                                    })
                        except Exception:
                            pass

            def _on_frame_navigated(frame):
                if frame.parent_frame is None:
                    nav_url = frame.url
                    if nav_url and nav_url != "about:blank":
                        if not all_nav_urls or all_nav_urls[-1] != nav_url:
                            all_nav_urls.append(nav_url)

            page.on("response", _on_response)
            page.on("framenavigated", _on_frame_navigated)

            await page.goto(url, timeout=CAPTURE_TIMEOUT * 1000, wait_until="networkidle")
            final_url = page.url
            title = await page.title()
            html = await page.content()
            text = await page.evaluate("() => document.body ? document.body.innerText : ''")

            if not text.strip() and CAPTURE_SPA_DWELL > 0:
                await page.wait_for_timeout(CAPTURE_SPA_DWELL)
                html = await page.content()
                text = await page.evaluate("() => document.body ? document.body.innerText : ''")

            screenshot_bytes = await page.screenshot(full_page=True)

            # Merge JS navigations not in HTTP redirect chain
            http_urls = {r["url"] for r in redirect_chain}
            for nav_url in all_nav_urls[:-1]:
                if nav_url != url and nav_url not in http_urls:
                    redirect_chain.append({
                        "url": nav_url,
                        "status": status_map.get(nav_url),
                        "location": "",
                        "type": "js_navigation",
                    })

            redirect_chain.append({"url": final_url, "status": 200, "location": "", "type": "final"})

            # Capture intermediate hops
            intermediate_captures = []
            intermediate_urls = [u for u in all_nav_urls if u != url and u != final_url]
            for i, inter_url in enumerate(intermediate_urls):
                inter_page = await context.new_page()
                try:
                    await inter_page.goto(inter_url, timeout=CAPTURE_TIMEOUT * 1000, wait_until="networkidle")
                    intermediate_captures.append({
                        "url": inter_url,
                        "hop_index": i + 1,
                        "title": await inter_page.title(),
                        "html": await inter_page.content(),
                        "text": await inter_page.evaluate("() => document.body ? document.body.innerText : ''"),
                        "screenshot_bytes": await inter_page.screenshot(full_page=True),
                    })
                except Exception as e:
                    intermediate_captures.append({
                        "url": inter_url,
                        "hop_index": i + 1,
                        "error": str(e),
                    })
                finally:
                    await inter_page.close()

        finally:
            await page.close()

        cf = _detect_cloudflare(html, text, title)

        return {
            "final_url": final_url,
            "status_code": 200,
            "title": title,
            "redirect_chain": redirect_chain,
            "html": html,
            "text": text,
            "screenshot_bytes": screenshot_bytes,
            "intermediate_captures": intermediate_captures,
            "xhr_responses": xhr_responses,
            "cloudflare": cf,
            "backend": "playwright_async",
        }


async def _async_web_capture_batch(urls: list[str], case_id: str) -> list[dict]:
    """Capture multiple URLs concurrently using async Playwright."""
    import asyncio
    from playwright.async_api import async_playwright  # type: ignore

    semaphore = asyncio.Semaphore(_BATCH_MAX_CONCURRENT)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent=CAPTURE_UA,
            extra_http_headers={"Accept-Language": "en-GB,en;q=0.9"},
        )
        try:
            tasks = [_async_capture_page(url, context, semaphore) for url in urls]
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)

            results: list[dict] = []
            for url, result in zip(urls, raw_results):
                if isinstance(result, Exception):
                    log_error(case_id, "web_capture_batch.async_page", str(result),
                              severity="warning", context={"url": url, "fallback": "requests"})
                    print(f"[web_capture_batch] Async capture failed for {url} ({result}), trying requests.")
                    try:
                        data = _capture_with_requests(url)
                        results.append(_write_capture_artefacts(url, case_id, data))
                    except Exception as req_err:
                        log_error(case_id, "web_capture_batch.requests", str(req_err),
                                  context={"url": url})
                        results.append({
                            "error": str(req_err),
                            "url": url,
                            "case_id": case_id,
                            "ts": utcnow(),
                        })
                else:
                    results.append(_write_capture_artefacts(url, case_id, result))
        finally:
            await browser.close()

    return results


def web_capture_batch(urls: list[str], case_id: str) -> list[dict]:
    """
    Capture multiple URLs sharing a single Playwright browser session.

    Tries async Playwright first (concurrent page loads via asyncio.gather),
    then falls back to sync Playwright (sequential), then to serial
    requests-based capture if Playwright is unavailable entirely.
    """
    if not urls:
        return []

    # Try async Playwright (concurrent page loads)
    try:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # Already inside an async context (e.g. MCP server) — schedule on
            # the running loop. MCP tool handlers run sync functions in a thread,
            # so we need a new loop in a new thread to avoid deadlock.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(asyncio.run, _async_web_capture_batch(urls, case_id)).result()
            return result
        else:
            return asyncio.run(_async_web_capture_batch(urls, case_id))
    except Exception as async_err:
        log_error(case_id, "web_capture_batch.async", str(async_err),
                  severity="warning", context={"url_count": len(urls), "fallback": "sync"})
        print(f"[web_capture_batch] Async Playwright unavailable ({async_err}), trying sync.")

    # Fall back to sync Playwright (sequential)
    try:
        return _web_capture_batch_sync(urls, case_id)
    except Exception as pw_err:
        log_error(case_id, "web_capture_batch.playwright", str(pw_err),
                  severity="warning", context={"url_count": len(urls), "fallback": "serial"})
        print(
            f"[web_capture_batch] Playwright unavailable ({pw_err}), "
            f"falling back to serial captures."
        )
        return [web_capture(url, case_id) for url in urls]


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Capture a URL for a case.")
    p.add_argument("url")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = web_capture(args.url, args.case_id)
    print(json.dumps(result, indent=2, default=str))
