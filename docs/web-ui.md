# Web UI — LLM Chat Interface

The case investigation page (`ui/case.html`) is a **full-screen LLM chat interface**. Analysts type natural language and Chief (the LLM agent) interprets intent and dispatches tools via Claude's `tool_use` API.

## Backend: `api/chat.py`

- `TOOL_DEFS` — 22 tool definitions for case-mode chat
- `SESSION_TOOL_DEFS` — 31 tool definitions for session-mode chat (includes all case-mode tools plus session-specific tools: `load_case_context`, `save_to_case`, etc.)
- `build_system_prompt(case_id)` — loads case metadata + artefact summary, uses prompt caching (`cache_control: ephemeral`)
- `chat(case_id, user_message, history)` — multi-turn tool loop (up to 10 rounds)
- `chat_stream(case_id, user_message, history)` — streaming variant yielding SSE events
- `session_chat_stream(session_id, user_message, history)` — streaming session-mode chat
- `execute_tool(case_id, tool_name, tool_input)` — dispatches to `api/actions.py`, returns `_message` strings
- `read_case_file(case_id, file_path)` — lets Claude read any case artefact on demand (traversal-safe)
- Chat history is **per-user per-case**: stored at `cases/{id}/chat_history_{email}.json` in Anthropic API message format
- History trimming: `_trim_for_api()` sends only last 20 messages to API (full history saved to disk), with orphaned `tool_result` cleanup and tool result truncation to 3000 chars
- **Compaction** (Opus models): when enabled, uses API-side context compaction instead of hard message truncation, preserving earlier conversation context

### Session-Mode Backing Cases

Session tools that need file-based artefact storage (e.g. `capture_urls`, `detect_phishing`, `generate_report`) automatically create a **backing case** via `_session_ensure_backing_case()`. The backing case ID is stored in the session context and reused for all subsequent tool calls in that session. When the session is materialised, the backing case's artefacts are already in place.

## API Routes (`api/main.py`)

### Chat Endpoints (synchronous)

- `POST /api/cases/{id}/chat` — accepts `message` form field, returns `{reply, tool_calls}`

### Streaming Chat Endpoints (SSE)

- `POST /api/chat/stream` — general streaming chat
- `POST /api/cases/{id}/chat/stream` — case-mode streaming chat
- `POST /api/sessions/{id}/chat/stream` — session-mode streaming chat

SSE event types:
- `text_delta` — partial token for progressive rendering
- `tool_start` — tool execution beginning (name + input)
- `tool_result` — tool execution complete (name + result)
- `case_context_loaded` — case context loaded into session (case_id, title, severity)
- `done` — final summary with full reply and tool call list
- `error` — error message

### Browse / Dashboard / Context Endpoints

- `GET /api/investigations/browse` — enriched case list with IOC totals, link counts, disposition; filterable via `?status=`, `?severity=`, `?q=`
- `GET /api/landscape` — landscape assessment data for dashboard charts (cached < 1hr, otherwise regenerated via `assess_landscape()`); filterable via `?days=`, `?client=`
- `GET /api/investigations/{id}/context-summary` — compact context bundle (meta, IOCs, verdicts, findings, report excerpt, investigation log, KQL queries) for loading a case into a chat session or displaying on the case detail page

### OpenCTI Threat Intelligence Endpoints

All require `investigations:read` permission. Data sourced from OpenCTI GraphQL API (`OPENCTI_URL`/`OPENCTI_API_KEY`).

- `GET /api/cti/feed?days=30&sector=&limit=20` — recent reports with linked threat actors, malware, campaigns, sectors, and labels. Filterable by sector label.
- `GET /api/cti/trending?days=7&limit=20` — recently created indicators sorted by score (minimum score 40)
- `GET /api/cti/attack-heatmap` — MITRE ATT&CK technique distribution. Returns tactic-grouped view if kill chain phases are populated, otherwise a flat top-N by relationship count.
- `GET /api/cti/ioc-xref` — batch cross-reference of all open case IOCs against OpenCTI observables. Returns each IOC enriched with `opencti_score`, `opencti_verdict`, and `opencti_link`.
- `GET /api/cti/watchlist?days=30` — threat actor watchlist with recent activity (reports) from OpenCTI
- `POST /api/cti/watchlist` — add a threat actor to the watchlist (form field: `name`)
- `DELETE /api/cti/watchlist?name=` — remove a threat actor from the watchlist
- `GET /api/cti/ioc-decay` — IOC decay/ageing: checks validity of open case IOCs against OpenCTI indicator validity periods. Returns summary (active/expired/revoked/not_in_cti) and per-IOC detail.

Watchlist stored at `registry/cti_watchlist.json`.

### Session Management Endpoints

- `POST /api/sessions` — create a new session
- `GET /api/sessions` — list sessions (`?all=true` includes expired/materialised)
- `PATCH /api/sessions/{id}` — rename a session
- `DELETE /api/sessions/{id}` — delete a session
- `DELETE /api/sessions` — delete all sessions for the authenticated user

### Other Routes

- `GET /api/cases/{id}/chat-history` — returns display-friendly history for UI rendering

Action routes (`POST /api/cases/{id}/actions/{action}`) are **routed through Chief** — each action + parameters is translated into a natural language instruction by `_action_to_message()` and dispatched via `chat.chat()`. Exception: `action=auto` runs `ChiefAgent.run()` in a background thread via `JobManager`.

## UI Pages

### Chat (`ui/case.html`)

- Full-screen chat layout with collapsible left sidebar (case info, IOCs, verdicts, file upload)
- User messages right-aligned (blue), assistant messages left-aligned (markdown-rendered)
- Tool calls shown as collapsible green "action cards" inline between messages
- **Streaming response**: tokens appear incrementally as they arrive via SSE
- **Activity feed**: real-time tool execution indicators below the chat input — pulsing amber while running, green tick when complete
- **Case context banner**: when `load_case_context` is used in session mode, a green banner shows the loaded case ID, title, and severity; dismissible via "Clear context"
- Report overlay accessible from topbar link
- Enter to send, Shift+Enter for newline, file drag-and-drop in sidebar

### Cases Browse (`ui/cases.html`)

- Standalone read-only browse page for reviewing all past cases
- **Case overview section** at the top (above filters):
  - **Stat cards row**: total cases (with open/closed sub-text), open high/critical, malicious IOCs, active clusters
  - **Charts row**: severity donut (Chart.js doughnut) + cases over time (Chart.js bar)
  - Data sourced from `GET /api/landscape`; falls back to computing basic stats from browse data if landscape fails
- Responsive card grid with severity, status, and disposition badges
- Filter bar: severity dropdown, status dropdown, disposition dropdown, free-text search (client-side filtering)
- Each card shows: case ID, title, badges, relative timestamp, IOC count summary, link count, external refs
- Click a card to open the case detail page

### Case Detail (`ui/case-detail.html`)

- Read-only summary view for a single case, linked from the cases browse page
- **Case header**: case ID, title, severity/status/disposition badges, analyst, created date
- **IOCs panel**: grouped by type (IPs, domains, URLs, hashes, etc.), showing up to 10 per type with expandable overflow
- **Verdicts panel**: high priority (red), needs review (amber), clean (green) sections
- **Findings panel**: typed findings with summary and detail text
- **KQL Queries panel**: all queries from the investigation — tagged as "executed" (green, from `run_kql` tool calls with workspace) or "suggested" (blue, from ```kql code fences in assistant responses). Deduplicated.
- **Investigation Log panel**: standardised chronological timeline of investigation activity. Raw analyst text input is excluded — replaced by deterministic "action" entries derived from tool names/inputs (e.g. "Enriched IOCs against threat intelligence providers", "Executed KQL query (workspace: PER)"). Assistant analysis text is kept as-is (already standardised LLM-generated language). Entries are typed as `action` (blue badge) or `analysis` (purple badge).
- **Report panel**: markdown-rendered report excerpt (first 3000 chars, via marked.js)
- "Open in Chat" button navigates to `case.html?case={id}` for interactive follow-up

### Navigation

Dashboard and Cases pages share a common nav bar with: **Dashboard**, **Cases**, **Chat** (primary button), user email, and **Logout**. The Chat button links to `case.html`, which restores the last active session/case via `localStorage` (see Session Persistence above). The `investigate.html` form page is accessible directly but not in the nav bar.

### Dashboard (`ui/dashboard.html`)

CTI-focused threat intelligence dashboard. Case-level summaries (stat cards, charts) now live on the cases page.

- **Two-column layout** — Internal Intelligence (left) vs External Intelligence (right):
  - **Internal Intelligence** (from `GET /api/landscape`):
    - **Case Clusters panel**: linked case groups from `link_analysis.clusters`
    - **High-Risk Cross-Case IOCs table**: IOCs from `ioc_intelligence.high_risk_cross_case`
  - **External Intelligence** (from `/api/cti/*` endpoints):
    - **CTI Feed panel**: recent OpenCTI reports with linked threat actors (red tags), malware (amber), campaigns (blue), sectors (green). Filterable by time range and sector.
    - **Trending Indicators panel**: top indicators by score with colour-coded badges (red >= 70, amber >= 40, green < 40)
    - **MITRE ATT&CK Heatmap**: technique cells coloured by relationship count. Tactic-grouped columns when kill chain phases are populated; flat top-N grid otherwise.
    - **Threat Actor Watchlist**: analysts can pin actors to watch. Shows recent reports from OpenCTI per actor. Add/remove via input field. Stored in `registry/cti_watchlist.json`.
    - **IOC Decay panel**: summary stats (active/expired/revoked/not in CTI) for all open case IOCs checked against OpenCTI indicator validity. Per-IOC list with status dot indicators.
- **IOC Cross-Reference panel** (full-width, below the split): shows IOCs that appear in both internal cases and OpenCTI. Sourced from `GET /api/cti/ioc-xref`. Table columns: IOC value, type, internal cases, OpenCTI score, OpenCTI verdict. Only shows matched IOCs (those with an `opencti_score` or `opencti_verdict`).

### Session Persistence

The chat page persists the active session/case context in `localStorage` so navigating away (to Dashboard, Cases, etc.) and back resumes where you left off. Key behaviours:

- **Context key**: `socai_active_context_{email}` — scoped per user to prevent cross-user leaks on shared workstations
- **Saved on**: session creation (`ensureSession`), session resume, case switch, materialisation
- **Cleared on**: explicit "new session" (`/new` command or "new" button)
- **Restore flow** (on page load with no URL params):
  1. Read saved context from `localStorage`
  2. If `caseId` → try loading case history; if stale/404 → clear and fall through to welcome
  3. If `sessionId` → fetch session metadata; if materialised → switch to case mode; if active → resume session; if 404 → clear and fall through
  4. Fall-through → show welcome screen (no backend session created)
- **Lazy session creation**: navigating to the chat page without a saved context shows the welcome screen without creating a backend session. A session is only created when the user sends their first message (`ensureSession()`). This prevents accumulation of empty sessions.

Shared helpers (`getActiveContext`, `setActiveContext`, `clearActiveContext`) are defined in `ui/app.js`.

### Session Sidebar

A slide-out sidebar (hamburger menu in topbar) provides session management:

- **Session list** with search/filter
- **Resume** — click to reopen a previous session
- **Rename** — edit session title inline
- **Delete** — remove individual sessions
- **Clear all** — bulk-delete all sessions for the current user
- Sessions are colour-coded by status: active, materialised, expired

## Available Tools

### Case-Mode (22 tools)

`capture_urls`, `triage_iocs`, `enrich_iocs`, `detect_phishing`, `correlate`, `analyse_email`, `generate_report`, `generate_fp_ticket`, `generate_queries`, `campaign_cluster`, `security_arch_review`, `reconstruct_timeline`, `analyse_pe_files`, `yara_scan`, `correlate_event_logs`, `contextualise_cves`, `generate_executive_summary`, `add_evidence`, `read_case_file`, `run_full_pipeline`, `generate_mdr_report`, `load_kql_playbook`

### Session-Mode (31 tools)

All case-mode tools plus: `create_session`, `list_sessions`, `materialise_session`, `upload_file`, `set_disposition`, `get_session_context`, `rename_session`, `load_case_context`, `save_to_case`

### Case Context Switching (session-mode)

- **`load_case_context`** — loads an existing case's meta, IOCs, verdicts, and findings into the current session. Emits a `case_context_loaded` SSE event that triggers the UI context banner. Stores the loaded case ID in `session_context.json` as `loaded_case_id`.
- **`save_to_case`** — writes findings, IOCs, status, disposition, and/or notes back to a case. Merges IOCs (deduplicates), appends findings, updates meta fields.

## Case Visibility & Access Control

`_user_can_access_case()` in `api/main.py`:
- **Owner access** — user email matches `case_meta.analyst`
- **Admin access** — users with `admin` permission access all cases
- **Malicious case sharing** — cases with confirmed malicious findings visible to **all** authenticated users
- **Default** — non-malicious cases are private to their creator

Enforced on all case-specific endpoints.
