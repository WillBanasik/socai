# Web UI — LLM Chat Interface

The web UI is a **Svelte 5 SPA** (`frontend/src/` → built to `ui-dist/`). Analysts type natural language and Chief (the LLM agent) interprets intent and dispatches tools via Claude's `tool_use` API.

## Backend: `api/chat.py`

- `TOOL_DEFS` — 44 tool definitions for case-mode chat (22 case-only + 22 shared)
- `SESSION_TOOL_DEFS` — 52 tool definitions for session-mode chat (30 session-only + 22 shared); composed dynamically from `_SESSION_ONLY_DEFS + [d for d in TOOL_DEFS if d["name"] in _SHARED_TOOL_NAMES]`
- `_dispatch_shared(tool_name, tool_input, case_id, perms, *, session_id=None)` — handles 22 tools that run identically in both modes; returns `None` if the tool is not shared, causing fall-through to mode-specific dispatch. `session_id` is passed from `_dispatch_session_tool()` for upload path resolution (e.g. `start_sandbox_session` resolves filenames against `sessions/<id>/uploads/`)
- `_dispatch_tool()` / `_dispatch_session_tool()` — mode-specific dispatchers; both call `_dispatch_shared` first, then handle mode-specific tools. `_dispatch_session_tool` resolves the session's case_id once at the top and passes it to all tools.
- `build_system_prompt(case_id)` — loads case metadata + artefact summary, uses prompt caching (`cache_control: ephemeral`)
- `chat(case_id, user_message, history)` — multi-turn tool loop (up to 10 rounds)
- `chat_stream(case_id, user_message, history)` — streaming variant yielding SSE events
- `session_chat_stream(session_id, user_message, history)` — streaming session-mode chat
- `execute_tool(case_id, tool_name, tool_input)` — dispatches to `api/actions.py`, returns `_message` strings
- `read_case_file(case_id, file_path)` — lets Claude read any case artefact on demand (traversal-safe)
- Chat history is **per-user per-case**: stored at `cases/{id}/chat_history_{email}.json` in Anthropic API message format
- History trimming: `_trim_for_api()` sends only last 20 messages to API (full history saved to disk), with orphaned `tool_result` cleanup and tool result truncation to 3000 chars
- **Compaction** (Opus models): when enabled, uses API-side context compaction instead of hard message truncation, preserving earlier conversation context

### Session-Mode Auto-Case Creation

Every session auto-creates a case at session start. The case ID is stored in both the session metadata and context, and is immediately available for all tool calls. `_session_ensure_backing_case()` is a simple lookup (with a legacy fallback for pre-existing sessions).

**Sample path resolution:** `start_sandbox_session` resolves relative filenames against upload directories — first `sessions/<id>/uploads/`, then `cases/<id>/uploads/`. If the file is not found, the response lists available files. This mirrors the pattern used by `analyse_telemetry` and `read_uploaded_file`.

**Backing case notification:** `start_sandbox_session` and `stop_sandbox_session` include `backing_case_id` in their results and mention the target case in `_message`, so the analyst knows where artefacts are being written.

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
- `done` — final summary with full reply, tool call list, and `usage` (input/output token counts)
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

### Preferences Endpoints

- `GET /api/preferences` — load per-user preferences (analyst name, custom instructions, response style, pinned sessions, session tags)
- `PUT /api/preferences` — partial-merge update of preferences
- `POST /api/preferences/pin/{session_id}` — pin a session
- `DELETE /api/preferences/pin/{session_id}` — unpin a session
- `PUT /api/preferences/tags/{session_id}` — set tags for a session (form: JSON body with `tags` array)

Preferences stored as JSON in `config/preferences/<email_hash>.json`. Custom instructions capped at 2000 chars. Valid response styles: `concise`/`detailed`/`formal`. Model selection is handled automatically by the agent tier system.

### Session Management Endpoints

- `POST /api/sessions` — create a new session with auto-created case (accepts optional `{"reference_id": "..."}` body)
- `GET /api/sessions` — list sessions (`?all=true` includes expired/finalised)
- `GET /api/sessions/search` — search across session titles, IOCs, findings, and tags (query param: `q`)
- `PATCH /api/sessions/{id}` — rename a session
- `DELETE /api/sessions/{id}` — delete a session
- `DELETE /api/sessions` — delete all sessions for the authenticated user
- `POST /api/sessions/cleanup` — delete all non-finalised sessions for the user (used on logout)
- `GET /api/sessions/{id}/threads` — list investigation threads with IOC/finding summaries
- `GET /api/sessions/{id}/export` — export session as Markdown (messages, tool calls, metadata)
- `POST /api/sessions/{id}/pivot` — create a new thread (no label)
- `POST /api/sessions/{id}/pivot-with-label` — create a new thread with label (form: `label`)
- `POST /api/sessions/{id}/threads/{tid}/activate` — switch active thread
- `GET /api/sessions/{id}/history?thread=` — filter history by thread (omit for active, `all` for everything)

### Other Routes

- `GET /api/cases/{id}/chat-history` — returns display-friendly history for UI rendering

Action routes (`POST /api/cases/{id}/actions/{action}`) are **routed through Chief** — each action + parameters is translated into a natural language instruction by `_action_to_message()` and dispatched via `chat.chat()`. Exception: `action=auto` runs `ChiefAgent.run()` in a background thread via `JobManager`.

## UI Pages (Svelte SPA)

The frontend is a Svelte 5 SPA built with Vite and Tailwind CSS 4. Source lives in `frontend/src/`, built output in `ui-dist/`. Hash-based routing (`#/dashboard`, `#/cases`, `#/session/{id}`, `#/chat/{caseId}`, `#/case/{caseId}`).

### Chat (`ChatView.svelte`)

- Full-screen chat layout with persistent left sidebar (sessions, recent cases)
- User messages right-aligned, assistant messages left-aligned (markdown-rendered via `MarkdownBlock.svelte`)
- Tool calls shown as `ToolCard.svelte` cards inline between messages (expandable for raw input/result)
- **Streaming response**: tokens appear incrementally as they arrive via SSE (`StreamingText.svelte`)
- **Activity feed**: `ActivityFeed.svelte` — same card style as ToolCard (agent name + task description + input summary), with status dot (amber pulsing = running, green = done, red = error). Transitions to ToolCard in the final message.
- **Case context banner**: `MaterialiseBanner.svelte` — when `load_case_context` is used in session mode, a banner shows the loaded case ID, title, and severity
- Enter to send, Shift+Enter for newline, file drag-and-drop (`FileUploadPill.svelte`)
- **Welcome screen**: `WelcomeScreen.svelte` — minimal branding + hint to use `/help` and `/prompts`, with context-aware `SuggestionChips.svelte` (adapts to session state — starter prompts, enrichment, disposition, IOC extraction)
- **Message actions**: hover to reveal edit (user messages) or regenerate (last assistant message) buttons. Edit opens inline textarea; regenerate re-sends from the last user message.
- **Token usage**: cumulative input/output tokens displayed in `StatusBar.svelte` (bolt icon with formatted count). Updated from `done` SSE events.
- **Slash commands**: client-side interception of `/help`, `/clear`, `/new`, `/pivot`, `/threads`, `/thread`, `/context`, `/uploads`, `/status`, `/prompts`, `/export` — never sent to the API

### Cases Browse (`CasesBrowse.svelte`)

- Standalone read-only browse page for reviewing all past cases
- **Case overview section** at the top (above filters):
  - **Stat cards row** (`StatCards.svelte`): total cases (with open/closed sub-text), open high/critical, malicious IOCs, active clusters
  - **Charts row**: severity donut (`SeverityDonut.svelte`) + cases over time (`CasesTimeline.svelte`)
  - Data sourced from `GET /api/landscape`; falls back to computing basic stats from browse data if landscape fails
- Responsive card grid (`CaseCard.svelte`) with severity, status, and disposition badges
- Filter bar (`CaseFilterBar.svelte`): severity dropdown, status dropdown, disposition dropdown, free-text search (client-side filtering)
- Each card shows: case ID, title, badges, relative timestamp, IOC count summary, link count, external refs
- Click a card to open the case detail page

### Case Detail (`CaseDetail.svelte`)

- Read-only summary view for a single case, linked from the cases browse page
- **Case header**: case ID, title, severity/status/disposition badges, analyst, created date
- **IOCs panel** (`IOCPanel.svelte`): grouped by type (IPs, domains, URLs, hashes, etc.), showing up to 10 per type with expandable overflow
- **Verdicts panel** (`VerdictPanel.svelte`): high priority (red), needs review (amber), clean (green) sections
- **Findings panel** (`FindingsPanel.svelte`): typed findings with summary and detail text
- **KQL Queries panel** (`KQLPanel.svelte`): all queries from the investigation — tagged as "executed" (green, from `run_kql` tool calls with workspace) or "suggested" (blue, from ```kql code fences in assistant responses). Deduplicated.
- **Investigation Log panel** (`InvestigationLog.svelte`): standardised chronological timeline of investigation activity. Raw analyst text input is excluded — replaced by deterministic "action" entries derived from tool names/inputs (e.g. "Enriched IOCs against threat intelligence providers", "Executed KQL query (workspace: PER)"). Assistant analysis text is kept as-is (already standardised LLM-generated language). Entries are typed as `action` (blue badge) or `analysis` (purple badge).
- **Report panel** (`ReportPanel.svelte`): markdown-rendered report excerpt (first 3000 chars)
- "Open in Chat" button navigates to `#/chat/{caseId}` for interactive follow-up

### Settings (`SettingsView.svelte`)

User preferences page accessible via sidebar nav or Ctrl+, shortcut:

- **Profile section**: analyst display name
- **Response style**: radio buttons — concise / detailed / formal. Injected into system prompt as personalisation.

- **Custom instructions**: textarea (2000 char limit with counter). Appended to system prompt for all sessions.
- **Keyboard shortcuts**: reference grid of all shortcuts (`KeyboardShortcuts.svelte`)
- **Integration status**: read-only info panel showing connected services

Preferences stored per-user via `api/preferences.py` (hashed email filenames in `config/preferences/`).

### Navigation

All pages share the `AppShell.svelte` layout with a persistent `Sidebar.svelte` (left) and `Topbar.svelte` (top). The sidebar shows: **Dashboard**, **Cases**, **Investigate**, **Settings** nav links, a **Search box** (debounced, searches across session titles/IOCs/findings/tags), **Pinned sessions** (star/unstar toggle), a **Sessions** list with per-session delete and pin buttons, and a **Recent Cases** list (sorted by creation time). `CommandPalette.svelte` provides Ctrl+K quick navigation.

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+K | Command palette |
| Ctrl+B | Toggle sidebar |
| Ctrl+\\ | Toggle context panel |
| Ctrl+, | Open settings |
| Ctrl+/ | Show shortcuts overlay |
| Enter | Send message |
| Shift+Enter | New line |

Shortcut overlay shown via Ctrl+/ or command palette. Dismissable with Esc or click-outside.

### Dashboard (`DashboardView.svelte`)

CTI-focused threat intelligence dashboard. Case-level summaries (stat cards, charts) now live on the cases page.

- **Two-column layout** — Internal Intelligence (left) vs External Intelligence (right):
  - **Internal Intelligence** (`InternalIntel.svelte`, from `GET /api/landscape`):
    - **Case Clusters panel**: linked case groups from `link_analysis.clusters`
    - **High-Risk Cross-Case IOCs table**: IOCs from `ioc_intelligence.high_risk_cross_case`
  - **External Intelligence** (from `/api/cti/*` endpoints):
    - **CTI Feed panel** (`CTIFeed.svelte`): recent OpenCTI reports with linked threat actors (red tags), malware (amber), campaigns (blue), sectors (green). Filterable by time range and sector.
    - **Trending Indicators panel** (`TrendingIndicators.svelte`): top indicators by score with colour-coded badges (red >= 70, amber >= 40, green < 40)
    - **MITRE ATT&CK Heatmap** (`AttackHeatmap.svelte`): technique cells coloured by relationship count. Tactic-grouped columns when kill chain phases are populated; flat top-N grid otherwise.
    - **Threat Actor Watchlist** (`Watchlist.svelte`): analysts can pin actors to watch. Shows recent reports from OpenCTI per actor. Add/remove via input field. Stored in `registry/cti_watchlist.json`.
    - **IOC Decay panel** (`IOCDecay.svelte`): summary stats (active/expired/revoked/not in CTI) for all open case IOCs checked against OpenCTI indicator validity. Per-IOC list with status dot indicators.
- **IOC Cross-Reference panel** (`IOCXRef.svelte`, full-width, below the split): shows IOCs that appear in both internal cases and OpenCTI. Sourced from `GET /api/cti/ioc-xref`. Table columns: IOC value, type, internal cases, OpenCTI score, OpenCTI verdict. Only shows matched IOCs (those with an `opencti_score` or `opencti_verdict`).

### Investigate (`InvestigateView.svelte`)

Form-based investigation launcher with file drop zone (`FileDropZone.svelte`) and IOC preview (`IOCPreview.svelte`). Accessible from the sidebar nav.

### Investigation Threads (context scoping)

Each session supports multiple **investigation threads** — isolated context partitions within a single session. Each thread has its own IOCs, findings, telemetry, and conversation history. The LLM only sees the active thread's history and context, preventing topic bleed when pivoting between investigations.

- **`/pivot [label]`** — create a new thread (sets it active, clears chat display)
- **`/threads`** — list all threads with IOC/finding counts
- **`/thread <N>`** — switch to thread N (reloads that thread's history)
- **`/context`** — shows the active thread's context
- **System prompt** — includes active thread detail + brief summaries of other threads
- **Finalisation** — merges all threads' IOCs and findings into the case

Backend: threads stored in `sessions/<id>/context.json` under `threads` dict. History messages tagged with `thread_id` and filtered before API calls. Backwards-compatible — old sessions auto-migrate to a single default thread.

### Session Lifecycle

Sessions are lazily created — no session exists until the analyst sends their first real message (slash commands are handled client-side and don't create sessions). Every session auto-creates a case at start. Key behaviours:

- **No session on login** — the welcome screen shows immediately with no backend session
- **Lazy creation** — `POST /api/sessions` is called in `ChatView.handleSend()` only when there is no active session or case
- **Auto-case creation** — every session creates a case immediately, visible in the case ID shown in the session prompt. Optional `reference_id` for SOAR/service desk linking.
- **Finalisation** — when the analyst sets a disposition, `finalise_case` syncs all context to the case and marks the session `finalised`. Finalised sessions are preserved permanently. Alternatively, generating an MDR report, PUP report, or FP ticket auto-closes the backing case (the session itself remains active until explicitly finalised or cleaned up on logout).
- **Logout cleanup** — `Topbar.logout()` calls `POST /api/sessions/cleanup` which deletes all non-finalised sessions. Finalised sessions are preserved as they are linked to cases.
- **Routing**: `#/session/{sessionId}` for sessions, `#/chat/{caseId}` for cases — bookmarkable, shareable
- **Stores**: `activeSessionId` and `activeCaseId` in `lib/stores/navigation.ts`
- **Session list**: `sessionList` store populated on mount via `listSessions()` API call

### Session Sidebar (`Sidebar.svelte`)

The persistent left sidebar provides session management:

- **Search box** — debounced (300ms) search across session titles, IOCs, findings, and tags via `GET /api/sessions/search`. Results shown in dropdown with match fields and relative timestamps.
- **Pinned sessions** — starred sessions appear at the top. Toggle via star icon on hover or `POST/DELETE /api/preferences/pin/{id}`.
- **Session list** with per-session delete (×) and pin (star) buttons — always visible
- **Resume** — click a session to navigate to `#/session/{id}`
- **Delete** — remove individual sessions via × button (calls `DELETE /api/sessions/{id}`)
- **Clear all** — bulk-delete all sessions for the current user (appears when > 1 session)
- **`/new` command** — creates a fresh session (previous session stays in sidebar)

**Session naming:** Each session displays its title based on state:
- **"new investigation"** (italic) — default for sessions that haven't been titled yet
- **Custom title** — if the session has been renamed or finalised (e.g. "IV_CASE_043 — phishing investigation")
- **Relative timestamp** — e.g. "39m ago", "1h ago" via `relativeTime()` utility

### Topbar (`Topbar.svelte`)

- **Context label**: blank while in session mode, shows case ID (purple accent) when in case mode, shows page name for other views
- **Sidebar toggle**: hamburger menu button (Ctrl+B)
- **Token usage**: bolt icon with formatted cumulative session tokens (e.g. "12.3k") and breakdown tooltip
- **Logout**: cleans up non-finalised sessions before clearing auth token

## Available Tools

### Shared Tools (22 — defined once in `TOOL_DEFS`, available in both modes)

`assess_landscape`, `link_cases`, `merge_cases`, `recall_cases`, `run_kql`, `load_kql_playbook`, `ingest_velociraptor`, `ingest_mde_package`, `memory_dump_guide`, `analyse_memory_dump`, `start_browser_session`, `stop_browser_session`, `list_browser_sessions`, `start_sandbox_session`, `stop_sandbox_session`, `list_sandbox_sessions`, `sandbox_exec`, `search_threat_articles`, `generate_threat_article`, `list_threat_articles`, `list_confluence_pages`, `web_search`

### Case-Only Tools (22)

`capture_urls`, `triage_iocs`, `enrich_iocs`, `detect_phishing`, `correlate`, `analyse_email`, `generate_report`, `generate_mdr_report`\*, `generate_pup_report`\*, `generate_fp_ticket`\*, `generate_queries`, `campaign_cluster`, `security_arch_review`, `reconstruct_timeline`, `analyse_pe_files`, `yara_scan`, `correlate_event_logs`, `contextualise_cves`, `generate_executive_summary`, `add_evidence`, `read_case_file`, `run_full_pipeline`

\* **Auto-close on collection:** `generate_mdr_report`, `generate_pup_report`, and `generate_fp_ticket` auto-close the case on successful generation (see `docs/pipeline.md` § Auto-close on Deliverable Collection).

### Session-Only Tools (30)

`analyse_telemetry`, `read_uploaded_file`, `extract_iocs`, `add_finding`, `finalise_case`, `generate_fp_comment`, `generate_mdr_report`, `generate_pup_report`, `load_case_context`, `save_to_case`, plus session-specific variants of case tools (e.g. `capture_urls` saves IOCs to session context, `enrich_iocs` works from session context, `detect_phishing` records findings in session context)

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
