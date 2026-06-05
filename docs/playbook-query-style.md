# Playbook Query Style — summarise first, then pivot

Guidance for the KQL (`config/playbooks/<id>/sentinel/*.kql`,
`config/kql_playbooks/**/*.kql`) and CQL (`config/playbooks/<id>/logscale/*.cql`)
query bodies that back the investigation playbooks. Enforced by
`tests/test_playbook_query_shape.py`.

## The principle

An investigation query should hand the analyst a **compact overview first**, and
let them **pivot to raw event rows only when a specific entity warrants it**. A
broad triage stage that returns thousands of raw rows is expensive (every row
crosses the MCP transport into the model's context — see the 74 KB `EmailEvents`
dump in case IV_CASE_167) and buries the signal.

Two shapes are acceptable; a third is not:

| Shape | When | Example terminal op |
|-------|------|---------------------|
| **SUMMARY** (preferred for triage/scope stages) | Early, broad stages. Collapse rows into counts/rollups. | KQL `summarize … by …`, `make-series`, `count()`, `dcount`, `top N by`, `arg_max(…) by`; CQL `groupBy([…])`, `bucket()`, `timeChart()`, `stats()`, `top()` |
| **BOUNDED** (acceptable for pivot/detail stages) | Later stages scoped to a specific user/host/IOC the summary surfaced. | raw rows **with** an explicit cap: KQL `\| take N`; CQL `sort(…, limit=N)` or `\| head(N)` |
| **RAW-DUMP** (not allowed) | — | raw rows from a broad filter with **no** aggregation and **no** cap |

## Rules

1. **Every stage query must terminate in either an aggregation or an explicit row
   cap.** No stage may return raw rows from a broad filter uncapped. Default cap:
   **200** (matches the existing CQL `limit=200` convention).
2. **Triage/scope stages (the early, broad ones — stage 0/1, or any stage whose
   `run` condition is "always") should be SUMMARY**, not merely capped. An analyst
   should see "how much / by whom / from where" before any raw rows.
3. **Pivot/detail stages may be BOUNDED** raw rows — but only when scoped to a
   specific entity (a single user/host/IOC carried over from an earlier summary).
4. **CQL caps are per-sub-query.** A stage file split by `// --- Sub-query X ---`
   markers runs each block independently, so **each** block needs its own cap or
   aggregation — a `head(50)` on sub-query C does not protect sub-query A.
5. **Never dump a high-volume table raw.** Treat these as summary-only at triage:
   `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`, `CloudAppEvents`,
   `OfficeActivity`, `SigninLogs` / `AADSignInEventsBeta` /
   `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`,
   `MicrosoftGraphActivityLogs`, `DeviceProcessEvents`, `DeviceNetworkEvents`,
   `DeviceFileEvents`, `DeviceRegistryEvents`, `SecurityEvent`, `CommonSecurityLog`
   (KQL); `ProcessRollup2`, `NetworkConnectIP4`, `NetworkReceiveAcceptIP4`,
   `DnsRequest` (CQL).
6. **Scope before you sweep.** A query that pulls "all sign-ins / all SP sign-ins /
   all Graph activity / all permission changes" for a tenant must carry an entity
   filter (UPN, AppId/ServicePrincipalName, IP) before it runs — an unscoped
   tenant-wide pull is both a payload problem and a relevance/exposure problem.
7. **Match identity fields exactly; reserve `has` for true terms.** KQL `has` is
   whitespace/term-delimited, so `UserId has "adil.khan@x.com"` (or `has "adil"`)
   silently misses dotted/email values — a false-negative on the exact pivot that
   matters. Use `=~` (or `in (...)`) for UPN / email / host identity fields, and
   `contains` for substring searches over free-text blobs (e.g. `Entities`). The
   same trap applies in CQL — prefer an exact match on identity fields.

## This is *not* the "no slimming" rule in reverse

`CLAUDE.md` forbids **slimming tool returns** — silently dropping rows from a
result the model already fetched. That is a different layer. Summarise-first is a
**query-design** choice: you ask the SIEM to aggregate, then return that aggregate
**in full** (no slimming of the aggregate), with a deliberate, documented raw-row
pivot as a separate stage. One loses evidence silently; the other is an explicit
analytical step with a defined drill-down path.

## Runtime backstop is not a substitute

The MCP `run_kql` wrapper auto-appends `| take 50` (single) / `| take 1000`
(batch) when a query carries no cap. That bounds the worst case but (a) 1000 raw
rows still busts context, and (b) it is invisible in the query body. Put the cap
**in the query** so the intent is explicit and survives any execution path.

## Exemplars to copy

- **Threshold-aggregation triage:** `reconnaissance` stage 1/2 — `summarize
  FailedAttempts=count(), DistinctUsers=dcount(...) by IPAddress, bin(…,1h) | where
  DistinctUsers >= 5`.
- **Behavioural rollup:** `command-and-control` stage 1 (beaconing jitter),
  `ransomware` stage 2 (files-per-interval).
- **Network groupBy:** `vulnerability-hunting` stage 3, `web-shell` CQL stage 3
  sub-query B — `groupBy([… RemoteIP, RemotePort], function=[count(...), min, max])`.
- **Campaign-scope collapse:** `phishing`/`bec` stage 0 — one summary row per
  (sender, subject) with message/recipient/click counts and the MessageId set.
- **Sign-in fingerprint:** `suspicious-signin` S2/S4 — `summarize count(),
  make_set(AppDisplayName), make_set(RiskLevel) by IPAddress, City, Country, UPN`.
