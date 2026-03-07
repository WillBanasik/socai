# Roadmap — Planned Features

## Tiered Incident Model (deferred — SOAR/Zoho integration phase)

### Context

The current data model is flat: each investigation is a **case**. Cases can be linked (duplicate, related, parent) via `tools/case_links.py` and grouped into clusters via `tools/campaign_cluster.py`. The dashboard shows these clusters visually.

The goal is a hierarchical model mirroring SOAR platforms:

```
Incident (SOAR incident / Zoho ticket)
  └── Investigation 1 (socai case)
        └── Alert 1 (SOAR alert)
              └── Events (SOAR/SIEM events)
  └── Investigation 2 (socai case)
        └── Alert 2
        └── Alert 3
  └── Investigation 3 (socai case)
        └── Alert 4
```

One incident may contain multiple investigations, run sequentially or in parallel. Each investigation maps to a socai case. Each case is triggered by one or more alerts, and alerts contain raw events.

### What this enables

- **Cross-investigation timeline**: visual representation of multiple linked investigations on a shared timeline, showing chronological progression and overlap
- **Drill-down**: dashboard view from incident → investigations → alerts → events, similar to SOAR UIs
- **Progress tracking**: contextualise progress across all investigations within an incident (e.g. "3 of 4 investigations closed, 1 pending enrichment")
- **Bi-directional sync**: socai disposition/findings pushed back to SOAR incident status and Zoho ticket; SOAR alert updates reflected in socai
- **Unified reporting**: incident-level executive summary aggregating findings from all child investigations

### Existing primitives to build on

| Primitive | Location | Role |
|-----------|----------|------|
| Case links (`parent` type) | `tools/case_links.py` | Parent case = incident container, children = investigations |
| Campaign clusters | `tools/campaign_cluster.py` | Groups cases sharing IOCs — natural incident candidates |
| Landscape clusters | `tools/case_landscape.py` | Cross-case cluster view for dashboard |
| Timeline reconstruction | `tools/timeline_reconstruct.py` | Per-case forensic timeline; extend to multi-case |
| Case context switching | `api/chat.py` `load_case_context` / `save_to_case` | Work on any case from a session |
| Dashboard clusters panel | `ui/dashboard.html` | Already renders linked case groups |

### Implementation plan (when SOAR/Zoho integration begins)

1. **Define incident entity** — schema based on SOAR's incident/alert model. Stored in `registry/incidents.json` or similar. Fields: incident_id, soar_ref, zoho_ticket, child_case_ids, status, created, resolved.

2. **Ingest from SOAR** — API endpoint or webhook receiver that creates incidents from SOAR alerts, auto-creates child cases, links them via parent link type.

3. **Multi-investigation timeline** — extend `reconstruct_timeline` to accept a list of case_ids and produce a merged chronological timeline. Dashboard component renders this as a horizontal swimlane chart (one lane per investigation).

4. **Drill-down UI** — dashboard incident card expands to show child investigations, each expandable to show alerts and key events. Uses existing case context summary endpoint for data.

5. **Zoho sync** — map incident lifecycle to Zoho ticket status. Push disposition, findings summary, and IOC counts. Pull ticket updates (comments, status changes).

6. **SOAR sync** — push case disposition back to SOAR incident. Mark alerts as investigated. Close SOAR incident when all child cases are resolved.

### Design constraints

- The incident model must **mirror the SOAR's hierarchy** — do not invent a parallel schema before understanding the SOAR's data model
- Zoho ticket structure (1:1 or 1:many mapping to incidents) must be confirmed before building sync
- All sync operations must be idempotent and handle partial failures gracefully
- The existing flat case model must continue to work independently — incidents are an optional grouping layer, not a replacement
