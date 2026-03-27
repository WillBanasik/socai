# OpenCTI Integration — Read & Write

## Read: Deep Report Queries (Implemented)

The `query_opencti` tool supports a `report_id` parameter for deep report fetches. When provided, it returns the full report bundle via parameterised GraphQL:

- Full description (listing results capped at 2000 chars; detail view uncapped)
- `report_types`, `confidence`, `published`
- `createdBy` (author), `objectMarking` (TLP markings)
- `externalReferences` (source URLs, vendor advisories)
- `objects` traversal (up to 500): indicators with patterns, threat actors with aliases, malware, attack patterns with MITRE IDs, campaigns, vulnerabilities, infrastructure, observables

**Usage:** Search with `query_type=report` to find reports, then pass the `id` to `report_id` for the full bundle.

**Code:** `_opencti_report_detail()` in `mcp_server/tools.py`.

## Write: Article → OpenCTI Publishing Pipeline

### Workflow

| Step | Tool | What happens |
|---|---|---|
| 1. Discover | `search_threat_articles` | RSS candidates with dedup (article index + Confluence + OpenCTI title overlap) |
| 2. Write | `write_threat_article` prompt | Analyst writes article locally |
| 3. Save | `save_threat_article` | Persists to `articles/`, updates index |
| 4a. Manual | `generate_opencti_package` | HTML file with labelled sections for manual OpenCTI posting |
| 4b. Auto | `post_opencti_report` | Pushes STIX bundle via `bundleCreate` (requires `SOCAI_OPENCTI_PUBLISH=1`) |

### Dedup Gates

| Gate | Where | How |
|---|---|---|
| Article index | `_is_covered()` | SHA-256 fingerprint of normalised title |
| Confluence | `_is_covered_confluence()` | Stemmed token overlap >= 40% |
| OpenCTI | `_is_covered_opencti()` | Stemmed token overlap >= 40% against recent report titles |
| Manifest | `check_before_publish()` | Refuses if `opencti_report_id` already set |

### STIX Bundle Contents

`build_stix_bundle()` in `tools/opencti_publish.py` generates:

- **Report SDO** — article text, external references (source URLs)
- **Indicator SDOs (STIX)** — one per extracted IOC (domains, IPs, hashes, emails)
- **Indicator SDOs (KQL)** — Sentinel/Defender hunt queries per IOC type, named `[HUNT] <title> — <type>`
- **Indicator SDOs (LogScale)** — CrowdStrike/NGSIEM hunt query, named `[HUNT] <title> — LogScale IOC hunt`
- **Observable SCOs** — raw IOC values (domain-name, ipv4-addr, file, email-addr)
- **Vulnerability SDOs** — one per extracted CVE
- **Relationship SROs** — linking indicators to the report

Hunt queries are linked to their parent report via `object_refs`, distinguishing them from standing detection queries (`[DEFENDER]`/`[SENTINEL]`) which are unlinked.

### Posting Package (Manual Flow)

`generate_opencti_package(article_id)` produces an HTML file with labelled sections:

1. Report description and metadata (name, type, published date, TLP, external reference)
2. Observable blocklists (domains, IPs, hashes, URLs, emails) — one per line for bulk paste
3. STIX IOC indicators table (name + pattern)
4. KQL hunt queries (pattern_type: kql)
5. LogScale hunt queries (pattern_type: logscale)
6. Full STIX bundle JSON (collapsible, for future automation)

### Config Flags

| Env Var | Default | Effect |
|---|---|---|
| `SOCAI_OPENCTI_PUBLISH` | `0` | Enable `post_opencti_report` and auto-publish |
| `SOCAI_ARTICLE_AUTO_DISCOVER` | `` | `daily` or `weekly` — scheduled RSS candidate fetch |
| `SOCAI_ARTICLE_AUTO_PUBLISH` | `0` | Auto-push unpublished articles to OpenCTI (requires publish enabled) |

### Article Manifest Fields

Articles track OpenCTI state in their manifest:

```json
{
  "opencti_report_id": null,
  "opencti_url": null,
  "published_at": null
}
```

Set by `publish_report()` after successful `bundleCreate`. Prevents double-posting.
