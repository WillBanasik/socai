# <Client Name> — Client Knowledge Base

> Persistent context about <Client>'s environment for SOC investigations.
> Populated from public OSINT (corporate site, filings, news, DNS, SPF, DMARC) + internal registry notes.
> Sections marked [INTERNAL] need populating from internal knowledge.
>
> ── HOW TO USE THIS TEMPLATE ──────────────────────────────────────────────
> • This is the canonical structure every `config/clients/<name>/knowledge.md` must follow.
>   It is NOT a client (the leading underscore keeps it out of the registry; client KBs are
>   read by exact path `CLIENT_PLAYBOOKS_DIR/<name>/knowledge.md`, never by globbing this dir).
> • Keep ALL `##` sections below, even when a section is mostly unknown — fill unknowns with
>   `[INTERNAL] confirm` rather than deleting the section, so gaps are visible and auditable.
> • Confidence language (mirrors `socai://analytical-standards`):
>     – State a fact plainly only when a source proves it (DNS lookup, filing, telemetry).
>     – Mark inference as "(assessed)"; mark DNS/web-derived items as confirmed-from-OSINT.
>     – Use `[INTERNAL] confirm` for anything only internal knowledge can settle
>       (UPN format, AD domain, privileged-account naming, exact EDR/CA posture).
> • Link related memories/KBs with `[[memory-name]]` where useful.
> • Delete this HOW-TO block in real client files.
> ──────────────────────────────────────────────────────────────────────────

---

## Organisation

- **Full name:** <legal entity / holding co>
- **Industry:** <sector — be specific>
- **HQ:** <address / city, country>
- **Size:** <employees; key scale metric — sites, customers, AUM, rooms, beds, etc.>
- **Founded:** <year>
- **Ownership / Listing:** <private / listed (exchange + ticker) / parent group / major shareholders>
- **Aliases:** <all aliases — must match `config/client_entities.json`; note any deliberate disambiguation-gate aliases>
- **Geography:** <countries / regions of operation>
- **Segments / Brands:** <business units, trading brands, subsidiaries>
- **Regulatory:** <data-protection + sector regulators that shape obligations>

---

## Identity & Access

- **Primary email domain:** <domain>
- **Other / subsidiary domains:** <list>
- **M365 / tenant:** <tenant name; Entra ID vs hybrid> — [INTERNAL] confirm
- **UPN format:** `user@<domain>` — [INTERNAL] confirm
- **AD domain:** <NETBIOS / FQDN> — [INTERNAL] confirm
- **MFA / SSO:** <Entra ID, Duo, Okta, etc.> — [INTERNAL] confirm CA posture
- **Privileged access / PAM:** <Wallix, Delinea, CyberArk, naming convention> — [INTERNAL]

---

## Network Topology

### DNS & Web

- **Authoritative NS:** <registrar / DNS provider>
- **Apex A / hosting:** <IPs / CDN / cloud>

### Mail Flow

- **MX:** <gateway — Mimecast / Proofpoint / Exchange Online direct / etc.>
- **SPF:** `<record>` — note each include and what it is (gateway, marketing, sigs, phishsim)
- **DMARC:** `<record>` — state posture (p=none weak / p=quarantine / p=reject strong) and the spoofing implication
- **DKIM / MTA-STS / TLS-RPT:** <as observed>

### Known Domains

| Domain | Purpose | Notes |
|---|---|---|
| `<domain>` | <primary / marketing / subsidiary / tenant> | <DNS, mail, DMARC posture> |

---

## Security Stack

- **Email security:** <gateway + Defender/3rd-party>
- **EDR/XDR:** <CrowdStrike Falcon (region) / Defender for Endpoint / etc.>
- **SIEM:** <Sentinel (workspace id) / CrowdStrike NG-SIEM (LogScale, region) / none>
- **Network / NGFW / NDR:** <FortiGate, Palo Alto, Check Point, F5, Darktrace, etc.>
- **Identity / Cloud security / SSE:** <Duo, ISE, Netskope, Zscaler, Cloudflare ZT, etc.>
- **Encore:** internal client id `<uuid>` (<access>)
- **Other (from data sources):** <notable connectors>
- See `registry/ngsiem_connectors/<client>.json` for the full `@dataConnectionID` list (NG-SIEM clients).
- **Identity containment authority:** `<performanta_delegated | client_actioned>` — [INTERNAL] confirm
  (`platforms.identity_response` in `client_entities.json`). `performanta_delegated` = we hold
  Entra/Defender identity-action delegation + SOP cover, so the analyst can reset passwords and
  revoke sessions (client does MFA reset / disable / OAuth-grant revoke). `client_actioned` = all
  identity actions go to the client. A policy fact — never inferred from integration presence.
  See `socai://containment-authority`.
- **Identity action integration:** `<entra (default) | netiq>` — [INTERNAL] confirm
  (`platforms.identity_integration`). `netiq` fuses password reset + session revoke into one
  non-separable combined action (the two cannot be actioned independently). Only relevant when
  `identity_response = performanta_delegated`.

---

## Known Legitimate Software & Services

Observed-legitimate identities/senders/agents — treat as known relationships, not IOCs:

- <SaaS, vendors, group/parent tenants, marketing senders, scanners, line-of-business apps>
- <phishing-simulation platform if any — flag the BP implication>

---

## Historical Patterns

### Known Incidents / Case History

- <socai case refs (IV_CASE_xxx) + one-line outcome; link `[[memory]]` where one exists>
- <public breaches if any; else "No publicly disclosed external breach at time of writing.">
- <sector threat context — who targets this industry and how>

### Expected FP / Baseline Patterns

- <recurring benign patterns: VPN egress, multi-country auth, scanner traffic, phishsim, housekeeping>
- <query-language note: KQL (Sentinel) vs CQL/LogScale (NG-SIEM)>

---

## Active Engagements

> Optional — include only when there is live authorised activity (pentest, migration, DR test)
> that changes verdicts. Capture: provider, scope, dates, sanctioned accounts/OUs/VPN groups,
> and the TP-vs-BP discriminator. Remove the section when none is active.

---

## Response Process

> Optional but recommended — how this client wants incidents handled.
> Prefer the live source over a local copy.

- **Source:** `PerformantaLab/mdr_soar` → `client_response_templates/<client>.json` (fetched live)
- **Notification channel / SLA:** <channel, hours>
- **Containment authority (GitHub overrides capability):** <pre-approved actions vs confirm-first;
  hypercare = notify-only>. This GitHub response process is the **authority of record** — it
  overrides the `identity_response` capability above and can only *restrict* it (set the template's
  top-level `containment_policy`: `pre_approved` | `confirm_first` | `prohibited`). See
  `socai://containment-authority`.
- **Contacts (P1/P2):** see live template

---

## Analyst Notes

- <the 3–6 load-bearing things an analyst must know before triaging this client>
- <query language, disambiguation gates, domain/logon quirks, posture caveats, remediation specifics>
