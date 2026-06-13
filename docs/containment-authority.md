# Containment & Remediation Authority

> Who actions a containment or remediation step for a given client — the SOC
> (Performanta analyst) or the client. This is a **general rule of thumb**
> derived from platform access. The per-client **GitHub response process**
> (`PerformantaLab/mdr_soar` → `client_response_templates/<client>.json`) is the
> authority of record and **overrides** everything below; it can only ever
> *restrict*, never expand. Served live as `socai://containment-authority`.

## Two layers, GitHub wins

1. **Capability (this document, the default)** — what we are *technically able*
   to do, derived from the client's platform / identity-plane access recorded in
   `config/client_entities.json` → `platforms`. This is the rule of thumb.
2. **Authorisation (per-client GitHub response process)** — what we are
   *permitted* to do, agreed with the client. Applied last in
   `response_actions`; on any conflict the GitHub process **wins** and can only
   downgrade capability (e.g. notify-only, confirm-first, "do not contain").

Worked example: for a client where we hold Defender XDR access, the capability
layer says we *could* contain — but if their GitHub response process says "must
not contain anything", the final plan is **notify-only, no SOC action**.
Capability = what we *can* do; GitHub = what we *may* do.

## Identity containment — split by `platforms.identity_response`

The determinant is **identity-plane access**, not the EDR brand. A Falcon-EDR
client can still be on Entra; the rule turns on whether we hold Entra/Defender
identity-action delegation **and** SOP cover — a policy fact, set explicitly per
client in `platforms.identity_response`, never inferred from integration
presence (SIEM/log-read access ≠ identity-action delegation).

Concretely: **a Sentinel workspace does not by itself confer the delegation
plane.** A client can use Sentinel as SIEM while its identity/endpoint plane is
Falcon (not Defender/Entra) — log ingestion gives us no identity-action
delegation, so it is `client_actioned` despite having a Sentinel workspace
(e.g. `glumutual`: Sentinel SIEM + Falcon EDR → `client_actioned`). Delegation
comes from a Microsoft identity/endpoint plane we hold, not from where logs land.

### `performanta_delegated` — we hold the delegation + SOP cover

| Identity action | Who actions it |
|---|---|
| Reset password | **SOC analyst** |
| Revoke sessions (≡ revoke refresh tokens) | **SOC analyst** |
| Reset / re-register MFA | Client |
| Disable account | Client |
| Revoke OAuth / app-consent grant | Client |

Per SOP the analyst's identity authority is **password reset + session
revocation only**. Everything that changes the account's standing (MFA reset,
disable, OAuth-grant revoke) is client remediation.

**Note on session revoke:** Entra "Revoke sessions" (`revokeSignInSessions`)
works *by* invalidating refresh tokens — there is no separate analyst
"revoke refresh token" control; the two are the same action. Already-issued
**access tokens** (short-lived, ~1 h) keep working until they expire, so revoke
stops *renewal*, not the current access token — it is not an instant hard-kill.

**Integration variant — `platforms.identity_integration`:** where a delegated
client actions identity through a different mechanism, set `identity_integration`
to flag it. `netiq` (e.g. University of Portsmouth) does **not** reset+revoke —
the SOC's single containment action **strips the account's security
(authentication) information**, which hard-blocks the user (they can no longer
authenticate); it is **not reversible by the SOC**. Recovery is **client-only**:
the local service desk re-adds the security information and re-enables the
account. So for NetIQ both sides are overridden — SOC = "block via NetIQ (strip
sec info)", client = "re-add sec info + re-enable (local service desk only)".
Absent / `entra` → the standard discrete reset-password + revoke-sessions
analyst actions apply. The who-actions-it split is unchanged; only the
mechanism differs.

### `client_actioned` — no identity-plane delegation (e.g. Falcon / NGSIEM)

All identity actions — including password reset and session revoke — are the
**client's** responsibility. The SOC has no identity-plane access.

## Endpoint containment — symmetric, we action on both

Independent of `identity_response`. Wherever we hold the EDR/XDR action API
(`platforms.defender_xdr.api_enabled` or `platforms.crowdstrike.api_enabled`),
the SOC actions:

- **Network contain / isolate** the device
- **Add IOCs** (block hash / domain / IP)
- **AV / on-demand scan** (Falcon on-demand scan; Defender AV scan)

Same on Falcon and Defender XDR — there is no SOC-vs-client split for endpoint
containment, only the GitHub override.

## How `response_actions` applies this

1. Resolve `platforms.identity_response` and endpoint API flags → build the
   capability plan (analyst actions, client actions, endpoint actions).
2. Apply the GitHub response process as an override gate. The optional
   top-level `containment_policy` field in the response template governs SOC
   execution:
   - `pre_approved` (default when absent) — SOC may execute permitted
     containment.
   - `confirm_first` — SOC must confirm with the client before containing.
   - `prohibited` — SOC must **not** contain; notify only.
3. Surface the precedence in output: a capability action withheld by the GitHub
   process is shown as *suppressed by client response process*, with the reason
   — so an analyst sees it was a policy decision, not a capability gap.
