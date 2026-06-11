# socai — Playbook Query Reference

A complete, human-readable export of every investigation query shipped with socai. Each query is reproduced verbatim from its source file; `{{placeholder}}` tokens are the parameters you substitute at run time (the tools do this for you via `render_stage_for_platform` / `generate_sentinel_query`).

This file is **generated** — do not hand-edit. Regenerate with:

```bash
python3 scripts/export_playbook_queries.py
```

Two query families are covered:

- **Part 1 — Multi-stage investigation playbooks** (`config/playbooks/`): vendor-agnostic stages, each with a per-platform query body. Platforms exported here: **Microsoft Sentinel (KQL)**, **CrowdStrike Falcon NG-SIEM (LogScale)**.
- **Part 2 — Composite single-shot Sentinel scenarios** (`config/kql_playbooks/sentinel/`): monolithic KQL queries that return a full investigation picture in one execution.

## Contents

**Part 1 — Multi-stage investigation playbooks**

- [Account Investigation (`account-compromise`)](#account-investigation-account-compromise)
- [BEC Investigation & Response (`bec`)](#bec-investigation--response-bec)
- [Command & Control (C2) Behavioural Hunt (`command-and-control`)](#command--control-c2-behavioural-hunt-command-and-control)
- [Credential Access / AD Attacks Investigation (`credential-access`)](#credential-access--ad-attacks-investigation-credential-access)
- [Data Exfiltration Investigation (`data-exfiltration`)](#data-exfiltration-investigation-data-exfiltration)
- [Defence Evasion / Tamper Investigation (`defence-evasion`)](#defence-evasion--tamper-investigation-defence-evasion)
- [Insider Threat / Data Staging Investigation (`insider-data-staging`)](#insider-threat--data-staging-investigation-insider-data-staging)
- [IOC Hunt (`ioc-hunt`)](#ioc-hunt-ioc-hunt)
- [Lateral Movement Investigation (`lateral-movement`)](#lateral-movement-investigation-lateral-movement)
- [Malware/Script Execution Traceback (`malware-execution`)](#malwarescript-execution-traceback-malware-execution)
- [Illicit OAuth Consent / App Abuse Investigation (`oauth-consent`)](#illicit-oauth-consent--app-abuse-investigation-oauth-consent)
- [Persistence Sweep (`persistence`)](#persistence-sweep-persistence)
- [Phishing Investigation (`phishing`)](#phishing-investigation-phishing)
- [Privilege Escalation Investigation (`privilege-escalation`)](#privilege-escalation-investigation-privilege-escalation)
- [Ransomware / Impact Investigation (`ransomware`)](#ransomware--impact-investigation-ransomware)
- [Inbound Reconnaissance Detection (`reconnaissance`)](#inbound-reconnaissance-detection-reconnaissance)
- [Vulnerability Hunting / Active-Exploitation Detection (`vulnerability-hunting`)](#vulnerability-hunting--active-exploitation-detection-vulnerability-hunting)
- [Web Shell / Exploited Public-Facing App Investigation (`web-shell`)](#web-shell--exploited-public-facing-app-investigation-web-shell)

**Part 2 — Composite single-shot Sentinel scenarios**

- [DLP / Data Exfiltration (`dlp-exfiltration`)](#dlp--data-exfiltration-dlp-exfiltration)
- [Email Threat / ZAP (`email-threat-zap`)](#email-threat--zap-email-threat-zap)
- [Inbox Rule / BEC Investigation (`inbox-rule-bec`)](#inbox-rule--bec-investigation-inbox-rule-bec)
- [Mailbox Permission Change (`mailbox-permission-change`)](#mailbox-permission-change-mailbox-permission-change)
- [OAuth Consent Grant (`oauth-consent-grant`)](#oauth-consent-grant-oauth-consent-grant)
- [Suspicious Sign-In (`suspicious-signin`)](#suspicious-sign-in-suspicious-signin)

---

# Part 1 — Multi-stage investigation playbooks

## Account Investigation (`account-compromise`)

Comprehensive account investigation playbook covering cloud identity (Azure AD / Entra ID), on-prem Active Directory, Microsoft Defender for Identity (MDI), behaviour analytics (UEBA), and post-compromise persistence. Designed for account compromise, lockout investigations, suspicious sign-in activity, and service account abuse. Each stage uses heavy summarisation to return analytical output — use max_rows 200-500 on run_kql to capture the full picture in a single call.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `upn` | string | — | UserPrincipalName of the suspect account (e.g. user@domain.com) |
| `username` | string | — | On-prem sAMAccountName (e.g. m.chalkiadaki). Derive from UPN if not provided. |
| `ip` | string | — | Suspicious source IP address (optional; omit to investigate all activity) |
| `lookback` | string | `30d` | Time range to investigate (default 30d) |

### Stage 1 — Cloud identity triage (Azure AD)

- **Run:** ALWAYS — starting point for cloud identity investigations.

**Microsoft Sentinel (KQL)**

```kql
let target_upn = "{{upn}}";
let investigation_window = {{lookback}};
let AllSignIns = union
    (
        SigninLogs
        | where TimeGenerated > ago(investigation_window)
        | where UserPrincipalName =~ target_upn
        | extend SignInType = "Interactive"
    ),
    (
        AADNonInteractiveUserSignInLogs
        | where TimeGenerated > ago(investigation_window)
        | where UserPrincipalName =~ target_upn
        | extend SignInType = "NonInteractive"
    );
// Triage summary — one row per IP/Location/App combination
AllSignIns
| summarize
    TotalCount = count(),
    SuccessCount = countif(ResultType == 0),
    FailCount = countif(ResultType != 0),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName, 15),
    ResultCodes = make_set(ResultType, 15),
    SignInTypes = make_set(SignInType),
    Clients = make_set(ClientAppUsed, 10),
    RiskLevels = make_set(RiskLevelDuringSignIn, 5),
    ConditionalAccessStatuses = make_set(ConditionalAccessStatus, 5),
    UserAgents = make_set(UserAgent, 5)
    by IPAddress, Location
| extend FailRate = round(100.0 * FailCount / TotalCount, 1)
| sort by TotalCount desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: Interactive sign-ins ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{upn}}/i
| Vendor.properties.isInteractive = "true"
| groupBy([source.ip, Vendor.properties.location.city, Vendor.properties.location.countryOrRegion], function=[
    count(as=TotalCount),
    collect([Vendor.properties.appDisplayName], limit=15),
    collect([Vendor.properties.status.errorCode], limit=15),
    collect([Vendor.properties.clientAppUsed], limit=10),
    collect([Vendor.properties.riskLevelDuringSignIn], limit=5),
    collect([Vendor.properties.conditionalAccessStatus], limit=5),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(TotalCount, order=desc)


// --- Sub-query B: Non-interactive sign-ins ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{upn}}/i
| Vendor.properties.isInteractive = "false"
| groupBy([source.ip, Vendor.properties.location.city, Vendor.properties.location.countryOrRegion], function=[
    count(as=TotalCount),
    collect([Vendor.properties.appDisplayName], limit=15),
    collect([Vendor.properties.status.errorCode], limit=15),
    collect([Vendor.properties.clientAppUsed], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(TotalCount, order=desc)
```

### Stage 2 — On-prem AD logon and lockout triage

- **Run:** ALWAYS — primary stage for on-prem AD and lockout investigations.

**Microsoft Sentinel (KQL)**

```kql
let target_user = "{{username}}";
let investigation_window = {{lookback}};
// All relevant logon events for this user
let LogonEvents = SecurityEvent
    | where TimeGenerated > ago(investigation_window)
    | where EventID in (4624, 4625, 4771, 4776, 4768, 4769)
    | where TargetUserName has target_user
    | extend
        Result = case(
            EventID == 4624, "Success",
            EventID == 4625, "Failure",
            EventID == 4771, "Kerberos PreAuth Failure",
            EventID == 4776 and Keywords == "Audit Failure", "NTLM Failure",
            EventID == 4776 and Keywords == "Audit Success", "NTLM Success",
            EventID == 4768, "TGT Request",
            EventID == 4769, "Service Ticket",
            "Other"
        ),
        KerbStatus = case(
            Status == "0x0", "OK",
            Status == "0x6", "Unknown principal",
            Status == "0x12", "Account locked/disabled/expired",
            Status == "0x17", "Password expired",
            Status == "0x18", "Wrong password",
            Status == "0x25", "Clock skew",
            Status == "0x1f", "Integrity check failed",
            isnotempty(Status), strcat("0x", Status),
            ""
        );
// Part 1: Summarised triage — one row per source/event-type/result combination
let Triage = LogonEvents
    | summarize
        Count = count(),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        LogonTypes = make_set(LogonTypeName, 10),
        KerbStatuses = make_set(KerbStatus, 10),
        Computers = make_set(Computer, 5)
        by IpAddress, WorkstationName, EventID, Result
    | extend Section = "Triage"
    | project Section, IpAddress, WorkstationName, EventID, Result,
              Count, FirstSeen, LastSeen, LogonTypes, KerbStatuses, Computers;
// Part 2: Lockout events
let Lockouts = SecurityEvent
    | where TimeGenerated > ago(investigation_window)
    | where EventID == 4740
    | where TargetUserName has target_user
    | summarize
        Count = count(),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        SourceWorkstations = make_set(TargetDomainName, 10),
        Computers = make_set(Computer, 5)
        by TargetUserName
    | extend Section = "Lockouts", IpAddress = "", WorkstationName = "",
             EventID = 4740, Result = "Lockout",
             LogonTypes = dynamic([]), KerbStatuses = dynamic([])
    | project Section, IpAddress, WorkstationName, EventID, Result,
              Count, FirstSeen, LastSeen, LogonTypes, KerbStatuses, Computers;
// Part 3: Hourly pattern — detect automated vs interactive activity
let HourlyPattern = LogonEvents
    | where EventID == 4624
    | summarize Count = count() by IpAddress, HourOfDay = datetime_part("hour", TimeGenerated)
    | extend Section = "HourlyPattern", WorkstationName = "",
             EventID = 4624, Result = "Success",
             FirstSeen = datetime(null), LastSeen = datetime(null),
             LogonTypes = dynamic([]), KerbStatuses = dynamic([]),
             Computers = dynamic([])
    | project Section, IpAddress, WorkstationName, EventID, Result,
              Count, FirstSeen, LastSeen, LogonTypes, KerbStatuses, Computers;
union Triage, Lockouts, HourlyPattern
| sort by Section asc, Count desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: Logon events summary (4624, 4625, 4771, 4776, 4768, 4769) ---

#Vendor="microsoft" #event.module=windows
| in(EventCode, values=["4624", "4625", "4771", "4776", "4768", "4769"])
| user.name = /{{username}}/i
| groupBy([windows.EventData.IpAddress, EventCode], function=[
    count(as=Count),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen),
    collect([host.hostname], limit=5)
  ])
| sort(Count, order=desc)


// --- Sub-query B: Failed logon detail (4625 — wrong password, locked out, etc.) ---

#Vendor="microsoft" #event.module=windows EventCode=4625
| user.name = /{{username}}/i
| table([@timestamp, host.hostname, user.name,
         windows.EventData.IpAddress, windows.EventData.SubStatus,
         windows.EventData.LogonType, windows.EventData.FailureReason])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query C: Account lockout events (4740) ---

#Vendor="microsoft" #event.module=windows EventCode=4740
| user.name = /{{username}}/i
| table([@timestamp, host.hostname, user.name,
         windows.EventData.TargetDomainName])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query D: Kerberos pre-auth failures (4771) with status decode ---

#Vendor="microsoft" #event.module=windows EventCode=4771
| user.name = /{{username}}/i
| StatusDecode := case {
    windows.EventData.Status = "0x6"  | "Unknown principal";
    windows.EventData.Status = "0x12" | "Account locked/disabled/expired";
    windows.EventData.Status = "0x17" | "Password expired";
    windows.EventData.Status = "0x18" | "Wrong password";
    windows.EventData.Status = "0x25" | "Clock skew";
    * | windows.EventData.Status;
  }
| groupBy([windows.EventData.IpAddress, StatusDecode], function=[
    count(as=Count),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(Count, order=desc)
```

### Stage 3 — Identity protection and behaviour analytics

- **Run:** ALWAYS — tables may be empty if MDI or UEBA is not deployed.

**Microsoft Sentinel (KQL)**

```kql
let target_upn = "{{upn}}";
let target_user = "{{username}}";
let investigation_window = {{lookback}};
union
(
    // MDI cross-protocol logon events (Kerberos, NTLM, LDAP, etc.)
    IdentityLogonEvents
    | where Timestamp > ago(investigation_window)
    | where AccountUpn =~ target_upn or AccountName =~ target_user
    | summarize
        Count = count(),
        SuccessCount = countif(ActionType == "LogonSuccess"),
        FailCount = countif(ActionType == "LogonFailed"),
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp),
        Protocols = make_set(Protocol, 10),
        Actions = make_set(ActionType, 10),
        FailReasons = make_set(FailureReason, 10),
        Applications = make_set(Application, 10)
        by IPAddress, DeviceName
    | extend SourceTable = "IdentityLogonEvents"
    | project SourceTable, IPAddress, DeviceName, Count, SuccessCount, FailCount,
              FirstSeen, LastSeen, Protocols, Actions, FailReasons, Applications
),
(
    // MDI directory operations (group membership, password changes, LDAP queries)
    IdentityDirectoryEvents
    | where Timestamp > ago(investigation_window)
    | where AccountUpn =~ target_upn or AccountName =~ target_user
    | summarize
        Count = count(),
        Actions = make_set(ActionType, 15),
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp)
        by DeviceName
    | extend SourceTable = "IdentityDirectoryEvents", IPAddress = "",
             SuccessCount = 0, FailCount = 0,
             Protocols = dynamic([]), FailReasons = dynamic([]),
             Applications = dynamic([])
    | project SourceTable, IPAddress, DeviceName, Count, SuccessCount, FailCount,
              FirstSeen, LastSeen, Protocols, Actions, FailReasons, Applications
),
(
    // UEBA anomaly scores — high-value signal for compromised accounts
    BehaviorAnalytics
    | where TimeGenerated > ago(investigation_window)
    | where UserPrincipalName =~ target_upn or UserName =~ target_user
    | where InvestigationPriority > 0 or ActivityInsights has_any ("True", "true")
    | summarize
        Count = count(),
        MaxPriority = max(InvestigationPriority),
        Activities = make_set(ActivityType, 15),
        Insights = make_set(ActivityInsights, 10),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by SourceIPAddress, SourceDevice
    | extend SourceTable = "BehaviorAnalytics",
             IPAddress = SourceIPAddress, DeviceName = SourceDevice,
             SuccessCount = 0, FailCount = 0,
             Protocols = dynamic([]),
             Actions = Activities,
             FailReasons = Insights,
             Applications = dynamic([])
    | project SourceTable, IPAddress, DeviceName, Count, SuccessCount, FailCount,
              FirstSeen, LastSeen, Protocols, Actions, FailReasons, Applications
),
(
    // Device-level logon events (MDE) — endpoint context
    DeviceLogonEvents
    | where Timestamp > ago(investigation_window)
    | where AccountName =~ target_user or AccountUpn =~ target_upn
    | summarize
        Count = count(),
        SuccessCount = countif(ActionType == "LogonSuccess"),
        FailCount = countif(ActionType == "LogonFailed"),
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp),
        LogonTypes = make_set(LogonType, 10),
        Protocols = make_set(Protocol, 10),
        RemoteIPs = make_set(RemoteIP, 15)
        by DeviceName
    | extend SourceTable = "DeviceLogonEvents", IPAddress = tostring(RemoteIPs),
             Actions = LogonTypes, FailReasons = dynamic([]),
             Applications = dynamic([])
    | project SourceTable, IPAddress, DeviceName, Count, SuccessCount, FailCount,
              FirstSeen, LastSeen, Protocols, Actions, FailReasons, Applications
)
| sort by SourceTable asc, Count desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: CrowdStrike Falcon user logon events ---

#event_simpleName=UserLogon
| UserName = /{{username}}/i
| groupBy([ComputerName, LogonType, RemoteAddressIP4], function=[
    count(as=Count),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen),
    collect([AuthenticationPackage], limit=5),
    collect([LogonDomain], limit=5)
  ])
| sort(Count, order=desc)


// --- Sub-query B: CrowdStrike Falcon failed logon events ---

#event_simpleName=UserLogonFailed2
| UserName = /{{username}}/i
| groupBy([ComputerName, RemoteAddressIP4], function=[
    count(as=FailCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen),
    collect([LogonType], limit=5),
    collect([SubStatus], limit=5)
  ])
| sort(FailCount, order=desc)


// --- UNAVAILABLE: Identity protection and behaviour analytics ---
// Sources: IdentityLogonEvents (MDI), IdentityDirectoryEvents (MDI),
//          BehaviorAnalytics (UEBA)
// Not available in LogScale. Check Microsoft Defender for Identity portal
// for cross-protocol logon analysis and UEBA anomaly scores.
```

### Stage 4 — Source host enumeration

- **Run:** When a source IP warrants investigation — automated auth pattern,

**Microsoft Sentinel (KQL)**

```kql
let target_ip = "{{ip}}";
let investigation_window = {{lookback}};
// Part 1: What accounts authenticate from this IP?
let AccountsFromIP = SecurityEvent
    | where TimeGenerated > ago(investigation_window)
    | where EventID in (4624, 4625, 4768, 4769)
    | where IpAddress == target_ip
       or IpAddress == strcat("::ffff:", target_ip)
    | summarize
        Count = count(),
        SuccessCount = countif(EventID == 4624),
        FailCount = countif(EventID == 4625),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventTypes = make_set(EventID, 10),
        LogonTypes = make_set(LogonTypeName, 10)
        by TargetUserName, Computer
    | extend Section = "AccountsFromIP"
    | project Section, TargetUserName, Computer, Count, SuccessCount, FailCount,
              FirstSeen, LastSeen, EventTypes, LogonTypes;
// Part 2: Hostname resolution
let HostnameResolution = DeviceNetworkInfo
    | where Timestamp > ago(investigation_window)
    | where IPAddresses has target_ip
    | summarize arg_max(Timestamp, *) by DeviceName
    | project Section = "HostnameResolution",
              TargetUserName = "",
              Computer = DeviceName,
              Count = 1,
              SuccessCount = 0,
              FailCount = 0,
              FirstSeen = Timestamp,
              LastSeen = Timestamp,
              EventTypes = dynamic([]),
              LogonTypes = dynamic([]);
union AccountsFromIP, HostnameResolution
| sort by Section asc, Count desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: Windows logon events from the target IP ---

#Vendor="microsoft" #event.module=windows
| in(EventCode, values=["4624", "4625", "4768", "4769"])
| windows.EventData.IpAddress = "{{ip}}"
| groupBy([user.name, host.hostname, EventCode], function=[
    count(as=Count),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(Count, order=desc)


// --- Sub-query B: CrowdStrike Falcon logons from the target IP ---

#event_simpleName=UserLogon
| RemoteAddressIP4 = "{{ip}}"
| groupBy([ComputerName, UserName, LogonType], function=[
    count(as=Count),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen),
    collect([AuthenticationPackage], limit=5)
  ])
| sort(Count, order=desc)


// --- Sub-query C: Entra ID sign-ins from the target IP ---

#event.module=entraid #event.dataset="entraid.signin"
| source.ip = "{{ip}}"
| groupBy([Vendor.properties.userPrincipalName, Vendor.properties.appDisplayName], function=[
    count(as=Count),
    collect([Vendor.properties.status.errorCode], limit=10),
    collect([Vendor.properties.riskLevelDuringSignIn], limit=5),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(Count, order=desc)


// --- UNAVAILABLE: Post-compromise persistence ---
// Sources: AuditLogs (MFA registration, password resets, OAuth consent),
//          OfficeActivity (inbox rules, mail forwarding)
// Not available in LogScale. Check Microsoft Entra admin center for
// MFA changes and Azure AD audit logs. Check Exchange admin center
// for mailbox rule modifications.
```

### Stage 5 — Post-compromise persistence

- **Run:** ALWAYS for compromised accounts.

**Microsoft Sentinel (KQL)**

```kql
let target_upn = "{{upn}}";
let investigation_window = {{lookback}};
union
(
    AuditLogs
    | where TimeGenerated > ago(investigation_window)
    | where TargetResources has target_upn or InitiatedBy has target_upn
    | where OperationName in (
        // MFA and credential changes
        "User registered security info",
        "User registered all required security info",
        "User started security info registration",
        "User deleted security info",
        "Admin registered security info",
        "Reset password (by admin)",
        "Reset password (self-service)",
        "Change password (self-service)",
        "User performed a self-service password reset",
        // OAuth consent grants
        "Consent to application",
        // Conditional access
        "Add conditional access policy",
        "Update conditional access policy",
        "Delete conditional access policy",
        // App registrations and service principals
        "Add service principal credentials",
        "Update application – Certificates and secrets management"
    )
    | project
        SourceTable = "AuditLogs",
        TimeGenerated,
        Activity = OperationName,
        InitiatedBy = tostring(InitiatedBy),
        TargetResources = tostring(TargetResources),
        Result,
        Detail = coalesce(ResultReason, ""),
        Extra = tostring(AdditionalDetails),
        ClientIP = "",
        CorrelationId
),
(
    OfficeActivity
    | where TimeGenerated > ago(investigation_window)
    | where UserId =~ target_upn
    | where Operation in (
        "New-InboxRule",
        "Set-InboxRule",
        "Enable-InboxRule",
        "New-TransportRule",
        "Set-TransportRule",
        "UpdateInboxRules",
        // Mail forwarding
        "Set-Mailbox",
        "Set-MailboxJunkEmailConfiguration"
    )
    | project
        SourceTable = "OfficeActivity",
        TimeGenerated,
        Activity = Operation,
        InitiatedBy = UserId,
        TargetResources = "",
        Result = ResultStatus,
        Detail = tostring(Parameters),
        Extra = "",
        ClientIP,
        CorrelationId = ""
)
| sort by TimeGenerated desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Account Compromise Stage 5 — Post-compromise persistence for {{upn}}.
// MFA / credential changes, OAuth consent, conditional-access tampering, and
//   inbox-rule / mail-forwarding persistence after a confirmed compromise.
// Source: Microsoft 365 unified audit log (#Vendor="microsoft" #event.module=m365 —
//   verified). AzureActiveDirectory and Exchange workloads both flow through this
//   module; rule/forwarding parameters live in the raw event (inspect matched rows).

// --- Sub-query A: Entra credential / MFA / OAuth / conditional-access changes ---

#Vendor="microsoft" #event.module=m365
| Vendor.Workload = "AzureActiveDirectory"
| @rawstring = /{{upn}}/i
| in(field=Vendor.Operation, values=["User registered security info",
    "User registered all required security info", "User started security info registration",
    "User deleted security info", "Admin registered security info",
    "Reset password (by admin)", "Reset password (self-service)",
    "Change password (self-service)", "User performed a self-service password reset",
    "Consent to application", "Add conditional access policy",
    "Update conditional access policy", "Delete conditional access policy",
    "Add service principal credentials",
    "Update application – Certificates and secrets management"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.ResultStatus], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: Inbox rules / mail forwarding ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| in(field=Vendor.Operation, values=["New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "New-TransportRule", "Set-TransportRule", "UpdateInboxRules",
    "Set-Mailbox", "Set-MailboxJunkEmailConfiguration"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

---

## BEC Investigation & Response (`bec`)

Full BEC (Business Email Compromise) lifecycle. Scope broad, contain fast, investigate deep. *** START BROAD *** An alert names one NetworkMessageId, but a BEC campaign almost always contains many emails sharing the same sender + subject. Stage 0 expands the seed alert into the full set of related NetworkMessageIds BEFORE any narrow-scope analysis runs. Stage 1 onwards then operates on the expanded ID set, not just the alert's single message. Skipping Stage 0 leads to under-blocked campaigns and missed clickers. CRITICAL: MDO blocks (Stage 2) are the FIRST containment action. Run Stage 0, then Stage 1, then IMMEDIATELY Stage 2 and instruct the analyst to submit the blocks. Only then proceed with Stages 3-7. Do not close the case until the analyst confirms blocks are in place.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `seed_message_id` |  | — | Single NetworkMessageId from the alert (used by Stage 0 to derive sender/subject) |
| `target_ids` |  | — | Comma-separated NetworkMessageIds. Populated from Stage 0 output before Stage 1. |
| `upn` |  | — | Compromised or target UserPrincipalName (for post-compromise stages) |
| `sender` |  | — | Malicious sender email address (auto-derived in Stage 0 if seed_message_id supplied) |
| `subject` |  | — | Email subject for broad-scope expansion (auto-derived in Stage 0 if seed_message_id supplied) |
| `url` |  | — | Malicious URL (from Stage 1) |
| `attacker_ip` |  | — | Attacker source IP (from Stage 4; used in Stages 5-7) |
| `lookback` |  | `14d` | Time range to investigate |

### Stage 0 — Broad scope expansion (sender + subject)

- **Run:** always — before Stage 1
- **Purpose:** FIRST STEP. Expand the seed alert (a single NetworkMessageId, or an explicit sender/subject pair) into the full set of related emails across the lookback window. One alert is rarely the whole campaign — there are usually more recipients from the same sender with the same subject. Returns all matching NetworkMessageIds, recipient count, and delivery breakdown grouped by (sender, subject). Feed the expanded NetworkMessageId list into target_ids for Stage 1 onwards.

**Microsoft Sentinel (KQL)**

```kql
let SeedLookup = EmailEvents
    | where isnotempty("{{seed_message_id}}") and NetworkMessageId == "{{seed_message_id}}"
    | top 1 by Timestamp asc
    | project SeedSender = SenderFromAddress, SeedSubject = Subject;
let SeedSender = toscalar(SeedLookup | project SeedSender);
let SeedSubject = toscalar(SeedLookup | project SeedSubject);
let TargetSender = iff(isempty("{{sender}}"), SeedSender, "{{sender}}");
let TargetSubject = iff(isempty("{{subject}}"), SeedSubject, "{{subject}}");
let CampaignEmails = EmailEvents
    | where Timestamp >= ago({{lookback}})
    | where isnotempty(TargetSender) and isnotempty(TargetSubject)
    | where SenderFromAddress =~ TargetSender
    | where Subject =~ TargetSubject
    | project
        NetworkMessageId,
        Timestamp,
        SenderFromAddress,
        SenderFromDomain,
        SenderMailFromAddress,
        Subject,
        RecipientEmailAddress,
        DeliveryAction,
        DeliveryLocation,
        ThreatTypes,
        DetectionMethods,
        EmailDirection,
        InternetMessageId;
let CampaignClicks = UrlClickEvents
    | where Timestamp >= ago({{lookback}})
    | summarize ClickCount = count() by NetworkMessageId;
CampaignEmails
| join kind=leftouter CampaignClicks on NetworkMessageId
| summarize
    MessageCount = dcount(NetworkMessageId),
    MessageIds = make_set(NetworkMessageId),
    Recipients = make_set(RecipientEmailAddress),
    RecipientCount = dcount(RecipientEmailAddress),
    SenderDomains = make_set(SenderFromDomain),
    MailFromAddresses = make_set(SenderMailFromAddress),
    DeliveryActions = make_set(DeliveryAction),
    DeliveryLocations = make_set(DeliveryLocation),
    ThreatTypes = make_set(ThreatTypes),
    DetectionMethods = make_set(DetectionMethods),
    ClickedMessageCount = countif(isnotempty(ClickCount)),
    TotalClicks = sum(ClickCount),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
  by SenderFromAddress, Subject
| extend SpansDays = datetime_diff('day', LastSeen, FirstSeen)
| sort by MessageCount desc, LastSeen desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// BEC Stage 0 — Broad scope expansion (sender + subject).
// Source: Microsoft Defender advanced-hunting EmailEvents / UrlClickEvents,
//   forwarded via the Defender 365 connector.
//   Tag #Vendor="microsoft" #event.dataset="windows-defender-365.event" is verified
//   (config/ngsiem/ngsiem_rules.md §4). Email columns ride Vendor.properties.*
//   (config/ngsiem/ngsiem_columns.yaml → microsoft_perf_defendero365_eventhub).
// Sub-table discriminator: Vendor.Workload — verified values "EmailEvents",
//   "EmailAttachmentInfo", "EmailUrlInfo", "UrlClickEvents". "EmailPostDeliveryEvents"
//   and "AlertInfo" follow the same scheme but were not in the verified sample;
//   confirm with:  #event.dataset="windows-defender-365.event"
//     | groupBy(Vendor.Workload, function=count())
//   ThreatTypes / DetectionMethods were not in the discovered sample — they may be
//   unpopulated; drop from output if empty.
// Pivot key across all stages: Vendor.properties.NetworkMessageId.

// --- Sub-query A: Seed lookup (derive sender + subject from the alert's NetworkMessageId) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| Vendor.properties.NetworkMessageId = "{{seed_message_id}}"
| table([@timestamp, Vendor.properties.SenderFromAddress, Vendor.properties.SenderFromDomain,
         Vendor.properties.Subject, Vendor.properties.RecipientEmailAddress], limit=5)
| sort(@timestamp, order=asc, limit=5)


// --- Sub-query B: Campaign expansion by (sender, subject) ---
// Fill {{sender}} and {{subject}} from Sub-query A (or pass them directly).

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| Vendor.properties.SenderFromAddress = /{{sender}}/i
| Vendor.properties.Subject = /{{subject}}/i
| groupBy([Vendor.properties.SenderFromAddress, Vendor.properties.Subject], function=[
    count(field=Vendor.properties.NetworkMessageId, distinct=true, as=MessageCount),
    count(field=Vendor.properties.RecipientEmailAddress, distinct=true, as=RecipientCount),
    collect([Vendor.properties.NetworkMessageId], limit=500),
    collect([Vendor.properties.RecipientEmailAddress], limit=500),
    collect([Vendor.properties.SenderFromDomain], limit=20),
    collect([Vendor.properties.SenderMailFromAddress], limit=20),
    collect([Vendor.properties.DeliveryAction], limit=10),
    collect([Vendor.properties.DeliveryLocation], limit=10),
    collect([Vendor.properties.ThreatTypes], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(MessageCount, order=desc, limit=200)


// --- Sub-query C: Click volume per campaign message (pivot on NetworkMessageId) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "UrlClickEvents"
| groupBy([Vendor.properties.NetworkMessageId], function=[
    count(as=ClickCount),
    collect([Vendor.properties.AccountUpn], limit=50),
    collect([Vendor.properties.Url], limit=50)
  ])
| sort(ClickCount, order=desc, limit=200)
```

### Stage 1 — Phishing delivery scope & clickers

- **Run:** always (after Stage 0 expansion)
- **Purpose:** Full email campaign scope — all recipients, delivery status, URL clicks, attachments. Identifies who received, who clicked, who clicked through. Operates on the expanded target_ids set from Stage 0 — never on the single alert NetworkMessageId in isolation.

**Microsoft Sentinel (KQL)**

```kql
let targetIds = dynamic([{{target_ids}}]);
let EmailCore = EmailEvents
    | where NetworkMessageId in (targetIds)
    | project
        NetworkMessageId,
        EmailTimestamp = Timestamp,
        Subject,
        SenderFromAddress,
        SenderDisplayName,
        SenderFromDomain,
        SenderMailFromAddress,
        SenderMailFromDomain,
        SenderIP = SenderIPv4,
        RecipientEmailAddress,
        RecipientObjectId,
        AuthenticationDetails,
        DeliveryAction,
        DeliveryLocation,
        ThreatTypes,
        ThreatNames,
        DetectionMethods,
        EmailDirection,
        InternetMessageId;
let Attachments = EmailAttachmentInfo
    | where NetworkMessageId in (targetIds)
    | summarize
        AttachmentSHA256 = make_set(SHA256),
        AttachmentNames = make_set(FileName)
      by NetworkMessageId;
let Urls = EmailUrlInfo
    | where NetworkMessageId in (targetIds)
    | summarize Urls = make_set(Url) by NetworkMessageId;
let Clicks = UrlClickEvents
    | where NetworkMessageId in (targetIds)
    | summarize
        ClickedUrls = make_set(Url),
        ClickedThrough = make_set_if(Url, IsClickedThrough == true),
        ClickCount = count(),
        FirstClick = min(Timestamp),
        LastClick = max(Timestamp),
        ClickIPs = make_set(IPAddress)
      by NetworkMessageId, AccountUpn;
EmailCore
| join kind=leftouter Attachments on NetworkMessageId
| join kind=leftouter Urls on NetworkMessageId
| join kind=leftouter (Clicks | project-away AccountUpn) on NetworkMessageId
| summarize
    MessageCount = dcount(NetworkMessageId),
    MessageIds = make_set(NetworkMessageId),
    Subjects = make_set(Subject),
    Senders = make_set(SenderFromAddress),
    SenderDomains = make_set(SenderFromDomain),
    MailFrom = make_set(SenderMailFromAddress),
    SenderIPs = make_set(SenderIP),
    DeliveryActions = make_set(DeliveryAction),
    DeliveryLocations = make_set(DeliveryLocation),
    ThreatTypes = make_set(ThreatTypes),
    DetectionMethods = make_set(DetectionMethods),
    AttachmentSHA256 = make_set(AttachmentSHA256),
    AttachmentNames = make_set(AttachmentNames),
    Urls = make_set(Urls),
    ClickedUrls = make_set(ClickedUrls),
    ClickedThrough = make_set(ClickedThrough),
    ClickCount = sum(ClickCount),
    FirstEmailSeen = min(EmailTimestamp),
    LastEmailSeen = max(EmailTimestamp),
    FirstClick = min(FirstClick),
    LastClick = max(LastClick),
    ClickIPs = make_set(ClickIPs)
  by UPN = RecipientEmailAddress
| extend Clicked = isnotempty(FirstClick)
| sort by Clicked desc, ClickCount desc, UPN asc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// BEC Stage 1 — Phishing delivery scope & clickers (per recipient UPN).
// Operates on the expanded {{target_ids}} set from Stage 0, never the single alert
//   NetworkMessageId. Source: Defender advanced-hunting (windows-defender-365);
//   see Stage 0 header for connector / Vendor.Workload caveats.
// CQL is join-free: correlate the sub-queries on Vendor.properties.NetworkMessageId.

// --- Sub-query A: Email evidence per recipient UPN ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| groupBy([Vendor.properties.RecipientEmailAddress], function=[
    count(field=Vendor.properties.NetworkMessageId, distinct=true, as=MessageCount),
    collect([Vendor.properties.NetworkMessageId], limit=200),
    collect([Vendor.properties.Subject], limit=20),
    collect([Vendor.properties.SenderFromAddress], limit=20),
    collect([Vendor.properties.SenderFromDomain], limit=20),
    collect([Vendor.properties.SenderMailFromAddress], limit=20),
    collect([Vendor.properties.SenderIPv4], limit=20),
    collect([Vendor.properties.DeliveryAction], limit=10),
    collect([Vendor.properties.DeliveryLocation], limit=10),
    collect([Vendor.properties.ThreatTypes], limit=10),
    min(@timestamp, as=FirstEmailSeen),
    max(@timestamp, as=LastEmailSeen)
  ])
| sort(MessageCount, order=desc, limit=200)


// --- Sub-query B: Clickers — who clicked, who clicked through (per UPN) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "UrlClickEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| groupBy([Vendor.properties.AccountUpn], function=[
    count(as=ClickCount),
    collect([Vendor.properties.NetworkMessageId], limit=100),
    collect([Vendor.properties.Url], limit=50),
    collect([Vendor.properties.IsClickedThrough], limit=5),
    collect([Vendor.properties.IPAddress], limit=20),
    min(@timestamp, as=FirstClick),
    max(@timestamp, as=LastClick)
  ])
| sort(ClickCount, order=desc, limit=200)


// --- Sub-query C: Attachments across the campaign ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailAttachmentInfo"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| groupBy([Vendor.properties.NetworkMessageId], function=[
    collect([Vendor.properties.SHA256], limit=50),
    collect([Vendor.properties.FileName], limit=50)
  ])
| sort(Vendor.properties.NetworkMessageId, order=asc, limit=500)
```

### Stage 2 — MDO block entities (MANDATORY — RUN IMMEDIATELY AFTER STAGE 1)

- **Run:** always — IMMEDIATELY after Stage 1. Do NOT defer.
- **Purpose:** FIRST CONTAINMENT ACTION. Extracts the exact URLs and sender addresses that MUST be blocked in Microsoft Defender for Office 365 NOW, before continuing the investigation. Present these to the analyst and instruct them to submit blocks via MDO portal (Tenant Allow/Block Lists) or PowerShell (New-TenantAllowBlockListItems) immediately. Do not proceed to Stage 3 until the analyst confirms blocks are submitted.

**Microsoft Sentinel (KQL)**

```kql
let targetIds = dynamic([{{target_ids}}]);
// Malicious URLs to block
let MaliciousUrls = EmailUrlInfo
    | where NetworkMessageId in (targetIds)
    | distinct Url
    | extend BlockType = "URL", BlockAction = "Add to MDO Tenant Allow/Block List > URLs";
// Sender addresses to block
let MaliciousSenders = EmailEvents
    | where NetworkMessageId in (targetIds)
    | where EmailDirection == "Inbound"
    | distinct SenderFromAddress, SenderMailFromAddress, SenderFromDomain
    | extend BlockType = "Sender", BlockAction = "Add to MDO Tenant Allow/Block List > Senders";
// Sender IPs (for transport rule blocking if needed)
let SenderIPs = EmailEvents
    | where NetworkMessageId in (targetIds)
    | where EmailDirection == "Inbound"
    | where isnotempty(SenderIPv4)
    | distinct SenderIPv4
    | extend BlockType = "SenderIP", BlockAction = "Consider transport rule block if IP is dedicated attacker infra";
// Combine all block entities
union
    (MaliciousUrls | project Entity = Url, BlockType, BlockAction),
    (MaliciousSenders | project Entity = SenderFromAddress, BlockType, BlockAction),
    (MaliciousSenders | project Entity = SenderFromDomain, BlockType,
        BlockAction = "Block entire domain if compromised third-party (not shared hosting)"),
    (SenderIPs | project Entity = SenderIPv4, BlockType, BlockAction)
| distinct Entity, BlockType, BlockAction
| sort by BlockType asc, Entity asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// BEC Stage 2 — MDO block entities (MANDATORY, run immediately after Stage 1).
// Extracts the exact URLs, sender addresses/domains and sender IPs to block in
//   Microsoft Defender for Office 365 (Tenant Allow/Block List) NOW.
// Source: Defender advanced-hunting (windows-defender-365); see Stage 0 header.
// These are containment outputs — present the distinct entities to the analyst and
//   instruct submission before continuing to Stage 3.

// --- Sub-query A: Malicious URLs to block (TABL > URLs) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailUrlInfo"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| groupBy([Vendor.properties.Url], function=[count(as=Occurrences)])
| sort(Occurrences, order=desc, limit=500)


// --- Sub-query B: Sender addresses / domains to block (TABL > Senders) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| Vendor.properties.EmailDirection = "Inbound"
| groupBy([Vendor.properties.SenderFromAddress, Vendor.properties.SenderMailFromAddress,
           Vendor.properties.SenderFromDomain], function=[count(as=Occurrences)])
| sort(Occurrences, order=desc, limit=500)


// --- Sub-query C: Sender IPs (consider transport-rule block if dedicated attacker infra) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| Vendor.properties.EmailDirection = "Inbound"
| Vendor.properties.SenderIPv4 = /.+/
| groupBy([Vendor.properties.SenderIPv4], function=[
    count(as=Occurrences),
    collect([Vendor.properties.SenderFromDomain], limit=20)
  ])
| sort(Occurrences, order=desc, limit=500)
```

### Stage 3 — ZAP and remediation status

- **Run:** always (after Stage 2 blocks are submitted)
- **Purpose:** Check post-delivery remediation for all campaign emails. Identifies emails that ZAP missed, emails still in mailboxes, and forwarded copies that bypass ZAP. Calculates exposure time per recipient.

**Microsoft Sentinel (KQL)**

```kql
let targetIds = dynamic([{{target_ids}}]);
let Delivered = EmailEvents
    | where NetworkMessageId in (targetIds)
    | where DeliveryAction == "Delivered"
    | project
        DeliveryTime = Timestamp,
        NetworkMessageId,
        RecipientEmailAddress,
        Subject,
        DeliveryLocation,
        SenderFromAddress;
let PostDelivery = EmailPostDeliveryEvents
    | where NetworkMessageId in (targetIds)
    | project
        NetworkMessageId,
        RecipientEmailAddress,
        ActionType,
        ActionTrigger,
        ActionResult,
        RemediationTime = Timestamp;
Delivered
| join kind=leftouter PostDelivery on NetworkMessageId, RecipientEmailAddress
| extend
    Remediated = isnotempty(RemediationTime),
    ExposureMinutes = iff(isnotempty(RemediationTime),
        datetime_diff('minute', RemediationTime, DeliveryTime), -1),
    RemediationType = coalesce(ActionType, "None"),
    RemediationTrigger = coalesce(ActionTrigger, "None")
| project
    RecipientEmailAddress,
    DeliveryTime,
    DeliveryLocation,
    Remediated,
    RemediationType,
    RemediationTrigger,
    RemediationTime,
    ExposureMinutes,
    Subject,
    SenderFromAddress,
    NetworkMessageId
| sort by Remediated asc, ExposureMinutes desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// BEC Stage 3 — ZAP and remediation status.
// Goal: which campaign emails were delivered, which were remediated (ZAP / admin
//   purge), which were missed and still in mailboxes, and the exposure window.
// Source: Defender advanced-hunting (windows-defender-365); see Stage 0 header.
// CQL is join-free: pivot on NetworkMessageId (+ RecipientEmailAddress) and compute
//   ExposureMinutes = (remediation @timestamp − delivery @timestamp). Recipients in
//   A with no matching row in B were NOT remediated (still exposed).

// --- Sub-query A: Delivered campaign mail (per recipient) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| Vendor.properties.DeliveryAction = "Delivered"
| table([@timestamp, Vendor.properties.NetworkMessageId, Vendor.properties.RecipientEmailAddress,
         Vendor.properties.Subject, Vendor.properties.DeliveryLocation,
         Vendor.properties.SenderFromAddress], limit=500)
| sort(@timestamp, order=asc, limit=500)


// --- Sub-query B: Post-delivery remediation events (ZAP / purge) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailPostDeliveryEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| table([@timestamp, Vendor.properties.NetworkMessageId, Vendor.properties.RecipientEmailAddress,
         Vendor.properties.ActionType], limit=500)
| sort(@timestamp, order=asc, limit=500)
```

### Stage 4 — Post-phishing sign-in analysis

- **Run:** when Stage 1 shows URL clicks
- **Purpose:** For each user who clicked, check for sign-ins from unfamiliar IPs within 4 hours of click. Detects AiTM token theft, credential reuse, and attacker pivot to compromised accounts. Flags risk level and CA status.

**Microsoft Sentinel (KQL)**

```kql
let TargetUPN = "{{upn}}";
let AttackerIP = "{{attacker_ip}}";
let Lookback = {{lookback}};
// Interactive sign-ins — anomalous locations, new devices, risk flags
let Interactive = SigninLogs
    | where TimeGenerated > ago(Lookback)
    | where UserPrincipalName =~ TargetUPN
    | where isempty(AttackerIP) or IPAddress == AttackerIP
    | extend
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion),
        DeviceName = tostring(DeviceDetail.displayName),
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        Browser = tostring(DeviceDetail.browser),
        IsManaged = tostring(DeviceDetail.isManaged),
        IsCompliant = tostring(DeviceDetail.isCompliant),
        TrustType = tostring(DeviceDetail.trustType),
        MfaMethod = tostring(MfaDetail.authMethod),
        ErrorCode = tostring(Status.errorCode),
        FailureReason = tostring(Status.failureReason)
    | project
        TimeGenerated, UserPrincipalName, IPAddress,
        City, Country,
        AppDisplayName, ResourceDisplayName,
        ResultType, ErrorCode, FailureReason,
        RiskLevelDuringSignIn, RiskState, RiskDetail,
        ConditionalAccessStatus, AuthenticationRequirement,
        MfaMethod,
        DeviceName, DeviceOS, Browser, IsManaged, IsCompliant, TrustType,
        SessionId = CorrelationId,
        SignInType = "Interactive";
// Non-interactive sign-ins — token replay, app access
let NonInteractive = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(Lookback)
    | where UserPrincipalName =~ TargetUPN
    | where isempty(AttackerIP) or IPAddress == AttackerIP
    | extend
        City = tostring(parse_json(tostring(LocationDetails)).city),
        Country = tostring(parse_json(tostring(LocationDetails)).countryOrRegion),
        ErrorCode = tostring(parse_json(tostring(Status)).errorCode),
        FailureReason = tostring(parse_json(tostring(Status)).failureReason)
    | project
        TimeGenerated, UserPrincipalName, IPAddress,
        City, Country,
        AppDisplayName, ResourceDisplayName,
        ResultType, ErrorCode, FailureReason,
        RiskLevelDuringSignIn, RiskState, RiskDetail = "",
        ConditionalAccessStatus, AuthenticationRequirement,
        MfaMethod = "",
        DeviceName = "", DeviceOS = "", Browser = "",
        IsManaged = "", IsCompliant = "", TrustType = "",
        SessionId = CorrelationId,
        SignInType = "NonInteractive";
// Summarise per source IP / geo / type first — one row per location with
// success/fail split, apps, risk and device posture. Pivot to raw sign-in rows
// for a specific suspect IP once an anomalous location surfaces.
union Interactive, NonInteractive
| summarize SignIns = count(),
    Successes = countif(ResultType == 0), Failures = countif(ResultType != 0),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName, 20), Resources = make_set(ResourceDisplayName, 20),
    RiskLevels = make_set(RiskLevelDuringSignIn, 10), ResultCodes = make_set(ErrorCode, 15),
    Devices = make_set(DeviceName, 15), Compliant = make_set(IsCompliant, 5),
    CA = make_set(ConditionalAccessStatus, 5), MFA = make_set(MfaMethod, 10)
    by IPAddress, City, Country, SignInType
| sort by SignIns desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// BEC Stage 4 — Post-phishing sign-in analysis.
// Goal: for the compromised / clicked account {{upn}}, surface sign-ins from
//   unfamiliar IPs (AiTM token theft, credential reuse). The attacker IP is an
//   OUTPUT of this stage — feed it into {{attacker_ip}} for Stages 5–7.
// Source: Entra ID sign-ins (dedicated entraid connector, dataset entraid.signin —
//   verified). Interactive vs non-interactive split on Vendor.properties.isInteractive.

// --- Sub-query A: Interactive sign-ins ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{upn}}/i
| Vendor.properties.isInteractive = "true"
| groupBy([source.ip, Vendor.properties.location.city, Vendor.properties.location.countryOrRegion],
    function=[
      count(as=TotalCount),
      collect([Vendor.properties.appDisplayName], limit=20),
      collect([Vendor.properties.status.errorCode], limit=15),
      collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
      collect([Vendor.properties.riskState], limit=10),
      collect([Vendor.properties.conditionalAccessStatus], limit=10),
      collect([Vendor.properties.authenticationRequirement], limit=10),
      collect([Vendor.properties.clientAppUsed], limit=10),
      collect([Vendor.properties.deviceDetail.operatingSystem], limit=10),
      collect([Vendor.properties.deviceDetail.browser], limit=10),
      min(@timestamp, as=FirstSeen),
      max(@timestamp, as=LastSeen)
    ])
| sort(TotalCount, order=desc, limit=200)


// --- Sub-query B: Non-interactive sign-ins (token replay, app access) ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{upn}}/i
| Vendor.properties.isInteractive = "false"
| groupBy([source.ip, Vendor.properties.location.city, Vendor.properties.location.countryOrRegion],
    function=[
      count(as=TotalCount),
      collect([Vendor.properties.appDisplayName], limit=20),
      collect([Vendor.properties.status.errorCode], limit=15),
      collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
      collect([Vendor.properties.conditionalAccessStatus], limit=10),
      min(@timestamp, as=FirstSeen),
      max(@timestamp, as=LastSeen)
    ])
| sort(TotalCount, order=desc, limit=200)
```

### Stage 5 — BEC persistence hunt

- **Run:** when Stage 4 confirms compromised accounts
- **Purpose:** Hunt for inbox rules (especially DeleteMessage=True / StopProcessingRules), mail forwarding changes, mailbox permission grants, and OAuth consent on compromised accounts. These are the primary BEC persistence TTPs.

**Microsoft Sentinel (KQL)**

```kql
let TargetUPN = "{{upn}}";
let AttackerIP = "{{attacker_ip}}";
let Lookback = {{lookback}};
// Section A: Inbox rules (the #1 BEC persistence mechanism)
let InboxRules = CloudAppEvents
    | where Timestamp > ago(Lookback)
    | where AccountId =~ TargetUPN or AccountDisplayName has split(TargetUPN, "@")[0]
    | where ActionType in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
        "UpdateInboxRules", "Remove-InboxRule", "Disable-InboxRule")
    | extend RawParams = tostring(RawEventData)
    | project Timestamp, ActionType, AccountId, IPAddress,
        RawParams = substring(RawParams, 0, 2000)
    | extend Section = "A_InboxRules";
// Section B: Mail forwarding configuration
let Forwarding = CloudAppEvents
    | where Timestamp > ago(Lookback)
    | where AccountId =~ TargetUPN or AccountDisplayName has split(TargetUPN, "@")[0]
    | where ActionType == "Set-Mailbox"
    | where tostring(RawEventData) has_any ("ForwardingSmtpAddress", "ForwardingAddress",
        "DeliverToMailboxAndForward", "RedirectTo")
    | extend RawParams = tostring(RawEventData)
    | project Timestamp, ActionType, AccountId, IPAddress,
        RawParams = substring(RawParams, 0, 2000)
    | extend Section = "B_Forwarding";
// Section C: Mailbox permission grants (SendAs, FullAccess, delegation)
let Permissions = CloudAppEvents
    | where Timestamp > ago(Lookback)
    | where AccountId =~ TargetUPN or AccountDisplayName has split(TargetUPN, "@")[0]
    | where ActionType has_any ("MailboxPermission", "RecipientPermission",
        "FolderPermission", "MailboxLogin")
    | extend RawParams = tostring(RawEventData)
    | project Timestamp, ActionType, AccountId, IPAddress,
        RawParams = substring(RawParams, 0, 2000)
    | extend Section = "C_Permissions";
// Section D: OAuth / consent grants (illicit app consent for persistence)
let OAuthConsent = CloudAppEvents
    | where Timestamp > ago(Lookback)
    | where AccountId =~ TargetUPN or AccountDisplayName has split(TargetUPN, "@")[0]
    | where ActionType in ("Consent to application.", "Add OAuth2PermissionGrant.",
        "Add app role assignment to user.", "Add delegated permission grant.",
        "Add service principal.", "Add service principal credentials.")
    | extend RawParams = tostring(RawEventData)
    | project Timestamp, ActionType, AccountId, IPAddress,
        RawParams = substring(RawParams, 0, 2000)
    | extend Section = "D_OAuthConsent";
// Section E: MFA method changes (attacker registering their own MFA)
let MFAChanges = CloudAppEvents
    | where Timestamp > ago(Lookback)
    | where AccountId =~ TargetUPN or AccountDisplayName has split(TargetUPN, "@")[0]
    | where ActionType has_any ("Update user.", "Register security info",
        "User registered security info", "Delete security info",
        "User deleted security info")
    | where tostring(RawEventData) has_any ("StrongAuthentication", "PhoneNumber",
        "AuthenticatorApp", "SecurityInfo", "Fido2")
    | extend RawParams = tostring(RawEventData)
    | project Timestamp, ActionType, AccountId, IPAddress,
        RawParams = substring(RawParams, 0, 2000)
    | extend Section = "E_MFAChanges";
union isfuzzy=true
    (InboxRules | extend SortTime = Timestamp),
    (Forwarding | extend SortTime = Timestamp),
    (Permissions | extend SortTime = Timestamp),
    (OAuthConsent | extend SortTime = Timestamp),
    (MFAChanges | extend SortTime = Timestamp)
| sort by Section asc, SortTime asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// BEC Stage 5 — BEC persistence hunt.
// Goal: inbox rules (esp. delete/StopProcessing), mail forwarding, mailbox
//   permission grants, OAuth consent, and MFA-method changes on {{upn}}.
// Source: Microsoft 365 unified audit log via the M365 connector
//   (#Vendor="microsoft" #event.module=m365 — verified, config/ngsiem/ngsiem_rules.md §4).
//   Operations are in Vendor.Operation; Exchange and AzureActiveDirectory workloads
//   both flow through this module (Vendor.Workload distinguishes them).
//   Forwarding/rule parameters are in the raw event (Vendor.* / @rawstring) — inspect
//   the matched rows for ForwardingSmtpAddress / DeleteMessage / StopProcessingRules.

// --- Sub-query A: Inbox rules ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| in(field=Vendor.Operation, values=["New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "UpdateInboxRules", "Remove-InboxRule", "Disable-InboxRule"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Mail forwarding configuration ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| Vendor.Operation = "Set-Mailbox"
| @rawstring = /ForwardingSmtpAddress|ForwardingAddress|DeliverToMailboxAndForward|RedirectTo/i
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query C: Mailbox permission grants (SendAs, FullAccess, delegation) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| Vendor.Operation = /MailboxPermission|RecipientPermission|FolderPermission|MailboxLogin/i
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query D: OAuth / consent grants (illicit app consent for persistence) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| in(field=Vendor.Operation, values=["Consent to application.", "Add OAuth2PermissionGrant.",
    "Add app role assignment to user.", "Add delegated permission grant.",
    "Add service principal.", "Add service principal credentials."])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query E: MFA method changes (attacker registering their own MFA) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| Vendor.Operation = /security info|Update user/i
| @rawstring = /StrongAuthentication|PhoneNumber|AuthenticatorApp|SecurityInfo|Fido2/i
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 6 — Attacker email activity

- **Run:** when Stage 4 confirms compromised accounts
- **Purpose:** Check whether the attacker sent emails from compromised accounts — Send, SendAs, SendOnBehalf operations. Detects BEC payoff phase (invoice fraud, payment redirection, internal phishing).

**Microsoft Sentinel (KQL)**

```kql
let TargetUPN = "{{upn}}";
let AttackerIP = "{{attacker_ip}}";
let Lookback = {{lookback}};
// Outbound emails sent from the compromised account
let SentEmails = EmailEvents
    | where Timestamp > ago(Lookback)
    | where SenderFromAddress =~ TargetUPN or SenderMailFromAddress =~ TargetUPN
    | where EmailDirection == "Outbound" or EmailDirection == "Intra-org"
    | project
        Timestamp,
        Subject,
        SenderFromAddress,
        RecipientEmailAddress,
        SenderIPv4,
        EmailDirection,
        ThreatTypes,
        DeliveryAction,
        NetworkMessageId;
// Exchange Send/SendAs/SendOnBehalf operations (OfficeActivity)
let SendOps = OfficeActivity
    | where TimeGenerated > ago(Lookback)
    | where OfficeWorkload == "Exchange"
    | where UserId =~ TargetUPN
    | where Operation in ("Send", "SendAs", "SendOnBehalf")
    | where isempty(AttackerIP) or ClientIP has AttackerIP
    | project
        Timestamp = TimeGenerated,
        Operation,
        UserId,
        ClientIP,
        OfficeObjectId,
        ExternalAccess;
union
    (SentEmails | extend Section = "A_SentEmails", SortTime = Timestamp),
    (SendOps | extend Section = "B_SendOps", SortTime = Timestamp)
| sort by Section asc, SortTime asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// BEC Stage 6 — Attacker email activity (the BEC payoff phase).
// Goal: did the attacker send mail from the compromised account {{upn}} — outbound
//   or intra-org (invoice fraud, payment redirection, internal phishing).
// Sub-query A: Defender advanced-hunting EmailEvents (windows-defender-365) for the
//   sent mail itself. Sub-query B: Exchange Send / SendAs / SendOnBehalf operations
//   from the M365 unified audit log (#event.module=m365).

// --- Sub-query A: Outbound / intra-org mail sent from the compromised account ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| Vendor.properties.SenderFromAddress = /{{upn}}/i OR Vendor.properties.SenderMailFromAddress = /{{upn}}/i
| Vendor.properties.EmailDirection = /Outbound|Intra-org/i
| table([@timestamp, Vendor.properties.Subject, Vendor.properties.SenderFromAddress,
         Vendor.properties.RecipientEmailAddress, Vendor.properties.SenderIPv4,
         Vendor.properties.EmailDirection, Vendor.properties.DeliveryAction,
         Vendor.properties.NetworkMessageId], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: Exchange Send / SendAs / SendOnBehalf operations ---

#Vendor="microsoft" #event.module=m365
| Vendor.Workload = "Exchange"
| Vendor.UserId = /{{upn}}/i
| in(field=Vendor.Operation, values=["Send", "SendAs", "SendOnBehalf"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP,
         Vendor.ExternalAccess], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

### Stage 7 — Attacker IP tenant sweep

- **Run:** when attacker IP is identified from Stage 4
- **Purpose:** Scope the attacker IP across the entire tenant. Identifies all accounts the attacker attempted or succeeded in accessing — not just the accounts from the original alert. Critical for finding unreported compromises.

**Microsoft Sentinel (KQL)**

```kql
let AttackerIP = "{{attacker_ip}}";
let Lookback = {{lookback}};
let Interactive = SigninLogs
    | where TimeGenerated > ago(Lookback)
    | where IPAddress == AttackerIP
    | extend
        City = tostring(LocationDetails.city),
        Country = tostring(LocationDetails.countryOrRegion)
    | summarize
        InteractiveCount = count(),
        SuccessCount = countif(ResultType == 0),
        FailedCount = countif(ResultType != 0),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        Apps = make_set(AppDisplayName),
        ResultTypes = make_set(ResultType),
        Locations = make_set(strcat(City, ", ", Country)),
        RiskLevels = make_set(RiskLevelDuringSignIn),
        CAStatuses = make_set(ConditionalAccessStatus)
      by UserPrincipalName;
let NonInteractive = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(Lookback)
    | where IPAddress == AttackerIP
    | summarize
        NonInteractiveCount = count(),
        NISuccessCount = countif(ResultType == 0),
        NIFirstSeen = min(TimeGenerated),
        NILastSeen = max(TimeGenerated),
        NIApps = make_set(AppDisplayName)
      by UserPrincipalName;
Interactive
| join kind=leftouter NonInteractive on UserPrincipalName
| project
    UserPrincipalName,
    InteractiveCount,
    SuccessCount,
    FailedCount,
    NonInteractiveCount = coalesce(NonInteractiveCount, 0),
    NISuccessCount = coalesce(NISuccessCount, 0),
    TotalEvents = InteractiveCount + coalesce(NonInteractiveCount, 0),
    FirstSeen,
    LastSeen = max_of(LastSeen, coalesce(NILastSeen, datetime(null))),
    Apps,
    Locations,
    RiskLevels,
    CAStatuses,
    ResultTypes
| sort by SuccessCount desc, TotalEvents desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// BEC Stage 7 — Attacker IP tenant sweep.
// Goal: scope {{attacker_ip}} across the whole tenant — every account the attacker
//   touched, not just the alert's. Critical for finding unreported compromises.
// Source: Entra ID sign-ins (entraid connector, dataset entraid.signin — verified).
//   A successful sign-in has Vendor.properties.status.errorCode = "0".

// --- Sub-query A: Interactive sign-ins from the attacker IP, per account ---

#event.module=entraid #event.dataset="entraid.signin"
| source.ip = "{{attacker_ip}}"
| Vendor.properties.isInteractive = "true"
| groupBy([Vendor.properties.userPrincipalName], function=[
    count(as=InteractiveCount),
    count(field=Vendor.properties.status.errorCode, distinct=true, as=DistinctResultCodes),
    collect([Vendor.properties.status.errorCode], limit=20),
    collect([Vendor.properties.appDisplayName], limit=20),
    collect([Vendor.properties.location.countryOrRegion], limit=10),
    collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
    collect([Vendor.properties.conditionalAccessStatus], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(InteractiveCount, order=desc, limit=200)


// --- Sub-query B: Non-interactive sign-ins from the attacker IP, per account ---

#event.module=entraid #event.dataset="entraid.signin"
| source.ip = "{{attacker_ip}}"
| Vendor.properties.isInteractive = "false"
| groupBy([Vendor.properties.userPrincipalName], function=[
    count(as=NonInteractiveCount),
    collect([Vendor.properties.status.errorCode], limit=20),
    collect([Vendor.properties.appDisplayName], limit=20),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(NonInteractiveCount, order=desc, limit=200)


// --- Sub-query C: Successful sign-ins only (errorCode 0) — highest priority ---

#event.module=entraid #event.dataset="entraid.signin"
| source.ip = "{{attacker_ip}}"
| Vendor.properties.status.errorCode = "0"
| groupBy([Vendor.properties.userPrincipalName], function=[
    count(as=SuccessCount),
    collect([Vendor.properties.appDisplayName], limit=20),
    collect([Vendor.properties.isInteractive], limit=5),
    min(@timestamp, as=FirstSuccess),
    max(@timestamp, as=LastSuccess)
  ])
| sort(SuccessCount, order=desc, limit=200)
```

**Definitions**

- **Broad Scope Principle** — Every BEC investigation starts broad. The alert identifies one NetworkMessageId, but campaigns typically deliver the same payload to many recipients sharing the same sender and subject. Stage 0 expands the single alert into the full campaign set before any narrow analysis runs. Operating on a single NetworkMessageId leads to under-blocked attackers (some senders escape MDO blocks because their addresses never appear in Stage 1's narrow query) and missed clickers (other recipients whose clicks are outside the alert's NetworkMessageId scope). Always expand first, then narrow.
- **BEC Persistence** — Techniques an attacker uses to maintain access to a compromised mailbox: inbox rules that delete evidence (DeleteMessage=True), mail forwarding to external addresses, mailbox delegation grants, and OAuth app consent.
- **AiTM Token Theft** — Adversary-in-the-Middle attack where the phishing page proxies the real Microsoft login, capturing the session token after MFA completion. The attacker replays the stolen token — MFA is not re-challenged because the token already satisfies the authentication requirement.
- **Exposure Time** — Duration between email delivery to inbox and remediation (ZAP, admin purge, or user deletion). ExposureMinutes = -1 means never remediated.
- **MDO Tenant Block** — A block entry in Microsoft Defender for Office 365 Tenant Allow/Block List that prevents delivery of emails from a specific sender address or containing a specific URL. Blocks should be submitted for all confirmed malicious senders and URLs before case closure.

---

## Command & Control (C2) Behavioural Hunt (`command-and-control`)

Behavioural detection of command-and-control activity when no IOC is yet known: beaconing (regular-interval callbacks), DNS tunnelling, long-duration low-volume implant keep-alive sessions, and LOLBin-initiated outbound callbacks. Reactive IOC matching is covered by the ioc-hunt playbook; this playbook finds C2 from behaviour alone. DeviceNetworkEvents carries no byte counts, so regularity and volume are inferred from connection timing and frequency (see per-stage comments for the firewall-log variants that add byte fidelity). Stage 1 always runs; Stages 2-4 are conditional on prior findings.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `device_name` | string | — | DeviceName / hostname to hunt on (the host suspected of C2 activity). |
| `lookback` | string | `7d` | Time range to investigate (default 7d). |
| `process_name` | string | `__NONE__` | Optional process to focus on (e.g. powershell.exe). Set to __NONE__ to scan all LOLBins. |

### Stage 1 — Beaconing detection

- **Run:** ALWAYS — entry point; surfaces candidate C2 destinations and processes.
- **Purpose:** Regular-interval outbound connections (low timing jitter) from LOLBins to a single external destination.

**Microsoft Sentinel (KQL)**

```kql
// Beaconing detection - regular-interval outbound callbacks from LOLBins.
// DeviceNetworkEvents carries no byte counts; regularity is inferred from
// inter-connection timing (low jitter ratio = automated beacon). For byte-size
// fingerprinting, pivot to firewall logs (CommonSecurityLog) on a candidate IP.
let lookback = {{lookback}};
let device = "{{device_name}}";
let proc = "{{process_name}}";
let LOLBins = dynamic(["powershell.exe","pwsh.exe","rundll32.exe","mshta.exe",
                       "wscript.exe","cscript.exe","certutil.exe","regsvr32.exe",
                       "bitsadmin.exe","msbuild.exe","installutil.exe","msiexec.exe"]);
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where DeviceName =~ device
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))
| where (proc == "__NONE__" and InitiatingProcessFileName in~ (LOLBins))
     or (proc != "__NONE__" and InitiatingProcessFileName =~ proc)
| sort by DeviceName asc, InitiatingProcessFileName asc, RemoteIP asc, TimeGenerated asc
| serialize
| extend grp = strcat(DeviceName, "|", InitiatingProcessFileName, "|", RemoteIP)
| extend DeltaSec = iff(prev(grp) == grp, datetime_diff('second', TimeGenerated, prev(TimeGenerated)), long(null))
| where isnotnull(DeltaSec) and DeltaSec > 0
| summarize
    IntervalSamples = count(),
    AvgIntervalSec = avg(DeltaSec),
    StdevIntervalSec = stdev(DeltaSec),
    Ports = make_set(RemotePort, 20),
    Domains = make_set(RemoteUrl, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by DeviceName, InitiatingProcessFileName, RemoteIP
| extend Connections = IntervalSamples + 1
| extend JitterRatio = round(StdevIntervalSec / AvgIntervalSec, 3)
// Low jitter + enough samples + non-trivial interval = beacon candidate.
| where Connections >= 6 and AvgIntervalSec >= 30 and JitterRatio < 0.30
| project DeviceName, Process = InitiatingProcessFileName, RemoteIP, Ports, Domains,
          Connections, AvgIntervalSec = round(AvgIntervalSec, 1), JitterRatio,
          FirstSeen, LastSeen
| sort by JitterRatio asc, Connections desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Beaconing detection - repeated outbound callbacks from LOLBins to a single
// remote IP. NetworkConnectIP4 carries no byte counts; this surfaces high-
// repetition destinations and their rough cadence (Span / Connections). For
// true interval-jitter analysis, export the per-connection timestamps for a
// candidate RemoteAddressIP4 and inspect the spacing directly.
#event_simpleName=NetworkConnectIP4
| ComputerName = /{{device_name}}/i
| RemoteAddressIP4 != /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/
| FileName = /^(powershell\.exe|pwsh\.exe|rundll32\.exe|mshta\.exe|wscript\.exe|cscript\.exe|certutil\.exe|regsvr32\.exe|bitsadmin\.exe|msbuild\.exe|installutil\.exe|msiexec\.exe)$/i
| groupBy([ComputerName, FileName, RemoteAddressIP4, RemotePort],
          function=[count(as=Connections), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| SpanSec := (LastSeen - FirstSeen) / 1000
| AvgIntervalSec := SpanSec / Connections
| Connections >= 6
| sort(Connections, order=desc)
```

### Stage 2 — DNS tunnelling patterns

- **Run:** When Stage 1 is inconclusive or DNS-based C2 is suspected (high-volume DNS to one domain).
- **Purpose:** High query volume with long/high-entropy subdomains under a single parent domain; uncommon record types where DNS logs are present.

**Microsoft Sentinel (KQL)**

```kql
// DNS tunnelling - abnormal query patterns to a single parent domain.
// MDE DeviceNetworkEvents exposes the FQDN in RemoteUrl but NOT the DNS record
// type. Where the DNS Analytics connector is present, the DnsEvents variant at
// the bottom adds record-type (TXT/NULL/CNAME) and query-volume fidelity.
let lookback = {{lookback}};
let device = "{{device_name}}";
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where DeviceName =~ device
| where isnotempty(RemoteUrl)
| extend Labels = split(RemoteUrl, ".")
| where array_length(Labels) >= 2
| extend ParentDomain = strcat(tostring(Labels[array_length(Labels) - 2]), ".", tostring(Labels[array_length(Labels) - 1]))
| extend Subdomain = tostring(Labels[0])
| extend SubLen = strlen(Subdomain)
| summarize
    QueryCount = count(),
    DistinctSubdomains = dcount(RemoteUrl),
    MaxSubdomainLen = max(SubLen),
    AvgSubdomainLen = round(avg(SubLen), 1),
    Processes = make_set(InitiatingProcessFileName, 10),
    SampleFqdns = make_set(RemoteUrl, 15),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by DeviceName, ParentDomain
// Tunnelling signature: many unique, long subdomains under one parent domain.
| where DistinctSubdomains >= 50 or MaxSubdomainLen >= 40
| project DeviceName, ParentDomain, QueryCount, DistinctSubdomains,
          MaxSubdomainLen, AvgSubdomainLen, Processes, SampleFqdns, FirstSeen, LastSeen
| sort by DistinctSubdomains desc, MaxSubdomainLen desc
// --- Optional: DNS Analytics connector variant (record types + volume) ---
// DnsEvents
// | where TimeGenerated > ago(lookback) and Computer has device
// | where QueryType in ("TXT", "NULL", "CNAME")
// | summarize QueryCount = count(), DistinctNames = dcount(Name) by ClientIP, QueryType
// | where QueryCount > 100
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// DNS tunnelling - high query volume and long subdomains under a single parent
// domain. Falcon DnsRequest carries DomainName (the queried FQDN). Long, high-
// cardinality subdomain labels under one registrable parent = tunnelling.
#event_simpleName=DnsRequest
| ComputerName = /{{device_name}}/i
| regex("^(?<sub>[^.]+)\\.(?<parent>.+)$", field=DomainName)
| SubLen := length("sub")
| groupBy([ComputerName, parent],
          function=[count(as=QueryCount), count(field=DomainName, distinct=true, as=DistinctSubdomains), max("SubLen", as=MaxSubLen)])
| DistinctSubdomains >= 50 OR MaxSubLen >= 40
| sort(DistinctSubdomains, order=desc)
```

### Stage 3 — Long-duration low-volume sessions

- **Run:** When Stage 1 surfaces a candidate destination, or to catch slow beacons Stage 1's interval test missed.
- **Purpose:** Persistent outbound contact spread over a long window with few connections - implant keep-alive.

**Microsoft Sentinel (KQL)**

```kql
// Long-duration, low-volume sessions - implant keep-alive.
// True byte volume needs firewall logs (CommonSecurityLog); from
// DeviceNetworkEvents we approximate with a long FirstSeen->LastSeen span and a
// low connection count to a single external destination (slow check-ins).
let lookback = {{lookback}};
let device = "{{device_name}}";
let MicrosoftDomains = dynamic(["microsoft.com","windowsupdate.com","windows.com",
                                "office.com","office365.com","azure.com","azureedge.net",
                                "msftncsi.com","msedge.net","live.com","skype.com",
                                "akamaitechnologies.com","akamai.net","cloudflare.com",
                                "digicert.com","msft.net"]);
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where DeviceName =~ device
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))
| where isempty(RemoteUrl) or not(RemoteUrl has_any (MicrosoftDomains))
| summarize
    Connections = count(),
    Ports = make_set(RemotePort, 20),
    Processes = make_set(InitiatingProcessFileName, 10),
    Domains = make_set(RemoteUrl, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by DeviceName, RemoteIP
| extend SessionSpanHours = round(datetime_diff('minute', LastSeen, FirstSeen) / 60.0, 2)
| extend ConnectionsPerHour = round(Connections / (SessionSpanHours + 0.01), 2)
// Long span + few, low-rate connections = persistent low-volume session.
| where SessionSpanHours >= 1 and Connections between (2 .. 60) and ConnectionsPerHour <= 12
| project DeviceName, RemoteIP, Domains, Ports, Processes, Connections,
          SessionSpanHours, ConnectionsPerHour, FirstSeen, LastSeen
| sort by SessionSpanHours desc, ConnectionsPerHour asc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Long-duration, low-volume sessions - implant keep-alive. NetworkConnectIP4
// has no byte counts; approximate with a long first->last span and a low
// connection count to a single external destination (slow check-ins).
#event_simpleName=NetworkConnectIP4
| ComputerName = /{{device_name}}/i
| RemoteAddressIP4 != /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/
| groupBy([ComputerName, RemoteAddressIP4],
          function=[count(as=Connections), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| SpanHours := (LastSeen - FirstSeen) / 3600000
| ConnectionsPerHour := Connections / (SpanHours + 0.01)
| SpanHours >= 1 AND Connections >= 2 AND Connections <= 60 AND ConnectionsPerHour <= 12
| sort(SpanHours, order=desc)
```

### Stage 4 — LOLBin C2 callbacks

- **Run:** When Stage 1 or 3 implicates a LOLBin, or to confirm process to network attribution for a candidate destination.
- **Purpose:** LOLBin processes initiating outbound connections to non-Microsoft destinations on non-standard ports, with parent-process context.

**Microsoft Sentinel (KQL)**

```kql
// LOLBin C2 callbacks - LOLBin processes calling out to non-Microsoft
// destinations on non-standard ports, with parent-process context for
// injection / living-off-the-land chains.
let lookback = {{lookback}};
let device = "{{device_name}}";
let proc = "{{process_name}}";
let LOLBins = dynamic(["powershell.exe","pwsh.exe","rundll32.exe","mshta.exe",
                       "wscript.exe","cscript.exe","certutil.exe","regsvr32.exe",
                       "bitsadmin.exe","msbuild.exe","installutil.exe","msiexec.exe"]);
let StandardPorts = dynamic([80, 443, 53, 123, 389, 636]);
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where DeviceName =~ device
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))
| where (proc == "__NONE__" and InitiatingProcessFileName in~ (LOLBins))
     or (proc != "__NONE__" and InitiatingProcessFileName =~ proc)
| where RemotePort !in (StandardPorts)
| summarize
    Connections = count(),
    Ports = make_set(RemotePort, 20),
    Domains = make_set(RemoteUrl, 10),
    CmdLines = make_set(InitiatingProcessCommandLine, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by DeviceName, Process = InitiatingProcessFileName,
     ParentProcess = InitiatingProcessParentFileName, RemoteIP,
     AccountName = InitiatingProcessAccountName
| project DeviceName, Process, ParentProcess, AccountName, RemoteIP, Ports,
          Domains, CmdLines, Connections, FirstSeen, LastSeen
| sort by Connections desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// LOLBin C2 callbacks - LOLBins calling out to non-Microsoft destinations on
// non-standard ports, with parent-process context.
#event_simpleName=NetworkConnectIP4
| ComputerName = /{{device_name}}/i
| RemoteAddressIP4 != /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/
| FileName = /^(powershell\.exe|pwsh\.exe|rundll32\.exe|mshta\.exe|wscript\.exe|cscript\.exe|certutil\.exe|regsvr32\.exe|bitsadmin\.exe|msbuild\.exe|installutil\.exe|msiexec\.exe)$/i
| !in(RemotePort, values=["80", "443", "53", "123", "389", "636"])
| groupBy([ComputerName, FileName, ParentBaseFileName, RemoteAddressIP4, RemotePort],
          function=[count(as=Connections), collect([CommandLine], limit=3)])
| sort(Connections, order=desc)
```

---

## Credential Access / AD Attacks Investigation (`credential-access`)

Targets credential-theft TTPs directly (distinct from lateral-movement, which only side-checks them on a movement path): LSASS access / dumping, Kerberoasting and AS-REP roasting, DCSync / directory replication abuse, and correlated credential- theft detections. Stage 1 (LSASS) and Stage 4 (detections) always run; Stages 2-3 are conditional. Reuses the Kerberoasting RC4 pattern from the team's reference query set.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `device_name` | string | `__NONE__` | Host to scope endpoint stages (regex/substring matched). __NONE__ to scan all. |
| `target_account` | string | `__NONE__` | Account under investigation (optional; __NONE__ to scan all). |
| `dc_name` | string | `__NONE__` | Domain controller name for DCSync scoping (optional). |
| `lookback` | string | `7d` | Time range to investigate (default 7d). |

### Stage 1 — LSASS access / credential dumping

- **Run:** ALWAYS — primary endpoint credential-theft signal.
- **Purpose:** dumping tooling and behaviour targeting lsass (procdump, comsvcs, mimikatz).

**Microsoft Sentinel (KQL)**

```kql
// Credential Access Stage 1 — LSASS access / credential dumping.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where ActionType in ("OpenProcessApiCall", "ReadProcessMemory")
    | where FileName =~ "lsass.exe" or AdditionalFields has "lsass"
    | project Source = "DeviceEvents", Timestamp, DeviceName, Behaviour = ActionType,
        InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
),
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where FileName in~ ("procdump.exe", "procdump64.exe", "rundll32.exe", "taskmgr.exe",
        "nanodump.exe", "sqldumper.exe", "werfault.exe")
        or ProcessCommandLine has_any ("lsass", "MiniDump", "sekurlsa", "mimikatz", "comsvcs.dll")
    | where ProcessCommandLine has_any ("lsass", "MiniDump", "sekurlsa", "dump")
    | project Source = "DeviceProcessEvents", Timestamp, DeviceName, Behaviour = FileName,
        InitiatingProcessFileName, InitiatingProcessCommandLine = ProcessCommandLine,
        InitiatingProcessAccountName = AccountName
)
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Credential Access Stage 1 — LSASS access / credential dumping.
// ⚠ Falcon has no in-repo process-access/handle event, so this detects the dumping
//   TOOLING and behaviour via ProcessRollup2 CommandLine. Pair with Stage 4 detections
//   (CrowdStrike's CredentialDumping detections fire on the actual lsass handle).
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(procdump|procdump64|rundll32|taskmgr|nanodump|sqldumper|werfault)\.exe$/i OR CommandLine = /lsass|comsvcs\.dll.{0,20}minidump|minidump|sekurlsa|mimikatz/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine,
         ParentBaseFileName, ParentCommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 2 — Kerberoasting / AS-REP roasting

- **Run:** when AD credential-theft is suspected.
- **Purpose:** RC4/DES TGS requests (4769) and pre-auth-disabled accounts (4768).

**Microsoft Sentinel (KQL)**

```kql
// Credential Access Stage 2 — Kerberoasting / AS-REP roasting.
let lookback = {{lookback}};
let account = "{{target_account}}";
union isfuzzy=true
(
    SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where EventID == 4769
    | where TicketEncryptionType in ("0x17", "0x18")   // RC4 / DES = roastable
    | where ServiceName != "krbtgt" and ServiceName !endswith "$"
    | where account == "__NONE__" or TargetUserName has account or ServiceName has account
    | summarize RequestCount = count(), Services = make_set(ServiceName, 20),
        FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
      by Activity = "Kerberoasting (4769 RC4/DES)", TargetUserName, IpAddress
    | where RequestCount >= 5
),
(
    SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where EventID == 4768
    | where PreAuthType == "0"   // pre-auth not required = AS-REP roastable
    | where account == "__NONE__" or TargetUserName has account
    | summarize RequestCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
      by Activity = "AS-REP roasting (4768 no preauth)", TargetUserName, IpAddress
)
| sort by LastSeen desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Credential Access Stage 2 — Kerberoasting / AS-REP roasting.
// Windows security events via the verified windows module. TicketEncryptionType
//   0x17 (RC4) / 0x18 (DES) on 4769 = roastable SPN; 4768 with PreAuthType 0 =
//   AS-REP roastable account.

// --- Sub-query A: Kerberoasting (4769 RC4/DES) ---

#Vendor="microsoft" #event.module=windows EventCode=4769
| in(field=windows.EventData.TicketEncryptionType, values=["0x17", "0x18"])
| windows.EventData.ServiceName != "krbtgt"
| windows.EventData.ServiceName != /\$$/
| groupBy([windows.EventData.TargetUserName, windows.EventData.ServiceName,
           windows.EventData.IpAddress], function=[
    count(as=RequestCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| RequestCount >= 5
| sort(RequestCount, order=desc, limit=200)


// --- Sub-query B: AS-REP roasting (4768, pre-auth not required) ---

#Vendor="microsoft" #event.module=windows EventCode=4768
| windows.EventData.PreAuthType = "0"
| groupBy([windows.EventData.TargetUserName, windows.EventData.IpAddress], function=[
    count(as=RequestCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(RequestCount, order=desc, limit=200)
```

### Stage 3 — DCSync / directory replication abuse

- **Run:** when domain-level credential theft is suspected.
- **Purpose:** replication control-access rights (4662) requested by a non-DC account.

**Microsoft Sentinel (KQL)**

```kql
// Credential Access Stage 3 — DCSync / directory replication abuse.
let lookback = {{lookback}};
let dc = "{{dc_name}}";
union isfuzzy=true
(
    SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where EventID == 4662
    // DS-Replication-Get-Changes / -All control-access rights
    | where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        or Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    | where SubjectUserName !endswith "$"   // exclude DC machine accounts (legit replication)
    | project Source = "SecurityEvent(4662)", TimeGenerated, Computer,
        Actor = SubjectUserName, ObjectName, AccessMask
),
(
    IdentityDirectoryEvents
    | where Timestamp > ago(lookback)
    | where ActionType has "replication" or ActionType has "DCSync"
    | where dc == "__NONE__" or DestinationDeviceName has dc
    | project Source = "IdentityDirectoryEvents", TimeGenerated = Timestamp,
        Computer = DestinationDeviceName, Actor = AccountUpn,
        ObjectName = TargetAccountUpn, AccessMask = ""
)
| sort by TimeGenerated asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Credential Access Stage 3 — DCSync / directory replication abuse.
// Windows 4662 carrying the DS-Replication-Get-Changes control-access-right GUIDs,
//   requested by a NON-DC account, is the DCSync tell.
// ⚠ The replication GUID lives in the event Properties — matched here against
//   @rawstring. Confirm the discrete field (e.g. windows.EventData.Properties) on the
//   client repo and tighten the match if needed.
#Vendor="microsoft" #event.module=windows EventCode=4662
| @rawstring = /1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2/i
| windows.EventData.SubjectUserName != /\$$/
| table([@timestamp, host.hostname, windows.EventData.SubjectUserName,
         windows.EventData.ObjectName, windows.EventData.AccessMask], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 4 — Credential-theft detections

- **Run:** ALWAYS — surfaces vendor detections for the above TTPs.
- **Purpose:** correlated EDR/SIEM credential-access alerts.

**Microsoft Sentinel (KQL)**

```kql
// Credential Access Stage 4 — Credential-theft detections.
let lookback = {{lookback}};
let device = "{{device_name}}";
SecurityAlert
| where TimeGenerated > ago(lookback)
| where AlertName has_any ("credential", "LSASS", "pass-the-hash", "pass the hash",
    "kerberoast", "golden ticket", "silver ticket", "DCSync", "overpass",
    "AS-REP", "mimikatz", "credential dumping", "ntds")
| where device == "__NONE__" or Entities has device
| project TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
    Entities = substring(tostring(Entities), 0, 500)
| sort by TimeGenerated asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Credential Access Stage 4 — Credential-theft detections.
// Source: Falcon detection summary events filtered to credential-access tradecraft.
#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| DetectName = /credential|lsass|pass.the.hash|kerberoast|golden ticket|silver ticket|dcsync|mimikatz|ntds|credential dumping/i
| table([@timestamp, ComputerName, UserName, DetectName, DetectDescription,
         Severity, Tactic, Technique, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

**Definitions**

- **DCSync** — MITRE T1003.006 — abusing the directory replication protocol (DRSUAPI) to pull password hashes from a DC. Legitimate replication is between DCs; a request from a non-DC account is the tell.

---

## Data Exfiltration Investigation (`data-exfiltration`)

Multi-stage data exfiltration investigation. Stage 1 identifies abnormal download/upload volumes and DLP alerts for the target user. Stage 2 checks cloud application activity (SharePoint, OneDrive, Exchange) for bulk access or sharing events. Stage 3 correlates with network telemetry to identify external data transfer destinations.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `target_upn` | string | — | User Principal Name of the suspect account |
| `lookback` | string | — | KQL timespan for lookback window (default 30d) |
| `threshold_mb` | string | — | Download volume threshold in MB to flag as abnormal (default 500) |

### Stage 1 — Volume anomaly and DLP alerts

- **Run:** ALWAYS — baseline check for abnormal data movement and DLP triggers.

**Microsoft Sentinel (KQL)**

```kql
let target_user = "{{target_upn}}";
let lookback = {{lookback}};
let DLPAlerts = SecurityAlert
    | where TimeGenerated >= ago(lookback)
    | where Entities has target_user
    | where AlertName has_any ("DLP", "data loss", "exfiltration", "mass download",
                                "unusual volume", "sensitive data", "information protection")
    | project
        AlertTime = TimeGenerated,
        AlertName,
        Severity,
        Description,
        Entities;
let OfficeVolume = OfficeActivity
    | where TimeGenerated >= ago(lookback)
    | where UserId =~ target_user
    | where Operation in ("FileDownloaded", "FileUploaded", "FileSyncDownloadedFull",
                           "FileModifiedExtended", "FileCopied")
    | summarize
        DownloadCount = countif(Operation in ("FileDownloaded", "FileSyncDownloadedFull")),
        UploadCount = countif(Operation == "FileUploaded"),
        CopyCount = countif(Operation == "FileCopied"),
        UniqueFiles = dcount(SourceFileName),
        Sites = make_set(Site_Url)
      by bin(TimeGenerated, 1d), UserId;
union
(
    DLPAlerts
    | extend RecordType = "DLP_Alert"
    | project RecordType, TimeGenerated = AlertTime, Detail = AlertName,
              Severity, Extra = Description
),
(
    OfficeVolume
    | extend RecordType = "DailyVolume"
    | project RecordType, TimeGenerated,
              Detail = strcat("Downloads:", DownloadCount, " Uploads:", UploadCount,
                              " Copies:", CopyCount, " UniqueFiles:", UniqueFiles),
              Severity = "",
              Extra = tostring(Sites)
)
| sort by TimeGenerated desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Data Exfiltration Stage 1 — Volume anomaly and DLP alerts for {{target_upn}}.
// Sub-query A: DLP / exfiltration detections. ⚠ DLP alerting is client-dependent in
//   NG-SIEM. This uses Defender advanced-hunting AlertInfo (windows-defender-365);
//   where the client runs Netskope DLP instead, swap to:
//     #Vendor="netskope" #event.module=sse | Vendor.alert_type=/dlp/i
//   (Vendor.dlp_incident_id / Vendor.dlp_rule_count carry the DLP detail).
//   Sub-table discriminator is Vendor.Workload (e.g. "AlertInfo") — see phishing Stage 0 header.
// Sub-query B: daily file-operation volume from the M365 unified audit log
//   (#event.module=m365 — verified).

// --- Sub-query A: DLP / exfiltration alerts ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "AlertInfo"
| Vendor.properties.Title = /DLP|data loss|exfiltration|mass download|unusual volume|sensitive|information protection/i
| @rawstring = /{{target_upn}}/i
| table([@timestamp, Vendor.properties.Title, Vendor.properties.Severity,
         Vendor.properties.Category], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: Daily file-operation volume (downloads / uploads / copies) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_upn}}/i
| in(field=Vendor.Operation, values=["FileDownloaded", "FileUploaded",
    "FileSyncDownloadedFull", "FileModifiedExtended", "FileCopied"])
| bucket(span=1d, function=[
    count(as=TotalOps),
    count(field=Vendor.SourceFileName, distinct=true, as=UniqueFiles),
    collect([Vendor.Operation], limit=10),
    collect([Vendor.SiteUrl], limit=20)
  ])
| sort(@timestamp, order=desc, limit=200)
```

### Stage 2 — Cloud application file access

- **Run:** ALWAYS — check for bulk file access, external sharing, and mailbox forwarding.

**Microsoft Sentinel (KQL)**

```kql
let target_user = "{{target_upn}}";
let lookback = {{lookback}};
let BulkAccess = OfficeActivity
    | where TimeGenerated >= ago(lookback)
    | where UserId =~ target_user
    | where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileAccessed",
                           "FolderModified", "ListItemUpdated")
    | summarize
        EventCount = count(),
        UniqueFiles = dcount(SourceFileName),
        UniqueSites = dcount(Site_Url),
        Operations = make_set(Operation),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
      by bin(TimeGenerated, 1h), UserId;
let SharingEvents = OfficeActivity
    | where TimeGenerated >= ago(lookback)
    | where UserId =~ target_user
    | where Operation has_any ("SharingSet", "AddedToGroup", "AnonymousLinkCreated",
                                "CompanyLinkCreated", "SharingInvitationCreated",
                                "SecureLinkCreated")
    | project
        TimeGenerated,
        Operation,
        TargetUser = TargetUserOrGroupName,
        SourceFileName,
        Site_Url;
let MailForwarding = OfficeActivity
    | where TimeGenerated >= ago(lookback)
    | where UserId =~ target_user
    | where Operation in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule",
                           "UpdateInboxRules", "New-TransportRule")
    | project
        TimeGenerated,
        Operation,
        Parameters = tostring(Parameters);
union
(
    BulkAccess
    | extend RecordType = "BulkAccess"
    | project RecordType, TimeGenerated, Detail = strcat("Events:", EventCount,
              " Files:", UniqueFiles, " Sites:", UniqueSites),
              Extra = tostring(Operations)
),
(
    SharingEvents
    | extend RecordType = "Sharing"
    | project RecordType, TimeGenerated,
              Detail = strcat(Operation, " → ", TargetUser, " | ", SourceFileName),
              Extra = Site_Url
),
(
    MailForwarding
    | extend RecordType = "MailRule"
    | project RecordType, TimeGenerated,
              Detail = Operation,
              Extra = Parameters
)
| sort by TimeGenerated desc
| take 50
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Data Exfiltration Stage 2 — Cloud application file access for {{target_upn}}.
// Bulk file access, external sharing, and mailbox-forwarding rules from the M365
//   unified audit log (#Vendor="microsoft" #event.module=m365 — verified).
//   Operations are in Vendor.Operation; file/site detail in Vendor.SourceFileName /
//   Vendor.SiteUrl; sharing target in Vendor.TargetUserOrGroupName (inspect rows).

// --- Sub-query A: Bulk file access (hourly) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_upn}}/i
| in(field=Vendor.Operation, values=["FileDownloaded", "FileSyncDownloadedFull",
    "FileAccessed", "FolderModified", "ListItemUpdated"])
| bucket(span=1h, function=[
    count(as=EventCount),
    count(field=Vendor.SourceFileName, distinct=true, as=UniqueFiles),
    count(field=Vendor.SiteUrl, distinct=true, as=UniqueSites),
    collect([Vendor.Operation], limit=10)
  ])
| sort(EventCount, order=desc, limit=200)


// --- Sub-query B: External sharing events ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_upn}}/i
| Vendor.Operation = /SharingSet|AddedToGroup|AnonymousLinkCreated|CompanyLinkCreated|SharingInvitationCreated|SecureLinkCreated/i
| table([@timestamp, Vendor.Operation, Vendor.SourceFileName, Vendor.SiteUrl], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query C: Mailbox-forwarding / inbox rules (exfil via mail) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_upn}}/i
| in(field=Vendor.Operation, values=["Set-Mailbox", "New-InboxRule", "Set-InboxRule",
    "UpdateInboxRules", "New-TransportRule"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

### Stage 3 — Network exfiltration indicators

- **Run:** when Stage 1 or Stage 2 shows suspicious volume or access patterns.
- **Purpose:** correlate with endpoint network events to identify external

**Microsoft Sentinel (KQL)**

```kql
let target_user = "{{target_upn}}";
let lookback = {{lookback}};
let UserDevices = SigninLogs
    | where TimeGenerated >= ago(lookback)
    | where UserPrincipalName =~ target_user
    | where isnotempty(DeviceDetail.displayName)
    | summarize arg_max(TimeGenerated, *) by tostring(DeviceDetail.displayName)
    | project DeviceName = tostring(DeviceDetail.displayName);
let UploadEvents = DeviceNetworkEvents
    | where TimeGenerated >= ago(lookback)
    | where DeviceName in (UserDevices)
    | where ActionType == "ConnectionSuccess"
    | where RemotePort in (443, 80, 22, 21, 445)
    | where not(ipv4_is_private(RemoteIP))
    | summarize
        ConnectionCount = count(),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        Processes = make_set(InitiatingProcessFileName),
        Ports = make_set(RemotePort)
      by DeviceName, RemoteIP, RemoteUrl;
let LargeFileOps = DeviceFileEvents
    | where TimeGenerated >= ago(lookback)
    | where DeviceName in (UserDevices)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where FolderPath has_any ("usb", "removable", "external", "cloud",
                                 "onedrive", "dropbox", "google drive")
    | project
        TimeGenerated,
        DeviceName,
        FileName,
        FolderPath,
        ActionType,
        InitiatingProcessFileName;
union
(
    UploadEvents
    | extend RecordType = "NetworkUpload"
    | project RecordType, TimeGenerated = LastSeen,
              DeviceName,
              Detail = strcat(RemoteIP, " | Connections:", ConnectionCount,
                              " | Ports:", tostring(Ports)),
              Extra = strcat("Processes: ", tostring(Processes),
                             " | URL: ", RemoteUrl)
),
(
    LargeFileOps
    | extend RecordType = "SuspiciousFilePath"
    | project RecordType, TimeGenerated,
              DeviceName,
              Detail = strcat(ActionType, " | ", FileName),
              Extra = strcat(FolderPath, " via ", InitiatingProcessFileName)
)
| sort by TimeGenerated desc
| take 50
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Data Exfiltration Stage 3 — Network exfiltration indicators.
// Goal: external data-transfer destinations and copies to removable/cloud paths.
// Source: CrowdStrike Falcon endpoint telemetry (the NG-SIEM equivalent of Sentinel
//   DeviceNetworkEvents / DeviceFileEvents). Identify the user's device(s) first
//   (e.g. via account-compromise Stage 3/4 UserLogon), then scope these by
//   ComputerName. RFC1918 destinations are excluded via regex below.

// --- Sub-query A: Outbound connections to external hosts on common exfil ports ---

#event_simpleName=NetworkConnectIP4
| in(field=RemotePort, values=[443, 80, 22, 21, 445])
| RemoteAddressIP4 != /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)/
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=[
    count(as=ConnectionCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(ConnectionCount, order=desc, limit=200)


// --- Sub-query B: File operations to removable / cloud-sync paths ---

#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| TargetFileName = /usb|removable|external|onedrive|dropbox|google drive|googledrive/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

---

## Defence Evasion / Tamper Investigation (`defence-evasion`)

Hunts attempts to blind detection: security-log clearing, EDR/AV disablement and tamper, defensive-tool process kills, and correlated defense-evasion detections. Stages 1, 2 and 4 always run; Stage 3 is conditional. Defender exposes dedicated tamper/AV-config telemetry; on Falcon behavioural attempts come from ProcessRollup2 command-line analysis and sensor tamper detections (see .cql headers).

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `device_name` | string | `__NONE__` | Host to scope (regex/substring matched). __NONE__ to scan all. |
| `user` | string | `__NONE__` | Associated user account (optional; __NONE__ to scan all). |
| `lookback` | string | `7d` | Time range to investigate (default 7d). |

### Stage 1 — Security-log clearing

- **Run:** ALWAYS.
- **Purpose:** Security/log clearing via 1102/104 and wevtutil / Clear-EventLog.

**Microsoft Sentinel (KQL)**

```kql
// Defence Evasion Stage 1 — Security-log clearing.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where device == "__NONE__" or Computer has device
    | where EventID in (1102, 104)   // 1102 = Security log cleared, 104 = a log file cleared
    | project Source = strcat("SecurityEvent(", tostring(EventID), ")"),
        Timestamp = TimeGenerated, DeviceName = Computer,
        Account = SubjectUserName, Detail = Activity
),
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl ", "clear-log"))
        or (FileName in~ ("powershell.exe", "pwsh.exe")
            and ProcessCommandLine has_any ("Clear-EventLog", "Remove-EventLog", "wevtutil"))
    | project Source = "DeviceProcessEvents", Timestamp, DeviceName,
        Account = AccountName, Detail = ProcessCommandLine
)
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Defence Evasion Stage 1 — Security-log clearing.

// --- Sub-query A: Windows security log cleared (1102) / log file cleared (104) ---

#Vendor="microsoft" #event.module=windows
| in(field=EventCode, values=["1102", "104"])
| host.hostname = /{{device_name}}/i
| table([@timestamp, host.hostname, EventCode, windows.EventData.SubjectUserName], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: wevtutil cl / Clear-EventLog via process telemetry ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(wevtutil|powershell|pwsh)\.exe$/i
| CommandLine = /\bcl\b|clear-log|Clear-EventLog|Remove-EventLog/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 2 — EDR / AV disablement and tamper

- **Run:** ALWAYS.
- **Purpose:** Defender/AV disable, exclusion adds, EDR service stop, tamper attempts.

**Microsoft Sentinel (KQL)**

```kql
// Defence Evasion Stage 2 — EDR / AV disablement & tamper.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where ActionType has_any ("TamperingAttempt", "AntivirusDisabled",
        "DefenderConfigChanged", "SecurityControlConfigChanged")
    | project Source = "DeviceEvents", Timestamp, DeviceName, ActionType,
        InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
),
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where ProcessCommandLine has_any ("Set-MpPreference", "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring", "Add-MpPreference", "MpCmdRun", "fltMC", "sc stop",
        "sc config", "Stop-Service", "net stop")
    | where ProcessCommandLine has_any ("defend", "windefend", "sense", "csagent", "csfalcon",
        "crowdstrike", "sentinel", "sophos", "cylance", "carbonblack", "mpssvc")
    | project Source = "DeviceProcessEvents", Timestamp, DeviceName, FileName,
        ProcessCommandLine, InitiatingProcessFileName, AccountName
)
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Defence Evasion Stage 2 — EDR / AV disablement & tamper.
// ⚠ Falcon sensor tamper/uninstall surfaces as DetectionSummaryEvent (Stage 4);
//   behavioural attempts are caught here via ProcessRollup2 command-line analysis.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| CommandLine = /Set-MpPreference.{0,40}-Disable|DisableRealtimeMonitoring|DisableBehaviorMonitoring|Add-MpPreference.{0,20}-ExclusionPath|sc.{0,5}(stop|config).{0,25}(windefend|sense|csagent)|fltMC.{0,10}unload|net stop.{0,25}(windefend|sense|csfalcon|sophos|cylance|sentinel)/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

### Stage 3 — Defensive-tool process kills

- **Run:** when Stage 1 or 2 shows tamper signal.
- **Purpose:** taskkill / Stop-Process targeting security tooling.

**Microsoft Sentinel (KQL)**

```kql
// Defence Evasion Stage 3 — Defensive-tool process kills.
let lookback = {{lookback}};
let device = "{{device_name}}";
let secTools = dynamic(["MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "CSFalconService.exe",
    "CSFalconContainer.exe", "sophos", "cb.exe", "cylancesvc.exe", "xagt.exe",
    "SentinelAgent.exe", "SentinelOne", "SecurityHealthService.exe", "windefend"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where device == "__NONE__" or DeviceName has device
| where FileName in~ ("taskkill.exe", "ntsd.exe", "pskill.exe", "pskill64.exe")
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has "Stop-Process")
| where ProcessCommandLine has_any (secTools)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Defence Evasion Stage 3 — Defensive-tool process kills.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(taskkill|ntsd|pskill|pskill64|powershell|pwsh)\.exe$/i
| CommandLine = /MsMpEng|MsSense|SenseIR|CSFalcon|cylancesvc|SentinelAgent|SentinelOne|sophos|carbonblack|cb\.exe|xagt|SecurityHealthService|windefend/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

### Stage 4 — Defense-evasion detections

- **Run:** ALWAYS.
- **Purpose:** correlated EDR/SIEM defense-evasion alerts.

**Microsoft Sentinel (KQL)**

```kql
// Defence Evasion Stage 4 — Defense-evasion detections.
let lookback = {{lookback}};
let device = "{{device_name}}";
SecurityAlert
| where TimeGenerated > ago(lookback)
| where Tactics has "DefenseEvasion"
    or AlertName has_any ("tamper", "defender disabled", "antivirus disabled", "log cleared",
        "security product", "evasion", "uninstall", "exclusion")
| where device == "__NONE__" or Entities has device
| project TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
    Entities = substring(tostring(Entities), 0, 500)
| sort by TimeGenerated asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Defence Evasion Stage 4 — Defense-evasion detections.
#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| DetectName = /tamper|defender|antivirus|log clear|evasion|uninstall|exclusion|disable/i OR Tactic = /Defense Evasion/i
| table([@timestamp, ComputerName, UserName, DetectName, DetectDescription,
         Severity, Tactic, Technique, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

**Definitions**

- **Tamper Protection** — Vendor control that blocks modification/disabling of the security agent. Tamper attempts (MITRE T1562) are high-fidelity evasion indicators.

---

## Insider Threat / Data Staging Investigation (`insider-data-staging`)

Investigates a legitimate user staging data for exfiltration — distinct from data-exfiltration, which focuses on the external transfer itself. Covers bulk SharePoint/OneDrive pulls, local archiving/staging, removable-media writes, and mass print / personal-cloud egress. Stages 1-2 always run; Stages 3-4 are conditional.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `target_upn` | string | — | User under investigation (UPN). |
| `device_name` | string | `__NONE__` | User's device to scope endpoint stages (regex/substring). __NONE__ to scan all. |
| `lookback` | string | `14d` | Time range to investigate (default 14d). |

### Stage 1 — Bulk SharePoint / OneDrive pull

- **Run:** ALWAYS.
- **Purpose:** high-volume downloads / sync from cloud document stores.

**Microsoft Sentinel (KQL)**

```kql
// Insider / Data Staging Stage 1 — Bulk SharePoint / OneDrive pull.
let lookback = {{lookback}};
let upn = "{{target_upn}}";
OfficeActivity
| where TimeGenerated > ago(lookback)
| where UserId =~ upn
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileAccessed")
| summarize EventCount = count(), UniqueFiles = dcount(SourceFileName),
    UniqueSites = dcount(Site_Url), Operations = make_set(Operation)
  by bin(TimeGenerated, 1h), UserId
| where EventCount >= 50
| sort by EventCount desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Insider / Data Staging Stage 1 — Bulk SharePoint / OneDrive pull.
// Source: M365 unified audit log (verified m365 module).
#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_upn}}/i
| in(field=Vendor.Operation, values=["FileDownloaded", "FileSyncDownloadedFull", "FileAccessed"])
| bucket(span=1h, function=[
    count(as=EventCount),
    count(field=Vendor.SourceFileName, distinct=true, as=UniqueFiles),
    count(field=Vendor.SiteUrl, distinct=true, as=UniqueSites),
    collect([Vendor.Operation], limit=10)
  ])
| EventCount >= 50
| sort(EventCount, order=desc, limit=200)
```

### Stage 2 — Local staging / archiving

- **Run:** ALWAYS.
- **Purpose:** rar/7z/zip/Compress-Archive activity and archive files written to disk.

**Microsoft Sentinel (KQL)**

```kql
// Insider / Data Staging Stage 2 — Local staging / archiving.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where FileName in~ ("rar.exe", "winrar.exe", "7z.exe", "7za.exe", "zip.exe",
        "tar.exe", "makecab.exe", "powershell.exe", "pwsh.exe")
    | where ProcessCommandLine has_any (" a ", "-hp", "Compress-Archive", "-mx", " -r ",
        "makecab", ".rar", ".7z", ".zip")
    | project Source = "Archiving", Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
),
(
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FileName endswith ".rar" or FileName endswith ".7z" or FileName endswith ".zip"
        or FileName endswith ".tar" or FileName endswith ".gz" or FileName endswith ".cab"
    | project Source = "ArchiveFile", Timestamp, DeviceName,
        AccountName = InitiatingProcessAccountName, FileName, FolderPath
)
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Insider / Data Staging Stage 2 — Local staging / archiving.

// --- Sub-query A: Archive tooling via process telemetry ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(rar|winrar|7z|7za|zip|tar|makecab|powershell|pwsh)\.exe$/i
| CommandLine = /\ba\b|-hp|Compress-Archive|-mx|\s-r\s|makecab|\.rar|\.7z|\.zip/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Archive files written to disk ---

#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /\.(rar|7z|zip|tar|gz|cab)$/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 3 — Removable-media writes

- **Run:** when staging is observed and removable media is in scope.
- **Purpose:** USB/removable device connections and files copied to them.

**Microsoft Sentinel (KQL)**

```kql
// Insider / Data Staging Stage 3 — Removable-media writes.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where ActionType in ("UsbDriveMounted", "UsbDriveMount", "PnpDeviceConnected")
    | project Source = "USBMount", Timestamp, DeviceName, ActionType, FileName,
        FolderPath = AdditionalFields, InitiatingProcessFileName
),
(
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FolderPath has_any ("removable", "usb") or AdditionalFields has "Removable"
    | project Source = "USBWrite", Timestamp, DeviceName, ActionType, FileName,
        FolderPath, InitiatingProcessFileName
)
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Insider / Data Staging Stage 3 — Removable-media writes.

// --- Sub-query A: Removable-media / USB device connections ---
// ⚠ Confirm Falcon USB device fields (DeviceManufacturer/Product/SerialNumber) against
//   the client repo; some sensors use DeviceInstanceId / ProductName variants.

#event_simpleName=/^(RemovableMediaConnected|USBDeviceConnected)$/
| ComputerName = /{{device_name}}/i
| table([@timestamp, ComputerName, DeviceManufacturer, DeviceProduct, DeviceSerialNumber], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Files written to removable paths ---

#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /removable|\\Device\\Harddisk[1-9]/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 4 — Mass print / cloud egress

- **Run:** when staging is observed.
- **Purpose:** bulk print jobs and connections to personal file-sharing services.

**Microsoft Sentinel (KQL)**

```kql
// Insider / Data Staging Stage 4 — Mass print / cloud egress.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where ActionType has "Print"
    | summarize PrintJobs = count(), Docs = make_set(FileName, 30),
        FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
      by Source = "Print", DeviceName, InitiatingProcessAccountName
    | where PrintJobs >= 20
),
(
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where ActionType == "ConnectionSuccess"
    | where RemoteUrl has_any ("dropbox", "wetransfer", "mega.nz", "drive.google",
        "sendspace", "anonfiles", "gofile", "mediafire", "pastebin")
    | summarize ConnCount = count(), Urls = make_set(RemoteUrl, 30),
        FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
      by Source = "CloudEgress", DeviceName, InitiatingProcessFileName
)
| sort by LastSeen desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Insider / Data Staging Stage 4 — Mass print / cloud egress.
// ⚠ Falcon has no print-job telemetry in this repo's vocabulary — the print portion is
//   Defender-only. This covers personal-cloud egress via DNS + network connections.

// --- Sub-query A: DNS lookups to personal file-sharing services ---

#event_simpleName=DnsRequest
| ComputerName = /{{device_name}}/i
| DomainName = /dropbox|wetransfer|mega\.nz|drive\.google|sendspace|anonfiles|gofile|mediafire|pastebin/i
| groupBy([ComputerName, DomainName], function=[
    count(as=Lookups),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(Lookups, order=desc, limit=200)


// --- Sub-query B: Outbound connections from the host (correlate with A) ---

#event_simpleName=NetworkConnectIP4
| ComputerName = /{{device_name}}/i
| RemoteAddressIP4 != /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)/
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=[
    count(as=ConnCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(ConnCount, order=desc, limit=200)
```

**Definitions**

- **Data Staging** — MITRE T1074 — collecting and consolidating data (often into archives) prior to exfiltration. For insiders the collection itself, by a legitimate account, is the investigable behaviour.

---

## IOC Hunt (`ioc-hunt`)

Fast IOC presence sweep across a Sentinel workspace. Stage 1 runs a single union query across all major tables (network, sign-in, firewall, alerts, threat intel) to determine whether any of the supplied IOCs have been seen. Stage 2 is a conditional context pivot that pulls surrounding activity from the table and time window where hits were found.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `iocs` | string | — | Comma-separated IOC values formatted as KQL dynamic list content (IPs, domains, hashes) |
| `lookback` | string | — | KQL timespan for lookback window (default 30d) |
| `hit_table` | string | — | Table name from Stage 1 hit (used in Stage 2) |
| `hit_time` | string | — | ISO timestamp of a Stage 1 hit to pivot around (used in Stage 2) |
| `hit_device` | string | — | DeviceProduct or DeviceName from Stage 1 hit (used in Stage 2) |

### Stage 1 — IOC presence sweep

- **Run:** ALWAYS — single query replaces 4-5 sequential table searches.

**Microsoft Sentinel (KQL)**

```kql
let ioc_list = dynamic([{{iocs}}]);
let lookback = {{lookback}};
union
(
    DeviceNetworkEvents
    | where TimeGenerated >= ago(lookback)
    | where RemoteIP in (ioc_list) or RemoteUrl has_any (ioc_list)
    | project
        SourceTable = "DeviceNetworkEvents",
        TimeGenerated,
        Indicator = RemoteIP,
        DeviceOrSource = DeviceName,
        User = InitiatingProcessAccountName,
        Detail = strcat(ActionType, " | ", InitiatingProcessFileName, " → ", RemoteIP, ":", RemotePort),
        Extra = InitiatingProcessCommandLine
),
(
    SigninLogs
    | where TimeGenerated >= ago(lookback)
    | where IPAddress in (ioc_list)
    | project
        SourceTable = "SigninLogs",
        TimeGenerated,
        Indicator = IPAddress,
        DeviceOrSource = tostring(DeviceDetail.displayName),
        User = UserPrincipalName,
        Detail = strcat(ResultType, " | ", AppDisplayName, " | Risk:", RiskLevelDuringSignIn),
        Extra = Location
),
(
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where SourceIP in (ioc_list) or DestinationIP in (ioc_list)
    | project
        SourceTable = "CommonSecurityLog",
        TimeGenerated,
        Indicator = iff(SourceIP in (ioc_list), SourceIP, DestinationIP),
        DeviceOrSource = strcat(DeviceVendor, "/", DeviceProduct),
        User = SourceUserName,
        Detail = strcat(Activity, " | ", DeviceAction, " | ", SourceIP, " → ", DestinationIP, ":", DestinationPort),
        Extra = Message
),
(
    SecurityAlert
    | where TimeGenerated >= ago(lookback)
    | where Entities has_any (ioc_list)
    | project
        SourceTable = "SecurityAlert",
        TimeGenerated,
        Indicator = extract(strcat("(", strcat_array(ioc_list, "|"), ")"), 0, Entities),
        DeviceOrSource = ProductName,
        User = "",
        Detail = strcat(Severity, " | ", AlertName),
        Extra = Description
)
| sort by TimeGenerated desc
| take 50
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: IP — CrowdStrike Falcon network connections ---
// Replace IP_LIST values with the suspect IPs.

#event_simpleName=NetworkConnectIP4
| in(RemoteAddressIP4, values=[{{iocs_ip}}])
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort,
         FileName, CommandLine, UserName, LocalAddressIP4])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query B: IP — CrowdStrike Falcon DNS resolution ---
// Check if any suspect IPs appeared in DNS A-record responses.

#event_simpleName=DnsRequest
| in(IP4Records, values=[{{iocs_ip}}])
| table([@timestamp, ComputerName, DomainName, IP4Records,
         FileName, ContextProcessId])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query C: IP — Entra ID sign-in logs ---
// Check if any suspect IPs were used for authentication.

#event.module=entraid #event.dataset="entraid.signin"
| in(source.ip, values=[{{iocs_ip}}])
| table([@timestamp, Vendor.properties.userPrincipalName, source.ip,
         Vendor.properties.appDisplayName, Vendor.properties.status.errorCode,
         Vendor.properties.riskLevelDuringSignIn,
         Vendor.properties.location.city, Vendor.properties.location.countryOrRegion])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query D: IP — Fortinet FortiGate firewall ---
// Check if suspect IPs appear in firewall traffic. Adjust tags for other vendors.

#Vendor="fortinet" #event.module=fortinet
| in(source.ip, values=[{{iocs_ip}}]) OR in(destination.ip, values=[{{iocs_ip}}])
| table([@timestamp, source.ip, destination.ip, destination.port,
         event.action, network.direction, observer.name,
         source.geo.country_name, Vendor.app])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query E: Domain — CrowdStrike Falcon DNS requests ---
// Replace DOMAIN_LIST values with the suspect domains.

#event_simpleName=DnsRequest
| in(DomainName, values=[{{iocs_domain}}])
| table([@timestamp, ComputerName, DomainName, IP4Records,
         FileName, ContextProcessId, UserName])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query F: Hash — CrowdStrike Falcon file/process events ---
// Replace HASH_LIST values with the suspect SHA256 hashes.

#event_simpleName=/^(ProcessRollup2|NewExecutableWritten|SyntheticProcessRollup2)$/
| in(SHA256HashData, values=[{{iocs_hash}}])
| table([@timestamp, ComputerName, FileName, CommandLine, FilePath,
         SHA256HashData, ParentBaseFileName, UserName])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query G: CrowdStrike detections mentioning IOCs ---

#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| SHA256HashData = "{{iocs_hash}}" OR CommandLine = /{{iocs_domain}}/i OR CommandLine = /{{iocs_ip}}/i
| table([@timestamp, ComputerName, DetectName, DetectDescription,
         Severity, FileName, CommandLine, SHA256HashData,
         Tactic, Technique])
| sort(@timestamp, order=desc)
| head(50)
```

### Stage 2 — Context pivot

- **Run:** when Stage 1 returns hits. Pulls 1-hour window around the hit for context.
- **Purpose:** understand what else happened on the same device/source around the time of the IOC hit.

**Microsoft Sentinel (KQL)**

```kql
let pivot_time = datetime({{hit_time}});
let window_start = pivot_time - 30m;
let window_end = pivot_time + 30m;
let device_filter = "{{hit_device}}";
CommonSecurityLog
| where TimeGenerated between (window_start .. window_end)
| where DeviceProduct has device_filter or DeviceName has device_filter
| project
    TimeGenerated,
    SourceIP,
    SourceUserName,
    DestinationIP,
    DestinationPort,
    Protocol,
    Activity,
    DeviceAction,
    DeviceVendor,
    DeviceProduct,
    Message
| sort by TimeGenerated asc
| take 50
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: All process activity on the hit host ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{hit_host}}/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine,
         SHA256HashData, ParentBaseFileName, TargetProcessId])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query B: Network connections from the hit host ---

#event_simpleName=NetworkConnectIP4
| ComputerName = /{{hit_host}}/i
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort,
         FileName, CommandLine, LocalAddressIP4])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query C: DNS requests from the hit host ---

#event_simpleName=DnsRequest
| ComputerName = /{{hit_host}}/i
| table([@timestamp, ComputerName, DomainName, IP4Records, FileName])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query D: File writes on the hit host ---

#event_simpleName=/^(NewExecutableWritten|NewScriptWritten|GenericFileWritten)$/
| ComputerName = /{{hit_host}}/i
| table([@timestamp, ComputerName, TargetFileName, FilePath,
         SHA256HashData, FileName, CommandLine, UserName])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query E: Entra ID sign-ins from the hit IP ---
// Only run if the Stage 1 hit was an IP-based IOC against Entra sign-in logs.

#event.module=entraid #event.dataset="entraid.signin"
| source.ip = "{{hit_ip}}"
| table([@timestamp, Vendor.properties.userPrincipalName, source.ip,
         Vendor.properties.appDisplayName, Vendor.properties.status.errorCode,
         Vendor.properties.riskLevelDuringSignIn, Vendor.properties.isInteractive,
         Vendor.properties.deviceDetail.displayName])
| sort(@timestamp, order=desc)
| head(50)
```

---

## Lateral Movement Investigation (`lateral-movement`)

Multi-stage lateral movement investigation. Stage 1 identifies RDP, SMB, WMI, PsExec, and WinRM connections from the compromised host. Stage 2 checks for credential access (pass-the-hash, Kerberos abuse, LSASS access) on the source and destination hosts. Stage 3 traces the full movement chain across multiple hops to map the blast radius.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `source_host` | string | — | Initially compromised hostname or DeviceName |
| `source_user` | string | — | Compromised user account (UPN or AccountName) |
| `lookback` | string | — | KQL timespan for lookback window (default 7d) |
| `destination_hosts` | string | — | Comma-separated destination hosts from Stage 1 (used in Stages 2-3) |

### Stage 1 — Lateral movement connections

- **Run:** ALWAYS — identify all lateral movement from the source host.

**Microsoft Sentinel (KQL)**

```kql
let source = "{{source_host}}";
let lookback = {{lookback}};
let LateralPorts = DeviceNetworkEvents
    | where TimeGenerated >= ago(lookback)
    | where DeviceName =~ source
    | where ActionType == "ConnectionSuccess"
    | where RemotePort in (3389, 445, 135, 5985, 5986, 22, 23)
    | where not(RemoteIP == "127.0.0.1")
    | project
        TimeGenerated,
        SourceHost = DeviceName,
        DestinationIP = RemoteIP,
        DestinationPort = RemotePort,
        Protocol = case(
            RemotePort == 3389, "RDP",
            RemotePort == 445, "SMB",
            RemotePort == 135, "WMI/DCOM",
            RemotePort in (5985, 5986), "WinRM",
            RemotePort == 22, "SSH",
            RemotePort == 23, "Telnet",
            strcat("Port:", RemotePort)
        ),
        InitiatingProcess = InitiatingProcessFileName,
        InitiatingCmdLine = InitiatingProcessCommandLine,
        User = InitiatingProcessAccountName;
let LateralTools = DeviceProcessEvents
    | where TimeGenerated >= ago(lookback)
    | where DeviceName =~ source
    | where FileName in~ ("psexec.exe", "psexec64.exe", "paexec.exe",
                           "wmic.exe", "winrs.exe", "mstsc.exe",
                           "ssh.exe", "plink.exe", "putty.exe")
            or ProcessCommandLine has_any ("Invoke-Command", "Enter-PSSession",
                                           "New-PSSession", "wmic /node",
                                           "Invoke-WmiMethod", "schtasks /create /s")
    | project
        TimeGenerated,
        SourceHost = DeviceName,
        FileName,
        ProcessCommandLine,
        User = AccountName,
        ParentProcess = InitiatingProcessFileName;
let RemoteLogons = DeviceLogonEvents
    | where TimeGenerated >= ago(lookback)
    | where RemoteDeviceName =~ source
    | where LogonType in ("RemoteInteractive", "Network", "NewCredentials")
    | where ActionType == "LogonSuccess"
    | project
        TimeGenerated,
        SourceHost = RemoteDeviceName,
        DestinationHost = DeviceName,
        LogonType,
        User = AccountName,
        AccountDomain;
union
(
    LateralPorts
    | extend RecordType = "NetworkConnection"
    | project RecordType, TimeGenerated, SourceHost,
              Detail = strcat(Protocol, " → ", DestinationIP, ":", DestinationPort),
              User,
              Extra = strcat(InitiatingProcess, " | ", InitiatingCmdLine)
),
(
    LateralTools
    | extend RecordType = "LateralTool"
    | project RecordType, TimeGenerated, SourceHost,
              Detail = strcat(FileName, " | ", ProcessCommandLine),
              User,
              Extra = strcat("Parent: ", ParentProcess)
),
(
    RemoteLogons
    | extend RecordType = "RemoteLogon"
    | project RecordType, TimeGenerated, SourceHost,
              Detail = strcat(LogonType, " → ", DestinationHost),
              User,
              Extra = AccountDomain
)
| sort by TimeGenerated asc
| take 50
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: Outbound connections on lateral movement ports ---
// Ports: 3389=RDP, 445=SMB, 135=WMI/DCOM, 5985/5986=WinRM, 22=SSH, 23=Telnet

#event_simpleName=NetworkConnectIP4
| ComputerName = /{{source_host}}/i
| in(RemotePort, values=["3389", "445", "135", "5985", "5986", "22", "23"])
| RemoteAddressIP4 != "127.0.0.1"
| Protocol := case {
    RemotePort = "3389" | "RDP";
    RemotePort = "445"  | "SMB";
    RemotePort = "135"  | "WMI/DCOM";
    RemotePort = "5985" | "WinRM";
    RemotePort = "5986" | "WinRM";
    RemotePort = "22"   | "SSH";
    RemotePort = "23"   | "Telnet";
    * | RemotePort;
  }
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort, Protocol,
         FileName, CommandLine, UserName])
| sort(@timestamp, order=asc)
| head(50)


// --- Sub-query B: Lateral movement tool execution ---
// PsExec, WMI, WinRM, SSH, and remote task scheduling tools.

#event_simpleName=ProcessRollup2
| ComputerName = /{{source_host}}/i
| FileName = /^(psexec\.exe|psexec64\.exe|paexec\.exe|wmic\.exe|winrs\.exe|mstsc\.exe|ssh\.exe|plink\.exe|putty\.exe)$/i OR CommandLine = /Invoke-Command|Enter-PSSession|New-PSSession|wmic.*\/node|Invoke-WmiMethod|schtasks.*\/create.*\/s/i
| table([@timestamp, ComputerName, FileName, CommandLine, UserName,
         ParentBaseFileName, SHA256HashData])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query C: Remote logons originating from the source host ---
// Look for UserLogon events where the remote IP matches the source host.
// NOTE: You need the source host's IP address for this query. Replace SOURCE_IP.

#event_simpleName=UserLogon
| RemoteAddressIP4 = "SOURCE_IP"
| in(LogonType, values=["3", "10"])
| table([@timestamp, ComputerName, UserName, LogonType, LogonDomain,
         RemoteAddressIP4, AuthenticationPackage])
| sort(@timestamp, order=asc)
| head(50)
```

### Stage 2 — Credential access on movement path

- **Run:** when Stage 1 identifies lateral connections.
- **Purpose:** detect credential theft techniques on source and destination hosts.

**Microsoft Sentinel (KQL)**

```kql
let hosts = dynamic([{{destination_hosts}}]);
let source = "{{source_host}}";
let all_hosts = array_concat(hosts, pack_array(source));
let lookback = {{lookback}};
let LsassAccess = DeviceProcessEvents
    | where TimeGenerated >= ago(lookback)
    | where DeviceName in~ (all_hosts)
    | where FileName in~ ("mimikatz.exe", "procdump.exe", "procdump64.exe",
                           "comsvcs.dll", "nanodump.exe", "pypykatz")
            or (ProcessCommandLine has "lsass" and ProcessCommandLine has_any
                ("MiniDump", "procdump", "comsvcs", "sekurlsa", "logonpasswords"))
    | project
        TimeGenerated,
        DeviceName,
        FileName,
        ProcessCommandLine,
        User = AccountName,
        ParentProcess = InitiatingProcessFileName;
let KerberosAnomalies = IdentityLogonEvents
    | where TimeGenerated >= ago(lookback)
    | where DeviceName in~ (all_hosts)
    | where LogonType in ("Kerberos", "KerberosAS")
    | where Application has_any ("overpass", "pass-the-ticket", "golden", "silver")
            or FailureReason has_any ("KDC_ERR", "PREAUTH_FAILED", "encryption type")
    | project
        TimeGenerated,
        DeviceName,
        LogonType,
        User = AccountUpn,
        FailureReason,
        Application;
let CredentialAlerts = SecurityAlert
    | where TimeGenerated >= ago(lookback)
    | where Entities has_any (all_hosts)
    | where AlertName has_any ("credential", "LSASS", "pass-the-hash",
                                "kerberoast", "golden ticket", "DCSync",
                                "lateral movement", "mimikatz", "brute force")
    | project
        TimeGenerated,
        AlertName,
        Severity,
        Description,
        Entities;
union
(
    LsassAccess
    | extend RecordType = "CredentialTool"
    | project RecordType, TimeGenerated, DeviceName,
              Detail = strcat(FileName, " | ", ProcessCommandLine),
              Severity = "High",
              Extra = strcat("User: ", User, " Parent: ", ParentProcess)
),
(
    KerberosAnomalies
    | extend RecordType = "KerberosAnomaly"
    | project RecordType, TimeGenerated, DeviceName,
              Detail = strcat(LogonType, " | ", User),
              Severity = "Medium",
              Extra = FailureReason
),
(
    CredentialAlerts
    | extend RecordType = "CredentialAlert"
    | project RecordType, TimeGenerated, DeviceName = "",
              Detail = AlertName,
              Severity,
              Extra = Description
)
| sort by TimeGenerated asc
| take 50
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: Credential dumping tools (per host) ---
// Replace HOST_NAME with each host to investigate.

#event_simpleName=ProcessRollup2
| ComputerName = /HOST_NAME/i
| FileName = /^(mimikatz\.exe|procdump\.exe|procdump64\.exe|nanodump\.exe|pypykatz)$/i OR CommandLine = /lsass.*MiniDump|lsass.*procdump|comsvcs.*lsass|sekurlsa|logonpasswords|SAM.*hive|SECURITY.*hive/i
| table([@timestamp, ComputerName, FileName, CommandLine, UserName,
         ParentBaseFileName, SHA256HashData])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query B: LSASS access events (per host) ---
// CrowdStrike tracks LSASS access through specific detections.

#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| ComputerName = /HOST_NAME/i
| DetectName = /credential|LSASS|pass.the.hash|kerberoast|golden.ticket|DCSync|lateral.movement|mimikatz|brute.force/i
| table([@timestamp, ComputerName, DetectName, DetectDescription,
         Severity, FileName, CommandLine, Tactic, Technique])
| sort(@timestamp, order=desc)
| head(50)


// --- UNAVAILABLE: MDI Kerberos anomaly detection ---
// Source: IdentityLogonEvents (Microsoft Defender for Identity)
// Not available in LogScale. Check Microsoft Defender for Identity portal
// for Kerberos protocol anomalies (overpass-the-hash, pass-the-ticket,
// golden ticket, silver ticket, encryption downgrade).
```

### Stage 3 — Movement chain and blast radius

- **Run:** when Stage 2 confirms credential access or Stage 1 shows multiple destinations.
- **Purpose:** trace secondary hops — did the adversary move further from the

**Microsoft Sentinel (KQL)**

```kql
let first_hop_hosts = dynamic([{{destination_hosts}}]);
let lookback = {{lookback}};
let SecondHop = DeviceNetworkEvents
    | where TimeGenerated >= ago(lookback)
    | where DeviceName in~ (first_hop_hosts)
    | where ActionType == "ConnectionSuccess"
    | where RemotePort in (3389, 445, 135, 5985, 5986, 22)
    | where not(RemoteIP == "127.0.0.1")
    | project
        TimeGenerated,
        SourceHost = DeviceName,
        DestinationIP = RemoteIP,
        DestinationPort = RemotePort,
        Protocol = case(
            RemotePort == 3389, "RDP",
            RemotePort == 445, "SMB",
            RemotePort == 135, "WMI/DCOM",
            RemotePort in (5985, 5986), "WinRM",
            RemotePort == 22, "SSH",
            strcat("Port:", RemotePort)
        ),
        User = InitiatingProcessAccountName,
        Process = InitiatingProcessFileName;
let SecondHopLogons = DeviceLogonEvents
    | where TimeGenerated >= ago(lookback)
    | where RemoteDeviceName in~ (first_hop_hosts)
    | where LogonType in ("RemoteInteractive", "Network", "NewCredentials")
    | where ActionType == "LogonSuccess"
    | project
        TimeGenerated,
        SourceHost = RemoteDeviceName,
        DestinationHost = DeviceName,
        LogonType,
        User = AccountName;
let AllHosts = union
    (SecondHop | project Host = SourceHost),
    (SecondHop | project Host = DestinationIP),
    (SecondHopLogons | project Host = SourceHost),
    (SecondHopLogons | project Host = DestinationHost)
    | distinct Host;
let BlastRadius = AllHosts
    | summarize Hosts = make_set(Host);
union
(
    SecondHop
    | extend RecordType = "SecondHopNetwork"
    | project RecordType, TimeGenerated, SourceHost,
              Detail = strcat(Protocol, " → ", DestinationIP, ":", DestinationPort),
              User,
              Extra = Process
),
(
    SecondHopLogons
    | extend RecordType = "SecondHopLogon"
    | project RecordType, TimeGenerated, SourceHost,
              Detail = strcat(LogonType, " → ", DestinationHost),
              User,
              Extra = ""
)
| sort by TimeGenerated asc
| take 50
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: Second-hop outbound connections (per destination host) ---
// Replace FIRST_HOP_HOST with each destination from Stage 1.

#event_simpleName=NetworkConnectIP4
| ComputerName = /FIRST_HOP_HOST/i
| in(RemotePort, values=["3389", "445", "135", "5985", "5986", "22"])
| RemoteAddressIP4 != "127.0.0.1"
| Protocol := case {
    RemotePort = "3389" | "RDP";
    RemotePort = "445"  | "SMB";
    RemotePort = "135"  | "WMI/DCOM";
    RemotePort = "5985" | "WinRM";
    RemotePort = "5986" | "WinRM";
    RemotePort = "22"   | "SSH";
    * | RemotePort;
  }
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort, Protocol,
         FileName, CommandLine, UserName])
| sort(@timestamp, order=asc)
| head(50)


// --- Sub-query B: Logons on second-hop hosts from first-hop hosts ---
// Replace FIRST_HOP_IP with the IP of each first-hop destination.

#event_simpleName=UserLogon
| RemoteAddressIP4 = "FIRST_HOP_IP"
| in(LogonType, values=["3", "10"])
| table([@timestamp, ComputerName, UserName, LogonType, LogonDomain,
         RemoteAddressIP4, AuthenticationPackage])
| sort(@timestamp, order=asc)
| head(50)
```

**Definitions**

- **Lateral Movement** — Techniques where an adversary moves from one system to another within the network, typically using legitimate remote access protocols (RDP, SMB, WMI) with stolen or escalated credentials.
- **Blast Radius** — The total set of systems and accounts accessed by the adversary from the initial point of compromise, including all intermediate hops.

---

## Malware/Script Execution Traceback (`malware-execution`)

Trace backwards through the kill chain from a malware execution or suspicious script alert: What executed? -> How did it get there? -> What was the initial access vector? Three structured stages collapse the investigation into minimal query count.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `device_name` | string | — | DeviceName from the alert |
| `filename` | string | — | Filename of the malware/script (set to __NONE__ if using sha256 only) |
| `sha256` | string | — | SHA256 hash (set to __NONE__ if using filename only) |
| `lookback` | string | `7d` | Time range to investigate (default 7d) |

### Stage 0 — Execution volume overview

- **Run:** ALWAYS — summarise first, then pivot to Stage 1 for the full process tree.
- **Purpose:** Compact per-(device, file) count of matching executions, before the raw ancestry pull.

**Microsoft Sentinel (KQL)**

```kql
// Malware/Script Execution Stage 0 — Execution volume overview.
// Summarise first: how many execution events match the target file/host, on which
// devices, run by whom, spawned by what — before pulling the full raw process
// ancestry in Stage 1. One row per (device, file). Pivot to Stage 1 for the tree.
let lookback = {{lookback}};
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceName =~ "{{device_name}}"
| where FileName =~ "{{filename}}" or SHA256 == "{{sha256}}"
| summarize ExecCount = count(),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
    Accounts = make_set(AccountName, 15),
    ParentProcesses = make_set(InitiatingProcessFileName, 15)
    by DeviceName, FileName, SHA256
| sort by ExecCount desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Malware/Script Execution Stage 0 — Execution volume overview (CrowdStrike Falcon).
// Summarise first: count executions matching the target file/host before pulling
// the raw process ancestry in Stage 1. One row per (host, file) with exec count,
// users and parent processes. Pivot to Stage 1 for the full tree.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /{{filename}}/i OR SHA256HashData = "{{sha256}}"
| groupBy([ComputerName, FileName, SHA256HashData], function=[
    count(as=ExecCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen),
    collect([UserName, ParentBaseFileName], limit=15)
  ])
| sort(ExecCount, order=desc, limit=200)
```

### Stage 1 — Execution context and process ancestry

- **Run:** ALWAYS — starting point for every malware/script execution investigation.

**Microsoft Sentinel (KQL)**

```kql
let TargetProcesses =
    DeviceProcessEvents
    | where Timestamp > ago({{lookback}})
    | where DeviceName =~ "{{device_name}}"
    | where FileName =~ "{{filename}}" or SHA256 == "{{sha256}}"
    // Uncomment to filter by execution time from the alert:
    // | where Timestamp between (datetime({{exec_time}}) - 5m .. datetime({{exec_time}}) + 5m)
;
let ParentLookup =
    DeviceProcessEvents
    | where Timestamp > ago({{lookback}})
    | where DeviceName =~ "{{device_name}}"
;
union
(
    TargetProcesses
    | join kind=leftouter (
        ParentLookup
        | project
            ParentProcessId = ProcessId,
            ParentTimestamp = Timestamp,
            ParentFile = FileName,
            ParentCommandLine = ProcessCommandLine,
            ParentSHA256 = SHA256,
            GrandparentFile = InitiatingProcessFileName,
            GrandparentCommandLine = InitiatingProcessCommandLine,
            GrandparentPID = InitiatingProcessParentId
    ) on $left.InitiatingProcessId == $right.ParentProcessId
    | project
        SourceTable = "DeviceProcessEvents",
        Timestamp,
        DeviceName,
        TargetFile = FileName,
        TargetCommandLine = ProcessCommandLine,
        TargetSHA256 = SHA256,
        AccountName,
        ParentFile,
        ParentCommandLine,
        GrandparentFile,
        GrandparentCommandLine,
        Extra = ""
),
(
    DeviceEvents
    | where Timestamp > ago({{lookback}})
    | where DeviceName =~ "{{device_name}}"
    | where ActionType in ("PowerShellCommand", "ScriptContent")
    | where InitiatingProcessFileName =~ "{{filename}}" or InitiatingProcessSHA256 == "{{sha256}}"
    | project
        SourceTable = "DeviceEvents",
        Timestamp,
        DeviceName,
        TargetFile = InitiatingProcessFileName,
        TargetCommandLine = "",
        TargetSHA256 = InitiatingProcessSHA256,
        AccountName = InitiatingProcessAccountName,
        ParentFile = "",
        ParentCommandLine = "",
        GrandparentFile = "",
        GrandparentCommandLine = "",
        Extra = tostring(AdditionalFields)
),
(
    SecurityAlert
    | where TimeGenerated > ago({{lookback}})
    | where CompromisedEntity =~ "{{device_name}}"
    | project
        SourceTable = "SecurityAlert",
        Timestamp = TimeGenerated,
        DeviceName = CompromisedEntity,
        TargetFile = AlertName,
        TargetCommandLine = "",
        TargetSHA256 = "",
        AccountName = "",
        ParentFile = "",
        ParentCommandLine = "",
        GrandparentFile = "",
        GrandparentCommandLine = "",
        Extra = Description
)
| sort by Timestamp desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: Process execution with parent context (CrowdStrike Falcon) ---
// Replaces KQL DeviceProcessEvents + parent join. Falcon ProcessRollup2 includes
// parent info natively — no join required.

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /{{filename}}/i OR SHA256HashData = "{{sha256}}"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine,
         SHA256HashData, ParentBaseFileName, ParentCommandLine,
         TargetProcessId, ParentProcessId, TreeId])
| sort(@timestamp, order=desc)
| head(200)


// --- Sub-query B: Process tree by TreeId (CrowdStrike Falcon) ---
// After finding the TreeId from sub-query A, run this to see the full process tree.
// Replace TREE_ID with the TreeId value from sub-query A results.

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| TreeId = "TREE_ID"
| table([@timestamp, ComputerName, UserName, ParentBaseFileName,
         FileName, CommandLine, SHA256HashData,
         TargetProcessId, ParentProcessId, TreeId])
| sort(@timestamp, order=asc)
| head(200)


// --- Sub-query C: Script and PowerShell content (CrowdStrike Falcon) ---
// Replaces KQL DeviceEvents where ActionType in ("PowerShellCommand", "ScriptContent").

#event_simpleName=/^(CommandHistory|ScriptControlScanTelemetry)$/
| ComputerName = /{{device_name}}/i
| table([@timestamp, ComputerName, FileName, CommandLine,
         ScriptContent, ScriptContentName,
         InitiatingProcessFileName, UserName])
| sort(@timestamp, order=desc)
| head(200)


// --- Sub-query D: CrowdStrike detections on host (replaces SecurityAlert) ---

#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| ComputerName = /{{device_name}}/i
| table([@timestamp, ComputerName, DetectName, DetectDescription,
         Severity, FileName, CommandLine, SHA256HashData,
         Tactic, Technique, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(200)
```

### Stage 2 — File delivery chain

- **Run:** ALWAYS — how did the file arrive on disk?

**Microsoft Sentinel (KQL)**

```kql
union
(
    DeviceFileEvents
    | where Timestamp > ago({{lookback}})
    | where DeviceName =~ "{{device_name}}"
    | where ActionType in ("FileCreated", "FileRenamed", "FileModified")
    | where FileName =~ "{{filename}}" or SHA256 == "{{sha256}}"
    | project
        SourceTable = "DeviceFileEvents",
        Timestamp,
        FileName,
        FolderPath,
        SHA256,
        FileOriginUrl,
        FileOriginIP = FileOriginReferrerUrl,
        InitiatingProcess = InitiatingProcessFileName,
        InitiatingCommandLine = InitiatingProcessCommandLine,
        RemoteIP = "",
        RemoteUrl = "",
        RemotePort = ""
),
(
    DeviceNetworkEvents
    | where Timestamp > ago({{lookback}})
    | where DeviceName =~ "{{device_name}}"
    | where InitiatingProcessFileName in~
        ("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
         "outlook.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
         "certutil.exe", "bitsadmin.exe", "mshta.exe", "wscript.exe",
         "cscript.exe", "curl.exe", "wget.exe", "regsvr32.exe",
         "rundll32.exe", "msiexec.exe", "{{filename}}")
    | project
        SourceTable = "DeviceNetworkEvents",
        Timestamp,
        FileName = InitiatingProcessFileName,
        FolderPath = InitiatingProcessFolderPath,
        SHA256 = "",
        FileOriginUrl = "",
        FileOriginIP = "",
        InitiatingProcess = InitiatingProcessFileName,
        InitiatingCommandLine = InitiatingProcessCommandLine,
        RemoteIP,
        RemoteUrl,
        RemotePort = tostring(RemotePort)
)
| sort by Timestamp desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: File writes matching target (CrowdStrike Falcon) ---
// Replaces KQL DeviceFileEvents where ActionType in ("FileCreated", "FileRenamed", "FileModified").

#event_simpleName=/^(NewExecutableWritten|ExecutableDeleted|NewScriptWritten|GenericFileWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /{{filename}}/i OR SHA256HashData = "{{sha256}}"
| table([@timestamp, ComputerName, TargetFileName, SourceFileName,
         SHA256HashData, FilePath, FileName, CommandLine,
         ParentBaseFileName, UserName])
| sort(@timestamp, order=desc)
| head(200)


// --- Sub-query B: Network connections by delivery processes (CrowdStrike Falcon) ---
// Replaces KQL DeviceNetworkEvents filtered to common delivery processes.

#event_simpleName=NetworkConnectIP4
| ComputerName = /{{device_name}}/i
| FileName = /^(chrome\.exe|msedge\.exe|firefox\.exe|iexplore\.exe|outlook\.exe|powershell\.exe|pwsh\.exe|cmd\.exe|certutil\.exe|bitsadmin\.exe|mshta\.exe|wscript\.exe|cscript\.exe|curl\.exe|wget\.exe|regsvr32\.exe|rundll32\.exe|msiexec\.exe)$/i OR FileName = /{{filename}}/i
| table([@timestamp, ComputerName, FileName, CommandLine,
         RemoteAddressIP4, RemotePort, LocalAddressIP4])
| sort(@timestamp, order=desc)
| head(200)
```

### Stage 3 — Initial access vector

- **Run:** When Stage 2 does not conclusively identify the delivery mechanism.

**Microsoft Sentinel (KQL)**

```kql
union
(
    // --- USB / removable media delivery ---
    DeviceEvents
    | where Timestamp > ago({{lookback}})
    | where DeviceName =~ "{{device_name}}"
    | where ActionType == "PnpDeviceConnected"
    | extend ParsedFields = parse_json(AdditionalFields)
    | project
        VectorType = "USB",
        SourceTable = "DeviceEvents",
        Timestamp,
        Activity = strcat("PnP device connected: ", tostring(ParsedFields.ClassName)),
        AccountName = "",
        RemoteIP = "",
        RemoteDeviceName = "",
        SenderFromAddress = "",
        RecipientEmailAddress = "",
        Subject = "",
        DeliveryAction = "",
        Detail = tostring(AdditionalFields)
),
(
    // --- USB file creation on removable paths ---
    DeviceFileEvents
    | where Timestamp > ago({{lookback}})
    | where DeviceName =~ "{{device_name}}"
    | where ActionType == "FileCreated"
    | where FileName =~ "{{filename}}" or SHA256 == "{{sha256}}"
    | where FolderPath matches regex @"^[D-Z]:\\" or FolderPath has "removable"
    | project
        VectorType = "USB",
        SourceTable = "DeviceFileEvents",
        Timestamp,
        Activity = strcat("File created from removable path: ", FolderPath),
        AccountName = InitiatingProcessAccountName,
        RemoteIP = "",
        RemoteDeviceName = "",
        SenderFromAddress = "",
        RecipientEmailAddress = "",
        Subject = "",
        DeliveryAction = "",
        Detail = strcat("InitiatingProcess: ", InitiatingProcessFileName)
),
(
    // --- Email attachment delivery ---
    EmailAttachmentInfo
    | where Timestamp > ago({{lookback}})
    | where FileName =~ "{{filename}}" or SHA256 == "{{sha256}}"
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago({{lookback}})
    ) on NetworkMessageId
    | project
        VectorType = "Email",
        SourceTable = "EmailAttachmentInfo+EmailEvents",
        Timestamp,
        Activity = strcat("Email attachment: ", FileName),
        AccountName = "",
        RemoteIP = SenderIPv4,
        RemoteDeviceName = "",
        SenderFromAddress,
        RecipientEmailAddress,
        Subject,
        DeliveryAction,
        Detail = strcat("FileSize: ", FileSize, " | NetworkMessageId: ", NetworkMessageId)
),
(
    // --- Lateral movement logons ---
    DeviceLogonEvents
    | where Timestamp > ago({{lookback}})
    | where DeviceName =~ "{{device_name}}"
    | where LogonType in ("RemoteInteractive", "Network", "NewCredentials")
    | project
        VectorType = "LateralMovement",
        SourceTable = "DeviceLogonEvents",
        Timestamp,
        Activity = strcat(LogonType, " logon"),
        AccountName = AccountName,
        RemoteIP,
        RemoteDeviceName,
        SenderFromAddress = "",
        RecipientEmailAddress = "",
        Subject = "",
        DeliveryAction = "",
        Detail = strcat("Protocol: ", Protocol, " | FailureReason: ", FailureReason)
)
| sort by VectorType asc, Timestamp desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// --- Sub-query A: USB / removable media (CrowdStrike Falcon) ---

#event_simpleName=/^(RemovableMediaConnected|USBDeviceConnected)$/
| ComputerName = /{{device_name}}/i
| table([@timestamp, ComputerName, DeviceManufacturer, DeviceProduct,
         DeviceSerialNumber, DriveLetter, VolumeName, UserName])
| sort(@timestamp, order=desc)
| head(200)


// --- Sub-query B: File writes on removable/external paths (CrowdStrike Falcon) ---

#event_simpleName=/^(NewExecutableWritten|GenericFileWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /{{filename}}/i OR SHA256HashData = "{{sha256}}"
| FilePath = /^[D-Z]:\\/
| table([@timestamp, ComputerName, TargetFileName, FilePath,
         SHA256HashData, FileName, CommandLine, UserName])
| sort(@timestamp, order=desc)
| head(200)


// --- UNAVAILABLE: Email attachment delivery ---
// Source: EmailAttachmentInfo + EmailEvents (M365 Defender)
// Not available in LogScale. Check the Microsoft 365 Defender portal
// or email gateway logs for attachment delivery to this host.


// --- Sub-query C: Lateral movement logons (CrowdStrike Falcon) ---
// Replaces KQL DeviceLogonEvents where LogonType in ("RemoteInteractive", "Network").
// CrowdStrike LogonType values: 2=Interactive, 3=Network, 10=RemoteInteractive

#event_simpleName=UserLogon
| ComputerName = /{{device_name}}/i
| in(LogonType, values=["3", "10"])
| table([@timestamp, ComputerName, UserName, LogonType,
         LogonDomain, RemoteAddressIP4, AuthenticationPackage])
| sort(@timestamp, order=desc)
| head(50)
```

---

## Illicit OAuth Consent / App Abuse Investigation (`oauth-consent`)

Investigates illicit OAuth consent-grant phishing and enterprise-app abuse: consent events and app-role / service-principal credential additions, service-principal sign-in activity post-consent, data the consented app accessed, the granting user's sign-in context, and an attacker-IP tenant sweep with correlated alerts. Migrated from the legacy Sentinel-only oauth-consent-grant playbook and extended with CQL. Stages 1, 2 and 4 always run; Stages 3 and 5 are conditional.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `upn` | string | — | UserPrincipalName who granted consent. |
| `ip` | string | `__NONE__` | IP address at time of consent (optional; used in Stage 5 sweep). __NONE__ to skip. |
| `object_id` | string | `__NONE__` | Entra object ID of the user (optional, for alert correlation). __NONE__ to skip. |
| `app_id` | string | `__NONE__` | AppId / client-id (or ServicePrincipal name fragment) of the consented app, read from the Stage 1 consent event Parameters. REQUIRED to scope Stage 2 — __NONE__ returns nothing rather than the entire tenant's SP sign-in log. |
| `lookback` | string | `14d` | Time range to investigate (default 14d). |

### Stage 1 — Consent & app-role / SP-credential events

- **Run:** ALWAYS — the consent event itself.
- **Purpose:** consent grants, OAuth2 permission grants, app-role assignments, SP credential adds.

**Microsoft Sentinel (KQL)**

```kql
// OAuth Consent Stage 1 — Consent & app-role / SP-credential events.
let lookback = {{lookback}};
let upn = "{{upn}}";
OfficeActivity
| where TimeGenerated > ago(lookback)
| where OfficeWorkload == "AzureActiveDirectory"
| where UserId =~ upn
| where Operation in ("Consent to application.", "Add OAuth2PermissionGrant.",
    "Add app role assignment to user.", "Add app role assignment to service principal.",
    "Add delegated permission grant.", "Add service principal.",
    "Add service principal credentials.", "Update application.", "Update service principal.")
| project TimeGenerated, Operation, UserId, ClientIP, ResultStatus,
    Parameters = tostring(Parameters)
| sort by TimeGenerated asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// OAuth Consent Stage 1 — Consent & app-role / SP-credential events.
// Source: M365 unified audit log, AzureActiveDirectory workload (verified m365 module).
#Vendor="microsoft" #event.module=m365
| Vendor.Workload = "AzureActiveDirectory"
| Vendor.UserId = /{{upn}}/i
| in(field=Vendor.Operation, values=["Consent to application.", "Add OAuth2PermissionGrant.",
    "Add app role assignment to user.", "Add app role assignment to service principal.",
    "Add delegated permission grant.", "Add service principal.",
    "Add service principal credentials.", "Update application.", "Update service principal."])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.ResultStatus], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 2 — Service-principal sign-ins post-consent

- **Run:** ALWAYS — shows whether the app started acting.
- **Purpose:** app/service-principal authentication activity after the grant.

**Microsoft Sentinel (KQL)**

```kql
// OAuth Consent Stage 2 — Service-principal sign-ins post-consent.
// Scoped to the consented app (app_id from Stage 1). app_id=__NONE__ returns
// nothing rather than the entire tenant's SP sign-in log — supply the AppId.
let lookback = {{lookback}};
let app_id = "{{app_id}}";
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(lookback)
| where app_id != "__NONE__"
    and (AppId == app_id or ServicePrincipalId == app_id or ServicePrincipalName has app_id)
| project TimeGenerated, ServicePrincipalName, ServicePrincipalId, AppId,
    IPAddress, ResourceDisplayName, ResultType, ResultDescription
| sort by TimeGenerated asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// OAuth Consent Stage 2 — Service-principal sign-ins post-consent.
// ⚠ Service-principal sign-ins ride the entraid connector. The discovered entraid
//   schema populates Vendor.properties.servicePrincipalName on SP sign-ins, but the
//   exact dataset (entraid.signin vs a sibling like entraid.serviceprincipalsignin)
//   is NOT confirmed in this repo — verify before relying on this:
//     #event.module=entraid | groupBy(#event.dataset, function=count())
//   then set the dataset filter on line 1 accordingly.
// Scoped to the consented app (app_id from Stage 1). app_id=__NONE__ matches
// nothing rather than returning every SP sign-in in the tenant.
#event.module=entraid #event.dataset=/entraid\..*signin/i
| Vendor.properties.servicePrincipalName = /.+/
| Vendor.properties.appId = "{{app_id}}" OR Vendor.properties.servicePrincipalName = /{{app_id}}/i
| table([@timestamp, Vendor.properties.servicePrincipalName, Vendor.properties.appId,
         source.ip, Vendor.properties.resourceDisplayName,
         Vendor.properties.status.errorCode], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 3 — Post-consent data access

- **Run:** when the consent looks illicit.
- **Purpose:** mail/file access, sends, sharing performed by the user / app.

**Microsoft Sentinel (KQL)**

```kql
// OAuth Consent Stage 3 — Post-consent data access.
// NOTE: the legacy playbook also queried MicrosoftGraphActivityLogs (the consented
// app's Graph API calls). If Graph activity logging is enabled, add a section for it;
// it has no NG-SIEM equivalent so the CQL side omits it.
let lookback = {{lookback}};
let upn = "{{upn}}";
OfficeActivity
| where TimeGenerated > ago(lookback)
| where UserId =~ upn
| where Operation in ("MailItemsAccessed", "FileDownloaded", "FileAccessed",
    "Send", "SendAs", "SharingSet", "AnonymousLinkCreated")
| project TimeGenerated, Operation, UserId, ClientIP, OfficeWorkload,
    OfficeObjectId, ResultStatus, ExternalAccess
| sort by TimeGenerated asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// OAuth Consent Stage 3 — Post-consent data access by the user / app.
// Source: M365 unified audit log. ⚠ The Sentinel original also reads
//   MicrosoftGraphActivityLogs (the consented app's Graph API calls) — there is NO
//   NG-SIEM equivalent for that table, so app-side Graph access is Sentinel-only.
#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i
| in(field=Vendor.Operation, values=["MailItemsAccessed", "FileDownloaded", "FileAccessed",
    "Send", "SendAs", "SharingSet", "AnonymousLinkCreated"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload,
         Vendor.ExternalAccess], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 4 — Granting-user sign-in context

- **Run:** ALWAYS.
- **Purpose:** location / risk / CA context around the consent.

**Microsoft Sentinel (KQL)**

```kql
// OAuth Consent Stage 4 — Granting-user sign-in context, summarised per source
// IP / geo. One row per location with success/fail split, apps, risk and CA
// status. Pivot to raw sign-in rows for a specific suspect IP if needed.
let lookback = {{lookback}};
let upn = "{{upn}}";
SigninLogs
| where TimeGenerated > ago(lookback)
| where UserPrincipalName =~ upn
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    ErrorCode = tostring(Status.errorCode)
| summarize SignIns = count(),
    Successes = countif(ResultType == 0), Failures = countif(ResultType != 0),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName, 20), Resources = make_set(ResourceDisplayName, 20),
    Risks = make_set(RiskLevelDuringSignIn, 10), CA = make_set(ConditionalAccessStatus, 5),
    AuthReq = make_set(AuthenticationRequirement, 5), ErrorCodes = make_set(ErrorCode, 15)
    by IPAddress, City, Country
| sort by SignIns desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// OAuth Consent Stage 4 — Granting-user sign-in context.
// Source: Entra ID sign-ins (entraid connector, dataset entraid.signin — verified).
#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{upn}}/i
| groupBy([source.ip, Vendor.properties.location.city,
           Vendor.properties.location.countryOrRegion], function=[
    count(as=TotalCount),
    collect([Vendor.properties.appDisplayName], limit=20),
    collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
    collect([Vendor.properties.conditionalAccessStatus], limit=10),
    collect([Vendor.properties.status.errorCode], limit=15),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(TotalCount, order=desc, limit=200)
```

### Stage 5 — IP tenant sweep + correlated alerts

- **Run:** when an attacker IP is known or the grant is confirmed malicious.
- **Purpose:** other accounts from the consent IP, plus correlated security alerts.

**Microsoft Sentinel (KQL)**

```kql
// OAuth Consent Stage 5 — IP tenant sweep + correlated alerts.
let lookback = {{lookback}};
let upn = "{{upn}}";
let ip = "{{ip}}";
let object_id = "{{object_id}}";
union isfuzzy=true
(
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ip != "__NONE__" and IPAddress == ip
    | where UserPrincipalName !~ upn
    | summarize SignInCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
        Apps = make_set(AppDisplayName, 20)
      by UserPrincipalName, Country = tostring(LocationDetails.countryOrRegion)
    | extend Section = "1_IPSweep"
),
(
    SecurityAlert
    | where TimeGenerated > ago(lookback)
    | where Entities has upn
        or (ip != "__NONE__" and Entities has ip)
        or (object_id != "__NONE__" and Entities has object_id)
    | project Section = "2_Alert", TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
        Entities = substring(tostring(Entities), 0, 400)
)
| sort by Section asc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// OAuth Consent Stage 5 — IP tenant sweep + correlated alerts.

// --- Sub-query A: Other accounts seen from the consent IP (tenant sweep) ---

#event.module=entraid #event.dataset="entraid.signin"
| source.ip = "{{ip}}"
| Vendor.properties.userPrincipalName != /{{upn}}/i
| groupBy([Vendor.properties.userPrincipalName,
           Vendor.properties.location.countryOrRegion], function=[
    count(as=SignInCount),
    collect([Vendor.properties.appDisplayName], limit=20),
    collect([Vendor.properties.status.errorCode], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(SignInCount, order=desc, limit=200)


// --- Sub-query B: Correlated alerts (Defender AlertInfo) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "AlertInfo"
| @rawstring = /{{upn}}/i OR @rawstring = /{{ip}}/i OR @rawstring = /{{object_id}}/i
| table([@timestamp, Vendor.properties.Title, Vendor.properties.Severity,
         Vendor.properties.Category], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

**Definitions**

- **Illicit Consent Grant** — MITRE T1528 — phishing a user into granting OAuth permissions to an attacker- controlled app, giving token-based access to mail/files that survives password resets and is not blocked by MFA.

---

## Persistence Sweep (`persistence`)

Standalone persistence hunt across the common autostart mechanisms: scheduled tasks, registry Run keys / ASEP, new services, WMI event subscriptions, and startup-folder writes. Currently only incidentally covered inside malware-execution. Stages 1-3 and 5 always run; Stage 4 (WMI) is conditional. Defender provides dedicated registry/WMI telemetry; on Falcon several mechanisms fall back to ProcessRollup2 command-line analysis of the LOLBins involved (see .cql headers).

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `device_name` | string | `__NONE__` | Host to scope (regex/substring matched). __NONE__ to scan all. |
| `user` | string | `__NONE__` | Associated user account (optional; __NONE__ to scan all). |
| `lookback` | string | `7d` | Time range to investigate (default 7d). |

### Stage 1 — Scheduled tasks

- **Run:** ALWAYS.
- **Purpose:** schtasks/at and Register-ScheduledTask creation (process + 4698).

**Microsoft Sentinel (KQL)**

```kql
// Persistence Stage 1 — Scheduled tasks.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where FileName in~ ("schtasks.exe", "at.exe")
        or (FileName in~ ("powershell.exe", "pwsh.exe")
            and ProcessCommandLine has_any ("New-ScheduledTask", "Register-ScheduledTask"))
    | where ProcessCommandLine has_any ("/create", "Register-ScheduledTask", "New-ScheduledTask")
    | project Source = "DeviceProcessEvents", Timestamp, DeviceName, AccountName,
        FileName, ProcessCommandLine, InitiatingProcessFileName
),
(
    SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where device == "__NONE__" or Computer has device
    | where EventID == 4698   // scheduled task created
    | project Source = "SecurityEvent(4698)", Timestamp = TimeGenerated, DeviceName = Computer,
        AccountName = SubjectUserName, FileName = "schtasks",
        ProcessCommandLine = Activity, InitiatingProcessFileName = ""
)
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Persistence Stage 1 — Scheduled tasks.

// --- Sub-query A: schtasks / Register-ScheduledTask via process telemetry ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(schtasks|at)\.exe$/i OR CommandLine = /Register-ScheduledTask|New-ScheduledTask/i
| CommandLine = /\/create|Register-ScheduledTask|New-ScheduledTask/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Scheduled-task creation via Windows event (4698) ---

#Vendor="microsoft" #event.module=windows EventCode=4698
| host.hostname = /{{device_name}}/i
| table([@timestamp, host.hostname, windows.EventData.SubjectUserName,
         windows.EventData.TaskName], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 2 — Run keys / autostart (ASEP)

- **Run:** ALWAYS.
- **Purpose:** registry writes to Run/RunOnce/Winlogon/IFEO and related autostart keys.

**Microsoft Sentinel (KQL)**

```kql
// Persistence Stage 2 — Run keys / autostart (ASEP).
let lookback = {{lookback}};
let device = "{{device_name}}";
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where device == "__NONE__" or DeviceName has device
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (
    @"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\CurrentVersion\RunServices",
    @"\Winlogon", @"Image File Execution Options", @"\Policies\Explorer\Run",
    @"\CurrentVersion\Windows\Load", @"\CurrentVersion\Explorer\Shell Folders")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Persistence Stage 2 — Run keys / autostart (ASEP).
// ⚠ Falcon's registry-autostart event is AsepValueUpdate, not yet seen in this repo's
//   onboarded clients — confirm via discovery before relying on Sub-query A:
//     * | groupBy(@event_simpleName, function=count())   (look for Asep*/Reg* events)
//   Sub-query B is the reliable fallback: reg.exe / PowerShell writes to autostart keys.

// --- Sub-query A: Registry autostart writes (Falcon AsepValueUpdate — confirm fields) ---

#event_simpleName=AsepValueUpdate
| ComputerName = /{{device_name}}/i
| table([@timestamp, ComputerName, RegObjectName, RegValueName, RegStringValue], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: reg.exe / PowerShell writes to autostart keys (fallback) ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(reg|powershell|pwsh)\.exe$/i
| CommandLine = /CurrentVersion\\Run|RunOnce|Winlogon|Image File Execution Options|Policies\\Explorer\\Run|Windows\\Load/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 3 — New services

- **Run:** ALWAYS.
- **Purpose:** service installation via sc.exe / New-Service / 7045.

**Microsoft Sentinel (KQL)**

```kql
// Persistence Stage 3 — New services.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where device == "__NONE__" or Computer has device
    | where EventID == 7045   // a new service was installed
    | project Source = "SecurityEvent(7045)", Timestamp = TimeGenerated, DeviceName = Computer,
        ServiceName = Activity, Account = SubjectUserName, Detail = RenderedDescription
),
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where (FileName =~ "sc.exe" and ProcessCommandLine has "create")
        or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any ("New-Service", "Set-Service"))
    | project Source = "DeviceProcessEvents", Timestamp, DeviceName,
        ServiceName = ProcessCommandLine, Account = AccountName, Detail = InitiatingProcessFileName
)
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Persistence Stage 3 — New services.

// --- Sub-query A: Service install via Windows event (7045) ---

#Vendor="microsoft" #event.module=windows EventCode=7045
| host.hostname = /{{device_name}}/i
| table([@timestamp, host.hostname, windows.EventData.ServiceName,
         windows.EventData.ImagePath, windows.EventData.ServiceType,
         windows.EventData.StartType], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: sc.exe / New-Service via process telemetry ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(sc|powershell|pwsh)\.exe$/i
| CommandLine = /\bcreate\b|New-Service|Set-Service/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 4 — WMI event subscriptions

- **Run:** when fileless / advanced persistence is suspected.
- **Purpose:** __EventFilter / EventConsumer / FilterToConsumerBinding creation.

**Microsoft Sentinel (KQL)**

```kql
// Persistence Stage 4 — WMI event subscriptions.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where ActionType has_any ("WmiBindEventFilter", "WmiBindEventConsumer",
        "WmiBindEventFilterToConsumer")
    | project Source = "DeviceEvents", Timestamp, DeviceName, ActionType,
        InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
),
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where (FileName =~ "wmic.exe" and ProcessCommandLine has_any ("__EventFilter",
        "CommandLineEventConsumer", "__FilterToConsumerBinding", "ActiveScriptEventConsumer"))
        or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any (
        "__EventFilter", "CommandLineEventConsumer", "Register-WmiEvent", "Set-WmiInstance"))
    | project Source = "DeviceProcessEvents", Timestamp, DeviceName, ActionType = FileName,
        InitiatingProcessFileName, InitiatingProcessCommandLine = ProcessCommandLine,
        AdditionalFields = ""
)
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Persistence Stage 4 — WMI event subscriptions.
// ⚠ Falcon WMI-subscription telemetry is not in this repo's vocabulary; this uses
//   ProcessRollup2 for wmic / PowerShell creating __EventFilter / EventConsumer /
//   FilterToConsumerBinding objects.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(wmic|powershell|pwsh)\.exe$/i
| CommandLine = /__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding|Register-WmiEvent|Set-WmiInstance/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 5 — Startup-folder writes

- **Run:** ALWAYS.
- **Purpose:** files written to a Start Menu\Programs\Startup folder.

**Microsoft Sentinel (KQL)**

```kql
// Persistence Stage 5 — Startup-folder writes.
let lookback = {{lookback}};
let device = "{{device_name}}";
DeviceFileEvents
| where Timestamp > ago(lookback)
| where device == "__NONE__" or DeviceName has device
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FolderPath has @"\Start Menu\Programs\Startup"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Persistence Stage 5 — Startup-folder writes.
#event_simpleName=/^(NewExecutableWritten|NewScriptWritten|GenericFileWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /\\Start Menu\\Programs\\Startup\\/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

**Definitions**

- **ASEP** — Auto-Start Extensibility Point — any registry/filesystem location Windows reads to launch code automatically at boot or logon (Run keys, services, scheduled tasks, Winlogon, IFEO). MITRE T1547 / T1053 / T1543.

---

## Phishing Investigation (`phishing`)

Multi-stage phishing campaign investigation. Scope broad, then narrow. *** START BROAD *** An alert names one NetworkMessageId, but a phishing campaign typically delivers the same payload to many recipients sharing the same sender + subject. Stage 0 expands the seed alert into the full set of related NetworkMessageIds BEFORE any narrow-scope analysis runs. Stage 1 onwards operates on the expanded ID set, not on the alert's single message. Skipping Stage 0 under-counts recipients, misses clickers, and leaves the attacker's other deliveries unaccounted for. Stage 0 expands the alert seed to the full campaign by (sender, subject). Stage 1 gathers full email evidence summarised by recipient UPN across the expanded NetworkMessageId set. Stages 2-4 are conditional follow-ups based on Stage 1 results.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `seed_message_id` | string | — | Single NetworkMessageId from the alert (used by Stage 0 to derive sender/subject) |
| `target_ids` | string | — | Comma-separated NetworkMessageIds. Populated from Stage 0 output before Stage 1. |
| `sender` | string | — | Malicious sender email address (auto-derived in Stage 0 if seed_message_id supplied) |
| `subject` | string | — | Email subject for broad-scope expansion (auto-derived in Stage 0 if seed_message_id supplied) |
| `url` | string | — | Malicious URL (used in stage 3; extracted from stage 1) |
| `sha256` | string | — | Attachment SHA256 hash (used in stage 4; extracted from stage 1) |
| `lookback` | string | `14d` | Time range for broad-scope expansion (default 14d) |

### Stage 0 — Broad scope expansion (sender + subject)

- **Run:** ALWAYS — first step. Expand the alert seed into the full campaign set.

**Microsoft Sentinel (KQL)**

```kql
let SeedLookup = EmailEvents
    | where isnotempty("{{seed_message_id}}") and NetworkMessageId == "{{seed_message_id}}"
    | top 1 by Timestamp asc
    | project SeedSender = SenderFromAddress, SeedSubject = Subject;
let SeedSender = toscalar(SeedLookup | project SeedSender);
let SeedSubject = toscalar(SeedLookup | project SeedSubject);
let TargetSender = iff(isempty("{{sender}}"), SeedSender, "{{sender}}");
let TargetSubject = iff(isempty("{{subject}}"), SeedSubject, "{{subject}}");
let CampaignEmails = EmailEvents
    | where Timestamp >= ago({{lookback}})
    | where isnotempty(TargetSender) and isnotempty(TargetSubject)
    | where SenderFromAddress =~ TargetSender
    | where Subject =~ TargetSubject
    | project
        NetworkMessageId,
        Timestamp,
        SenderFromAddress,
        SenderFromDomain,
        SenderMailFromAddress,
        Subject,
        RecipientEmailAddress,
        DeliveryAction,
        DeliveryLocation,
        ThreatTypes,
        DetectionMethods,
        EmailDirection,
        InternetMessageId;
let CampaignClicks = UrlClickEvents
    | where Timestamp >= ago({{lookback}})
    | summarize ClickCount = count() by NetworkMessageId;
CampaignEmails
| join kind=leftouter CampaignClicks on NetworkMessageId
| summarize
    MessageCount = dcount(NetworkMessageId),
    MessageIds = make_set(NetworkMessageId),
    Recipients = make_set(RecipientEmailAddress),
    RecipientCount = dcount(RecipientEmailAddress),
    SenderDomains = make_set(SenderFromDomain),
    MailFromAddresses = make_set(SenderMailFromAddress),
    DeliveryActions = make_set(DeliveryAction),
    DeliveryLocations = make_set(DeliveryLocation),
    ThreatTypes = make_set(ThreatTypes),
    DetectionMethods = make_set(DetectionMethods),
    ClickedMessageCount = countif(isnotempty(ClickCount)),
    TotalClicks = sum(ClickCount),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
  by SenderFromAddress, Subject
| extend SpansDays = datetime_diff('day', LastSeen, FirstSeen)
| sort by MessageCount desc, LastSeen desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Phishing Stage 0 — Broad scope expansion (sender + subject).
// Source: Microsoft Defender advanced-hunting EmailEvents / UrlClickEvents,
//   forwarded via the Defender 365 connector.
//   Tag #Vendor="microsoft" #event.dataset="windows-defender-365.event" is verified
//   (config/ngsiem/ngsiem_rules.md §4). Email columns ride Vendor.properties.*
//   (config/ngsiem/ngsiem_columns.yaml → microsoft_perf_defendero365_eventhub).
// Sub-table discriminator: Vendor.Workload — verified values "EmailEvents",
//   "EmailAttachmentInfo", "EmailUrlInfo", "UrlClickEvents". "EmailPostDeliveryEvents"
//   and "AlertInfo" follow the same scheme but were not in the verified sample;
//   confirm with:  #event.dataset="windows-defender-365.event"
//     | groupBy(Vendor.Workload, function=count())
//   ThreatTypes / DetectionMethods were not in the discovered sample — they may be
//   unpopulated; drop from output if empty.
// Pivot key across all stages: Vendor.properties.NetworkMessageId.

// --- Sub-query A: Seed lookup (derive sender + subject from the alert's NetworkMessageId) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| Vendor.properties.NetworkMessageId = "{{seed_message_id}}"
| table([@timestamp, Vendor.properties.SenderFromAddress, Vendor.properties.SenderFromDomain,
         Vendor.properties.Subject, Vendor.properties.RecipientEmailAddress], limit=5)
| sort(@timestamp, order=asc, limit=5)


// --- Sub-query B: Campaign expansion by (sender, subject) ---
// Fill {{sender}} and {{subject}} from Sub-query A (or pass them directly).

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| Vendor.properties.SenderFromAddress = /{{sender}}/i
| Vendor.properties.Subject = /{{subject}}/i
| groupBy([Vendor.properties.SenderFromAddress, Vendor.properties.Subject], function=[
    count(field=Vendor.properties.NetworkMessageId, distinct=true, as=MessageCount),
    count(field=Vendor.properties.RecipientEmailAddress, distinct=true, as=RecipientCount),
    collect([Vendor.properties.NetworkMessageId], limit=500),
    collect([Vendor.properties.RecipientEmailAddress], limit=500),
    collect([Vendor.properties.SenderFromDomain], limit=20),
    collect([Vendor.properties.SenderMailFromAddress], limit=20),
    collect([Vendor.properties.DeliveryAction], limit=10),
    collect([Vendor.properties.DeliveryLocation], limit=10),
    collect([Vendor.properties.ThreatTypes], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(MessageCount, order=desc, limit=200)


// --- Sub-query C: Click volume per campaign message (pivot on NetworkMessageId) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "UrlClickEvents"
| groupBy([Vendor.properties.NetworkMessageId], function=[
    count(as=ClickCount),
    collect([Vendor.properties.AccountUpn], limit=50),
    collect([Vendor.properties.Url], limit=50)
  ])
| sort(ClickCount, order=desc, limit=200)
```

### Stage 1 — Core email evidence (per UPN)

- **Run:** ALWAYS — after Stage 0 expansion. Do NOT pass only the alert's single

**Microsoft Sentinel (KQL)**

```kql
let targetIds = dynamic([{{target_ids}}]);
let EmailCore = EmailEvents
    | where NetworkMessageId in (targetIds)
    | project
        NetworkMessageId,
        EmailTimestamp = Timestamp,
        Subject,
        SenderFromAddress,
        SenderDisplayName,
        SenderFromDomain,
        SenderIP = SenderIPv4,
        RecipientEmailAddress,
        RecipientObjectId,
        AuthenticationDetails,
        DeliveryAction,
        DeliveryLocation,
        ThreatTypes,
        ThreatNames,
        InternetMessageId;
let Attachments = EmailAttachmentInfo
    | where NetworkMessageId in (targetIds)
    | summarize AttachmentSHA256 = make_set(SHA256) by NetworkMessageId;
let Urls = EmailUrlInfo
    | where NetworkMessageId in (targetIds)
    | summarize Urls = make_set(Url) by NetworkMessageId;
let Clicks = UrlClickEvents
    | where NetworkMessageId in (targetIds)
    | summarize
        ClickedUrls = make_set(Url),
        ClickedThrough = make_set_if(Url, IsClickedThrough == true),
        FirstClick = min(Timestamp),
        LastClick = max(Timestamp)
      by NetworkMessageId;
EmailCore
| join kind=leftouter Attachments on NetworkMessageId
| join kind=leftouter Urls on NetworkMessageId
| join kind=leftouter Clicks on NetworkMessageId
| summarize
    MessageCount = dcount(NetworkMessageId),
    MessageIds = make_set(NetworkMessageId),
    Subjects = make_set(Subject),
    Senders = make_set(SenderFromAddress),
    SenderDomains = make_set(SenderFromDomain),
    SenderIPs = make_set(SenderIP),
    DeliveryActions = make_set(DeliveryAction),
    ThreatTypes = make_set(ThreatTypes),
    AttachmentSHA256 = make_set(AttachmentSHA256),
    Urls = make_set(Urls),
    ClickedUrls = make_set(ClickedUrls),
    ClickedThrough = make_set(ClickedThrough),
    FirstEmailSeen = min(EmailTimestamp),
    LastEmailSeen = max(EmailTimestamp),
    FirstClick = min(FirstClick),
    LastClick = max(LastClick)
  by UPN = RecipientEmailAddress
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Phishing Stage 1 — Core email evidence, summarised per recipient UPN.
// Source: Defender advanced-hunting (windows-defender-365). See Stage 0 header for
//   the connector / Vendor.Workload caveats. Pivot key: Vendor.properties.NetworkMessageId.
// {{target_ids}} is the comma-quoted NetworkMessageId set from Stage 0.
// CQL is join-free here: run each sub-query and correlate on NetworkMessageId.

// --- Sub-query A: Email evidence per recipient UPN ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| groupBy([Vendor.properties.RecipientEmailAddress], function=[
    count(field=Vendor.properties.NetworkMessageId, distinct=true, as=MessageCount),
    collect([Vendor.properties.NetworkMessageId], limit=200),
    collect([Vendor.properties.Subject], limit=20),
    collect([Vendor.properties.SenderFromAddress], limit=20),
    collect([Vendor.properties.SenderDisplayName], limit=20),
    collect([Vendor.properties.SenderFromDomain], limit=20),
    collect([Vendor.properties.SenderIPv4], limit=20),
    collect([Vendor.properties.DeliveryAction], limit=10),
    collect([Vendor.properties.DeliveryLocation], limit=10),
    collect([Vendor.properties.ThreatTypes], limit=10),
    min(@timestamp, as=FirstEmailSeen),
    max(@timestamp, as=LastEmailSeen)
  ])
| sort(MessageCount, order=desc, limit=200)


// --- Sub-query B: Attachment hashes per message ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailAttachmentInfo"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| groupBy([Vendor.properties.NetworkMessageId], function=[
    collect([Vendor.properties.SHA256], limit=50),
    collect([Vendor.properties.FileName], limit=50)
  ])
| sort(Vendor.properties.NetworkMessageId, order=asc, limit=500)


// --- Sub-query C: URLs per message ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailUrlInfo"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| groupBy([Vendor.properties.NetworkMessageId], function=[
    collect([Vendor.properties.Url], limit=100),
    collect([Vendor.properties.UrlDomain], limit=100)
  ])
| sort(Vendor.properties.NetworkMessageId, order=asc, limit=500)


// --- Sub-query D: URL clicks per message + recipient (who clicked through) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "UrlClickEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| groupBy([Vendor.properties.NetworkMessageId, Vendor.properties.AccountUpn], function=[
    count(as=ClickCount),
    collect([Vendor.properties.Url], limit=50),
    collect([Vendor.properties.IsClickedThrough], limit=5),
    collect([Vendor.properties.IPAddress], limit=20),
    min(@timestamp, as=FirstClick),
    max(@timestamp, as=LastClick)
  ])
| sort(ClickCount, order=desc, limit=200)
```

### Stage 2 — Post-delivery logon correlation

- **Run:** when Stage 1 shows DeliveryAction == "Delivered" AND ThreatTypes present.
- **Purpose:** detect whether any recipient logged on to a device within 30 minutes

**Microsoft Sentinel (KQL)**

```kql
let targetIds = dynamic([{{target_ids}}]);
let Recipients = EmailEvents
    | where NetworkMessageId in (targetIds)
    | where DeliveryAction == "Delivered"
    | project
        TimeEmail = Timestamp,
        UPN = RecipientEmailAddress,
        AccountName = tostring(split(RecipientEmailAddress, "@")[0]),
        NetworkMessageId,
        Subject;
Recipients
| join kind=inner (
    IdentityLogonEvents
    | project LogonTime = Timestamp, AccountName, DeviceName, LogonType
) on AccountName
| where (LogonTime - TimeEmail) between (0min .. 30min)
| project
    UPN,
    TimeEmail,
    LogonTime,
    TimeDelta = LogonTime - TimeEmail,
    AccountName,
    DeviceName,
    LogonType,
    Subject,
    NetworkMessageId
| sort by UPN asc, TimeEmail asc
| take 50
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Phishing Stage 2 — Post-delivery logon correlation.
// Goal (from the Sentinel original): for recipients of *delivered* phishing mail,
//   find an endpoint logon within ~30 minutes of delivery (possible compromise).
// Email side: Defender advanced-hunting EmailEvents (windows-defender-365).
// Logon side: Falcon endpoint logons (#event_simpleName=UserLogon) — the NG-SIEM
//   equivalent of Sentinel IdentityLogonEvents.
// CQL is join-free: run A, then run B filtered to the account(s) of interest and
//   correlate on AccountName + a 0–30 min window after the email DeliveryTime.

// --- Sub-query A: Delivered recipients (with derived AccountName) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| Vendor.properties.DeliveryAction = "Delivered"
| regex("^(?<AccountName>[^@]+)@", field=Vendor.properties.RecipientEmailAddress)
| table([@timestamp, Vendor.properties.RecipientEmailAddress, AccountName,
         Vendor.properties.Subject, Vendor.properties.NetworkMessageId], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Endpoint logons for the recipient account(s) ---
// Replace the AccountName regex below with the account(s) surfaced by Sub-query A,
// then look for LogonTime within 0–30 min AFTER the matching email DeliveryTime.

#event_simpleName=UserLogon
| UserName = /__RECIPIENT_ACCOUNT__/i
| table([@timestamp, UserName, ComputerName, LogonType, UserSid], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 3 — URL delivery scope and exposure time

- **Run:** when Stage 1 returns URLs.
- **Purpose:** find all recipients who received this URL, check delivery status,

**Microsoft Sentinel (KQL)**

```kql
let URL = "{{url}}";
EmailUrlInfo
| where Url has URL
| join kind=inner (
    EmailEvents
    | where DeliveryAction == "Delivered" and EmailDirection == "Inbound"
) on NetworkMessageId
| project
    DeliveryTime = Timestamp,
    NetworkMessageId,
    Url,
    SenderFromAddress,
    SenderIPv4,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    DeliveryLocation
| join kind=leftouter (
    EmailPostDeliveryEvents
    | where ActionType has "ZAP"
    | project NetworkMessageId, RecipientEmailAddress, ZAPTime = Timestamp, ZAPAction = ActionType
) on NetworkMessageId, RecipientEmailAddress
| extend ExposureMinutes = iff(isnotempty(ZAPTime), datetime_diff('minute', ZAPTime, DeliveryTime), -1)
| project
    DeliveryTime,
    ZAPTime,
    ExposureMinutes,
    NetworkMessageId,
    SenderFromAddress,
    SenderIPv4,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    DeliveryLocation,
    ZAPAction
| sort by DeliveryTime asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Phishing Stage 3 — URL delivery scope and exposure time.
// Goal: who received the malicious {{url}}, was it delivered to the inbox, and how
//   long was it exposed before ZAP / admin purge removed it.
// Source: Defender advanced-hunting (windows-defender-365). See Stage 0 header.
// CQL is join-free: pivot on NetworkMessageId (+ RecipientEmailAddress) and compute
//   ExposureMinutes = (post-delivery ActionTime − DeliveryTime) from B and C.

// --- Sub-query A: Messages carrying the URL ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailUrlInfo"
| Vendor.properties.Url = /{{url}}/i
| groupBy([Vendor.properties.NetworkMessageId], function=[
    collect([Vendor.properties.Url], limit=20),
    collect([Vendor.properties.UrlDomain], limit=20)
  ])
| sort(Vendor.properties.NetworkMessageId, order=asc, limit=500)


// --- Sub-query B: Delivery detail for inbound, delivered mail (pivot on NetworkMessageId from A) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| Vendor.properties.DeliveryAction = "Delivered"
| Vendor.properties.EmailDirection = "Inbound"
| table([@timestamp, Vendor.properties.NetworkMessageId, Vendor.properties.SenderFromAddress,
         Vendor.properties.SenderIPv4, Vendor.properties.RecipientEmailAddress,
         Vendor.properties.Subject, Vendor.properties.DeliveryLocation], limit=500)
| sort(@timestamp, order=asc, limit=500)


// --- Sub-query C: Post-delivery remediation (ZAP / purge) per message + recipient ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailPostDeliveryEvents"
| Vendor.properties.ActionType = /ZAP/i
| table([@timestamp, Vendor.properties.NetworkMessageId, Vendor.properties.RecipientEmailAddress,
         Vendor.properties.ActionType], limit=500)
| sort(@timestamp, order=asc, limit=500)
```

### Stage 4 — Attachment endpoint execution

- **Run:** when Stage 1 returns attachment hashes.
- **Purpose:** confirm whether the attachment was written to disk and/or executed

**Microsoft Sentinel (KQL)**

```kql
let targetIds = dynamic([{{target_ids}}]);
let AttachmentHash = "{{sha256}}";
let DeliveryWindow = EmailEvents
    | where NetworkMessageId in (targetIds)
    | summarize EarliestDelivery = min(Timestamp)
    | project EarliestDelivery;
let FileWritten = DeviceFileEvents
    | where SHA256 =~ AttachmentHash
    | where Timestamp between (toscalar(DeliveryWindow) .. (toscalar(DeliveryWindow) + 2h))
    | project
        FileTimestamp = Timestamp,
        DeviceName,
        FileName,
        FolderPath,
        SHA256,
        FileOriginUrl,
        InitiatingProcessFileName,
        ActionType;
let FileExecuted = DeviceProcessEvents
    | where SHA256 =~ AttachmentHash
    | where Timestamp between (toscalar(DeliveryWindow) .. (toscalar(DeliveryWindow) + 2h))
    | project
        ExecTimestamp = Timestamp,
        DeviceName,
        FileName,
        FolderPath,
        SHA256,
        ProcessCommandLine,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        AccountName;
FileWritten
| join kind=leftouter FileExecuted on DeviceName, SHA256
| project
    FileTimestamp,
    ExecTimestamp,
    Executed = isnotempty(ExecTimestamp),
    DeviceName,
    FileName,
    FolderPath,
    SHA256,
    ProcessCommandLine,
    InitiatingProcessFileName,
    AccountName,
    FileOriginUrl
| sort by FileTimestamp asc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Phishing Stage 4 — Attachment endpoint execution.
// Goal: was the attachment ({{sha256}}) written to disk and/or executed on an
//   endpoint, within ~2h of email delivery.
// Primary source: CrowdStrike Falcon endpoint telemetry (#event_simpleName=...),
//   the NG-SIEM equivalent of Sentinel DeviceFileEvents / DeviceProcessEvents.
//   Falcon carries the file hash in SHA256HashData.
// Alternative when Falcon endpoint is not deployed: Defender advanced-hunting
//   DeviceFileEvents / DeviceProcessEvents via #event.dataset="windows-defender-365.event"
//   (filter Vendor.properties.SHA256 = "{{sha256}}").
// CQL is join-free: correlate A and B on ComputerName + SHA256HashData within ~2h
//   of the delivery time from Stage 1/3.

// --- Sub-query A: File written to disk with the attachment hash ---

#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| SHA256HashData = "{{sha256}}"
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Process execution of the attachment hash ---

#event_simpleName=ProcessRollup2
| SHA256HashData = "{{sha256}}"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine,
         ParentBaseFileName, ParentCommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

---

## Privilege Escalation Investigation (`privilege-escalation`)

Multi-stage privilege escalation and AD group change investigation. Stage 1 gathers the escalation event detail across Entra ID audit logs, on-prem AD security events, and related security alerts. Stage 2 checks the actor's sign-in legitimacy (location, risk, device, identity). Stage 3 is conditional — tracks what the target account did after gaining elevated privileges (admin portal access, cascading changes, mailbox abuse).

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `actor_upn` | string | — | UPN of the account that performed the escalation action |
| `target_user` | string | — | UPN of the account that was escalated (set to __NONE__ if investigating actor only) |
| `target_group` | string | — | Group name the target was added to (set to __NONE__ if not a group-add alert) |
| `lookback` | string | `14d` | Time range to investigate (default 14d) |

### Stage 1 — Escalation event detail

- **Run:** ALWAYS — starting point for every privilege escalation investigation.

**Microsoft Sentinel (KQL)**

```kql
union
(
    AuditLogs
    | where TimeGenerated > ago({{lookback}})
    | where OperationName in (
        "Add member to role",
        "Add member to group",
        "Add eligible member to role",
        "Add eligible member (permanent)",
        "Add member to role in PIM requested (permanent)",
        "Add member to role outside of PIM",
        "User activated eligible role",
        "Remove member from role",
        "Remove member from group"
    )
    | where InitiatedBy has "{{actor_upn}}"
        or TargetResources has "{{target_user}}"
        or TargetResources has "{{target_group}}"
    | extend ActorUPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
    | extend ActorIP = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
    | extend TargetAccount = tostring(TargetResources[0].userPrincipalName)
    | extend TargetGroup = tostring(TargetResources[0].displayName)
    | project
        SourceTable = "AuditLogs",
        TimeGenerated,
        Activity = OperationName,
        ActorUPN,
        ActorIP,
        TargetAccount,
        TargetGroup,
        Result,
        Detail = tostring(AdditionalDetails)
),
(
    SecurityEvent
    | where TimeGenerated > ago({{lookback}})
    | where EventID in (4728, 4732, 4756, 4727, 4731, 4755)
    // 4728 = member added to domain local group
    // 4732 = member added to global security group
    // 4756 = member added to universal security group
    // 4727/4731/4755 = corresponding group deletions
    | where SubjectUserName has "{{actor_upn}}"
        or TargetUserName has "{{target_user}}"
        or TargetUserName has "{{target_group}}"
    // Uncomment to filter by device:
    // | where Computer has "{{device_name}}"
    | project
        SourceTable = "SecurityEvent",
        TimeGenerated,
        Activity = strcat("EventID ", tostring(EventID), " - ", Activity),
        ActorUPN = SubjectUserName,
        ActorIP = IpAddress,
        TargetAccount = MemberName,
        TargetGroup = TargetUserName,
        Result = tostring(EventID),
        Detail = EventData
),
(
    SecurityAlert
    | where TimeGenerated > ago({{lookback}})
    | where Entities has "{{actor_upn}}"
        or Entities has "{{target_user}}"
    | project
        SourceTable = "SecurityAlert",
        TimeGenerated,
        Activity = AlertName,
        ActorUPN = "",
        ActorIP = "",
        TargetAccount = "",
        TargetGroup = "",
        Result = AlertSeverity,
        Detail = Description
)
| sort by TimeGenerated desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Privilege Escalation Stage 1 — Escalation event detail.
// Covers cloud (Entra/AAD directory audit), on-prem AD (Windows security events),
//   and related detections — the three unioned sources of the Sentinel original.
// Params: {{actor_upn}} (who performed it), {{target_user}}, {{target_group}}
//   (__NONE__ when not applicable — the regex simply won't match).

// --- Sub-query A: Entra/AAD role & group changes (M365 unified audit log) ---
// AzureActiveDirectory operations flow through the verified m365 module.

#Vendor="microsoft" #event.module=m365
| Vendor.Workload = "AzureActiveDirectory"
| in(field=Vendor.Operation, values=["Add member to role", "Add member to group",
    "Add eligible member to role", "Add eligible member (permanent)",
    "Add member to role in PIM requested (permanent)", "Add member to role outside of PIM",
    "User activated eligible role", "Remove member from role", "Remove member from group"])
| Vendor.UserId = /{{actor_upn}}/i OR @rawstring = /{{target_user}}/i OR @rawstring = /{{target_group}}/i
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.ResultStatus], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: On-prem AD group-membership changes (Windows security events) ---
// 4728 = added to global group, 4732 = domain-local, 4756 = universal
//   (4727/4731/4755 = group created/changed). SubjectUserName = actor, TargetUserName
//   = group, MemberName/MemberSid = the added principal (⚠ MemberName not in the
//   discovered sample — verify against the client repo if empty).

#Vendor="microsoft" #event.module=windows
| in(field=EventCode, values=["4728", "4732", "4756", "4727", "4731", "4755"])
| windows.EventData.SubjectUserName = /{{actor_upn}}/i OR windows.EventData.TargetUserName = /{{target_user}}/i OR windows.EventData.TargetUserName = /{{target_group}}/i
| table([@timestamp, EventCode, host.hostname, windows.EventData.SubjectUserName,
         windows.EventData.TargetUserName, windows.EventData.MemberName,
         windows.EventData.MemberSid], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query C: Related detections (Defender AlertInfo) ---
// Sub-table discriminator is Vendor.Workload="AlertInfo" (see phishing Stage 0 header).
// Falcon alternative: #event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "AlertInfo"
| @rawstring = /{{actor_upn}}/i OR @rawstring = /{{target_user}}/i
| table([@timestamp, Vendor.properties.Title, Vendor.properties.Severity,
         Vendor.properties.Category], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

### Stage 2 — Actor legitimacy check

- **Run:** ALWAYS — checks whether the actor's sign-in context is legitimate.

**Microsoft Sentinel (KQL)**

```kql
// Privilege-Escalation Stage 2 — Actor legitimacy check.
// Sign-ins are summarised per source IP / location (one row per IP with
// success/fail split, apps, risk, user-agents) rather than dumped raw — an
// active actor over the lookback can produce thousands of sign-in rows. The
// IdentityInfo row stays a single authoritative directory snapshot. Pivot to
// raw sign-in rows for a specific suspect IP once one stands out.
let actor = "{{actor_upn}}";
let lookback = {{lookback}};
let SignIns =
    union
    (
        SigninLogs
        | where TimeGenerated > ago(lookback)
        | where UserPrincipalName =~ actor
        | extend SignInType = "Interactive"
    ),
    (
        AADNonInteractiveUserSignInLogs
        | where TimeGenerated > ago(lookback)
        | where UserPrincipalName =~ actor
        | extend SignInType = "NonInteractive"
    )
    | summarize SignIns = count(),
        Successes = countif(ResultType == 0), Failures = countif(ResultType != 0),
        FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
        Apps = make_set(AppDisplayName, 20), Risks = make_set(RiskLevelDuringSignIn, 10),
        UserAgents = make_set(UserAgent, 10)
        by IPAddress, Location, SignInType
    | extend SourceTable = strcat(SignInType, "SignIns"), TimeGenerated = LastSeen;
let Identity =
    IdentityInfo
    | where AccountUPN =~ actor
    | summarize arg_max(TimeGenerated, *) by AccountUPN
    | project SourceTable = "IdentityInfo", TimeGenerated, AccountUPN,
        AccountDisplayName, Department, JobTitle;
union isfuzzy=true SignIns, Identity
| sort by SourceTable asc, SignIns desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Privilege Escalation Stage 2 — Actor legitimacy check for {{actor_upn}}.
// Is the actor's sign-in context legitimate (location, risk, device, CA)?
// Source: Entra ID sign-ins (entraid connector, dataset entraid.signin — verified).
//   The Sentinel IdentityInfo enrichment (department / job title) has no portable
//   NG-SIEM equivalent — pull it from the directory if role context is needed.

// --- Sub-query A: Interactive sign-ins with risk / device / CA context ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{actor_upn}}/i
| Vendor.properties.isInteractive = "true"
| groupBy([source.ip, Vendor.properties.location.city, Vendor.properties.location.countryOrRegion],
    function=[
      count(as=TotalCount),
      collect([Vendor.properties.appDisplayName], limit=20),
      collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
      collect([Vendor.properties.riskState], limit=10),
      collect([Vendor.properties.riskDetail], limit=10),
      collect([Vendor.properties.conditionalAccessStatus], limit=10),
      collect([Vendor.properties.authenticationRequirement], limit=10),
      collect([Vendor.properties.deviceDetail.operatingSystem], limit=10),
      collect([Vendor.properties.deviceDetail.isCompliant], limit=5),
      collect([Vendor.properties.deviceDetail.isManaged], limit=5),
      collect([Vendor.properties.deviceDetail.trustType], limit=5),
      collect([Vendor.properties.userAgent], limit=10),
      min(@timestamp, as=FirstSeen),
      max(@timestamp, as=LastSeen)
    ])
| sort(TotalCount, order=desc, limit=200)


// --- Sub-query B: Non-interactive sign-ins ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{actor_upn}}/i
| Vendor.properties.isInteractive = "false"
| groupBy([source.ip, Vendor.properties.location.countryOrRegion], function=[
    count(as=TotalCount),
    collect([Vendor.properties.appDisplayName], limit=20),
    collect([Vendor.properties.status.errorCode], limit=15),
    collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(TotalCount, order=desc, limit=200)
```

### Stage 3 — Post-escalation activity (target account)

- **Run:** CONDITIONAL — when escalation looks suspicious or actor legitimacy is

**Microsoft Sentinel (KQL)**

```kql
union
(
    SigninLogs
    | where TimeGenerated > ago({{lookback}})
    | where UserPrincipalName =~ "{{target_user}}"
    | where AppDisplayName in (
        "Azure Portal",
        "Microsoft Azure Management",
        "Microsoft 365 admin center",
        "Exchange Admin Center",
        "Microsoft Entra admin center",
        "Microsoft Graph",
        "Microsoft Graph PowerShell",
        "Azure Active Directory PowerShell",
        "Microsoft Teams Admin Center",
        "SharePoint Online Management Shell"
    )
    | project
        SourceTable = "SigninLogs",
        TimeGenerated,
        Activity = strcat("Sign-in to ", AppDisplayName),
        TargetAccount = UserPrincipalName,
        IPAddress,
        AppOrResource = AppDisplayName,
        Detail = tostring(DeviceDetail)
),
(
    AuditLogs
    | where TimeGenerated > ago({{lookback}})
    | where InitiatedBy has "{{target_user}}"
    | where OperationName in (
        // Cascading privilege changes
        "Add member to role",
        "Add member to group",
        "Add eligible member to role",
        // App and OAuth abuse
        "Add application",
        "Add service principal",
        "Add service principal credentials",
        "Consent to application",
        "Add app role assignment to service principal",
        // Credential changes
        "Reset password (by admin)",
        "Update user",
        "Add owner to application",
        "Add owner to service principal",
        // MFA manipulation
        "User registered security info",
        "User deleted security info",
        "Admin registered security info"
    )
    | extend TargetAccount = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
    | project
        SourceTable = "AuditLogs",
        TimeGenerated,
        Activity = OperationName,
        TargetAccount,
        IPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress),
        AppOrResource = tostring(TargetResources[0].displayName),
        Detail = tostring(TargetResources)
),
(
    OfficeActivity
    | where TimeGenerated > ago({{lookback}})
    | where UserId =~ "{{target_user}}"
    | where Operation in (
        // Mailbox rule manipulation
        "New-InboxRule",
        "Set-InboxRule",
        "Enable-InboxRule",
        "New-TransportRule",
        "Set-TransportRule",
        "UpdateInboxRules",
        // eDiscovery / compliance search
        "New-ComplianceSearch",
        "Start-ComplianceSearch",
        "New-ComplianceSearchAction",
        // SharePoint admin actions
        "SiteCollectionAdminAdded",
        "SharingPolicyChanged",
        "SiteCollectionCreated"
    )
    | project
        SourceTable = "OfficeActivity",
        TimeGenerated,
        Activity = Operation,
        TargetAccount = UserId,
        IPAddress = ClientIP,
        AppOrResource = OfficeWorkload,
        Detail = tostring(Parameters)
)
| sort by TimeGenerated desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Privilege Escalation Stage 3 — Post-escalation activity for {{target_user}}.
// What did the escalated account do with its new privileges — admin-portal access,
//   cascading directory/app/credential/MFA changes, and Exchange/SharePoint abuse.
// Sources: Entra sign-ins (entraid.signin) and the M365 unified audit log (m365) —
//   both verified modules.

// --- Sub-query A: Sign-ins to admin portals / management apps ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{target_user}}/i
| in(field=Vendor.properties.appDisplayName, values=["Azure Portal",
    "Microsoft Azure Management", "Microsoft 365 admin center", "Exchange Admin Center",
    "Microsoft Entra admin center", "Microsoft Graph", "Microsoft Graph PowerShell",
    "Azure Active Directory PowerShell", "Microsoft Teams Admin Center",
    "SharePoint Online Management Shell"])
| table([@timestamp, Vendor.properties.appDisplayName, source.ip,
         Vendor.properties.location.countryOrRegion, Vendor.properties.status.errorCode], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: Cascading directory / app / credential / MFA changes by the target ---

#Vendor="microsoft" #event.module=m365
| Vendor.Workload = "AzureActiveDirectory"
| Vendor.UserId = /{{target_user}}/i
| in(field=Vendor.Operation, values=["Add member to role", "Add member to group",
    "Add eligible member to role", "Add application", "Add service principal",
    "Add service principal credentials", "Consent to application",
    "Add app role assignment to service principal", "Reset password (by admin)",
    "Update user", "Add owner to application", "Add owner to service principal",
    "User registered security info", "User deleted security info",
    "Admin registered security info"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query C: Exchange / SharePoint operations (inbox rules, eDiscovery, sharing) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_user}}/i
| in(field=Vendor.Operation, values=["New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "New-TransportRule", "Set-TransportRule", "UpdateInboxRules", "New-ComplianceSearch",
    "Start-ComplianceSearch", "New-ComplianceSearchAction", "SiteCollectionAdminAdded",
    "SharingPolicyChanged", "SiteCollectionCreated"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

---

## Ransomware / Impact Investigation (`ransomware`)

Detects and scopes ransomware impact behaviour: shadow-copy and recovery tampering, mass file modification / extension-change bursts, ransom-note drops, and encryption-tool detections. Stages 1 (recovery tampering) and 2 (mass file modification) always run; Stages 3-4 are conditional on prior signal. Defender DeviceFileEvents gives a clean rename/extension burst; Falcon file-rename telemetry is weaker, so on LogScale Stage 2 leans on process behaviour, file-write volume, and detections (see the .cql header).

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `device_name` | string | — | Hostname / DeviceName showing impact behaviour (regex/substring matched). |
| `user` | string | `__NONE__` | Associated user account (optional; __NONE__ to scan all). |
| `lookback` | string | `3d` | Time range to investigate (default 3d). |

### Stage 1 — Shadow-copy and recovery tampering

- **Run:** ALWAYS — earliest reliable ransomware signal.
- **Purpose:** vssadmin/wbadmin/bcdedit/wmic shadowcopy/cipher abuse to inhibit recovery.

**Microsoft Sentinel (KQL)**

```kql
// Ransomware Stage 1 — Shadow-copy & recovery tampering (MITRE T1490).
let lookback = {{lookback}};
let device = "{{device_name}}";
let user = "{{user}}";
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceName has device
| where user == "__NONE__" or AccountName has user
| where FileName in~ ("vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wmic.exe",
    "cipher.exe", "diskshadow.exe", "powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("delete shadows", "delete catalog",
    "resize shadowstorage", "shadowcopy delete", "win32_shadowcopy",
    "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "wbadmin delete",
    "deletecatalog", "/purge")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Ransomware Stage 1 — Shadow-copy & recovery tampering (MITRE T1490).
// Source: CrowdStrike Falcon ProcessRollup2 — CommandLine analysis of the recovery-
//   inhibition LOLBins is the reliable cross-platform signal.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(vssadmin|wbadmin|bcdedit|wmic|cipher|diskshadow|powershell|pwsh)\.exe$/i
| CommandLine = /delete shadows|delete catalog|resize shadowstorage|shadowcopy delete|win32_shadowcopy|recoveryenabled no|bootstatuspolicy ignoreallfailures|wbadmin delete|deletecatalog|\/purge/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine,
         ParentBaseFileName, ParentCommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 2 — Mass file modification / extension burst

- **Run:** ALWAYS — core encryption behaviour.
- **Purpose:** high-rate file rename/modify and extension change per device.

**Microsoft Sentinel (KQL)**

```kql
// Ransomware Stage 2 — Mass file modification / extension burst.
let lookback = {{lookback}};
let device = "{{device_name}}";
DeviceFileEvents
| where Timestamp > ago(lookback)
| where DeviceName has device
| where ActionType in ("FileRenamed", "FileModified", "FileCreated")
| extend Ext = tolower(extract(@"\.([A-Za-z0-9_-]{1,12})$", 1, FileName))
| summarize
    ModCount = count(),
    DistinctExtensions = dcount(Ext),
    DistinctFolders = dcount(FolderPath),
    SampleExtensions = make_set(Ext, 30),
    SampleFiles = make_set(FileName, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
  by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where ModCount >= 200
| sort by ModCount desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Ransomware Stage 2 — Mass file modification / extension burst.
// ⚠ Platform asymmetry: Defender DeviceFileEvents gives a clean rename/extension
//   burst. Falcon has no equivalent rename-rate event in this repo's vocabulary, so
//   this approximates impact via file-WRITE volume per device. A high NewFileCount in
//   a short window from one host is the signal — confirm with the Stage 4 detection.
#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| ComputerName = /{{device_name}}/i
| groupBy([ComputerName], function=[
    count(as=NewFileCount),
    collect([TargetFileName], limit=40),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| NewFileCount >= 200
| sort(NewFileCount, order=desc, limit=200)
```

### Stage 3 — Ransom-note drops

- **Run:** when Stage 1 or 2 shows impact signal.
- **Purpose:** ransom-note filename patterns written across many folders.

**Microsoft Sentinel (KQL)**

```kql
// Ransomware Stage 3 — Ransom-note drops (same note written across many folders).
let lookback = {{lookback}};
let device = "{{device_name}}";
DeviceFileEvents
| where Timestamp > ago(lookback)
| where DeviceName has device
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName matches regex @"(?i)(readme|recover|restore|decrypt|how.?to.?(decrypt|recover)|unlock|_help_|ransom)"
| summarize
    NoteCount = count(),
    DistinctFolders = dcount(FolderPath),
    SampleFolders = make_set(FolderPath, 30),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
  by DeviceName, FileName
| where DistinctFolders >= 3
| sort by DistinctFolders desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Ransomware Stage 3 — Ransom-note drops.
// Source: Falcon file-write events; ransom-note filename patterns.
#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /readme|recover|restore|decrypt|how.?to.?(decrypt|recover)|unlock|_help_|ransom/i
| groupBy([ComputerName, TargetFileName], function=[
    count(as=NoteCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(NoteCount, order=desc, limit=200)
```

### Stage 4 — Encryption tooling and impact detections

- **Run:** when Stage 1 or 2 shows impact signal.
- **Purpose:** correlated EDR detections and service-stop events around impact.

**Microsoft Sentinel (KQL)**

```kql
// Ransomware Stage 4 — Encryption tooling & impact detections.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    SecurityAlert
    | where TimeGenerated > ago(lookback)
    | where Entities has device
        or AlertName has_any ("ransom", "encryption", "impact", "shadow copy", "inhibit recovery")
    | project Source = "SecurityAlert", TimeGenerated, Name = AlertName,
        Severity = AlertSeverity, Detail = tostring(Tactics)
),
(
    SecurityEvent
    | where TimeGenerated > ago(lookback)
    | where Computer has device
    | where EventID in (7036, 7045, 7040)
    | project Source = "SecurityEvent", TimeGenerated,
        Name = strcat("EventID ", tostring(EventID)), Severity = "",
        Detail = RenderedDescription
)
| sort by TimeGenerated asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Ransomware Stage 4 — Encryption tooling & impact detections.
// Source: Falcon detection summary events. ⚠ DetectName/DetectDescription/Tactic/
//   Technique are standard Falcon detection fields — confirm against the client repo
//   if empty (some sensors populate Objective/Scenario instead).
#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| ComputerName = /{{device_name}}/i
| table([@timestamp, ComputerName, DetectName, DetectDescription, Severity,
         Tactic, Technique, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc, limit=200)
```

**Definitions**

- **Recovery Inhibition** — MITRE T1490 — deleting volume shadow copies and disabling Windows recovery so victims cannot restore without paying. A hallmark pre-encryption step.

---

## Inbound Reconnaissance Detection (`reconnaissance`)

Detects active inbound reconnaissance preceding intrusion: credential stuffing / password spray, external port and service scanning, and sub-domain / MX enumeration of the client's registered domains. Stages 1 (identity) and 2 (network scanning) are portable across Sentinel and LogScale; Stage 3 (authoritative-DNS enumeration) is Sentinel-only and log-source dependent (requires the DNS Analytics connector). Stage 1 always runs; Stages 2-3 are conditional on prior findings.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `lookback` | string | `24h` | Time range to investigate (default 24h). |
| `target_upn` | string | `__NONE__` | Optional UPN to focus a credential-spray hunt on. Set to __NONE__ to scan all accounts. |
| `source_ip` | string | `__NONE__` | Optional external source IP to focus on. Set to __NONE__ to scan all sources. |

### Stage 1 — Credential stuffing / password spray

- **Run:** ALWAYS — entry point; surfaces spraying source IPs and the accounts targeted.
- **Purpose:** High-volume failed sign-ins across many accounts from a single IP in a short window.

**Microsoft Sentinel (KQL)**

```kql
// Credential stuffing / password spray - high-volume failed auth across many
// accounts from a single source IP in a short window.
//   password spray = many distinct users, few attempts each
//   credential stuffing / brute force = high attempt volume from one source
let lookback = {{lookback}};
let target = "{{target_upn}}";
let srcip = "{{source_ip}}";
union isfuzzy=true
  (SigninLogs
     | where TimeGenerated > ago(lookback) | where ResultType != 0
     | extend SignInType = "Interactive"),
  (AADNonInteractiveUserSignInLogs
     | where TimeGenerated > ago(lookback) | where ResultType != 0
     | extend SignInType = "NonInteractive")
| where target == "__NONE__" or UserPrincipalName =~ target
| where srcip == "__NONE__" or IPAddress == srcip
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize
    FailedAttempts = count(),
    DistinctUsers = dcount(UserPrincipalName),
    TargetedUsers = make_set(UserPrincipalName, 50),
    ErrorCodes = make_set(ResultType, 10),
    Apps = make_set(AppDisplayName, 10),
    Countries = make_set(Country, 5),
    SignInTypes = make_set(SignInType, 2),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by IPAddress, TimeWindow = bin(TimeGenerated, 1h)
| extend AttemptsPerUser = round(todouble(FailedAttempts) / DistinctUsers, 2)
| where DistinctUsers >= 5 or FailedAttempts >= 25
| extend Pattern = case(
    DistinctUsers >= 10 and AttemptsPerUser <= 5, "password_spray",
    FailedAttempts >= 50, "credential_stuffing_or_brute_force",
    "elevated_failed_auth")
| project IPAddress, TimeWindow, Pattern, FailedAttempts, DistinctUsers,
          AttemptsPerUser, Countries, Apps, ErrorCodes, SignInTypes,
          TargetedUsers, FirstSeen, LastSeen
| sort by DistinctUsers desc, FailedAttempts desc
// --- Optional: correlate spraying IPs with platform detections (SecurityAlert) ---
// SecurityAlert
// | where TimeGenerated > ago(lookback)
// | where AlertName has_any ("spray", "brute force", "failed sign-in", "credential")
// | project TimeGenerated, AlertName, AlertSeverity, ProviderName, Entities
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Credential stuffing / password spray - failed Entra ID sign-ins (dedicated
// entraid connector, dataset entraid.signin) clustered by source IP.
//   many distinct users, few attempts each = password spray
//   high attempt volume from one source = credential stuffing / brute force
#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.status.errorCode != 0
| groupBy([source.ip],
          function=[count(as=FailedAttempts),
                    count(field=Vendor.properties.userPrincipalName, distinct=true, as=DistinctUsers),
                    collect([Vendor.properties.userPrincipalName], limit=50)])
| AttemptsPerUser := FailedAttempts / DistinctUsers
| DistinctUsers >= 5 OR FailedAttempts >= 25
| sort(DistinctUsers, order=desc)
```

### Stage 2 — Port / service scanning

- **Run:** When Stage 1 surfaces a candidate source IP, or network-layer recon is suspected.
- **Purpose:** A single external IP contacting many internal hosts or ports in a short window.

**Microsoft Sentinel (KQL)**

```kql
// Port / service scanning - a single external IP touching many internal hosts
// or many distinct ports in a short window. Endpoint inbound visibility depends
// on the MDE sensor; perimeter firewall logs (CommonSecurityLog) are the richer
// source where forwarded - see the optional block below.
let lookback = {{lookback}};
let srcip = "{{source_ip}}";
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where ActionType in ("InboundConnectionAccepted", "ConnectionRequest", "ConnectionFailed", "ListeningConnectionCreated")
| where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))
| where srcip == "__NONE__" or RemoteIP == srcip
| summarize
    DistinctHosts = dcount(DeviceName),
    DistinctPorts = dcount(LocalPort),
    Hosts = make_set(DeviceName, 50),
    Ports = make_set(LocalPort, 50),
    Connections = count(),
    Actions = make_set(ActionType, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by RemoteIP, TimeWindow = bin(TimeGenerated, 1h)
| where DistinctPorts >= 10 or DistinctHosts >= 5
| extend ScanType = case(
    DistinctHosts >= 5 and DistinctPorts <= 3, "horizontal_host_sweep",
    DistinctPorts >= 10 and DistinctHosts <= 2, "vertical_port_scan",
    "broad_scan")
| project RemoteIP, TimeWindow, ScanType, DistinctHosts, DistinctPorts,
          Connections, Ports, Hosts, Actions, FirstSeen, LastSeen
| sort by DistinctPorts desc, DistinctHosts desc
// --- Optional: perimeter firewall variant (CommonSecurityLog) ---
// CommonSecurityLog
// | where TimeGenerated > ago(lookback) and DeviceAction in ("deny", "drop", "reset")
// | summarize DistinctPorts = dcount(DestinationPort), DistinctHosts = dcount(DestinationIP) by SourceIP, bin(TimeGenerated, 1h)
// | where DistinctPorts >= 20 or DistinctHosts >= 10
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Port / service scanning - a single external source touching many hosts/ports.
// Inbound connections on the Falcon endpoint sensor are logged as
// NetworkReceiveAcceptIP4; NetworkConnectIP4 is included for environments that
// only surface the outbound side of the handshake.
#event_simpleName=/^(NetworkReceiveAcceptIP4|NetworkConnectIP4)$/
| RemoteAddressIP4 != /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/
| groupBy([RemoteAddressIP4],
          function=[count(as=Connections),
                    count(field=ComputerName, distinct=true, as=DistinctHosts),
                    count(field=LocalPort, distinct=true, as=DistinctPorts),
                    collect([LocalPort], limit=50)])
| DistinctPorts >= 10 OR DistinctHosts >= 5
| sort(DistinctPorts, order=desc)
```

### Stage 3 — Sub-domain / MX enumeration

- **Run:** When mail-infrastructure / authoritative-DNS enumeration is suspected and DNS logs are ingested.
- **Purpose:** Anomalous DNS query volume against the client's registered domains (authoritative-DNS recon). Log-source dependent; Sentinel-only.

**Microsoft Sentinel (KQL)**

```kql
// Sub-domain / MX enumeration - anomalous DNS query volume against the client's
// own registered domains (authoritative-DNS recon ahead of phishing / mail
// spoofing). LOG-SOURCE DEPENDENT: requires the DNS Analytics connector
// (DnsEvents) or an external/authoritative DNS log feed. Set the ClientDomains
// list below to the client's registered domains before running.
let lookback = {{lookback}};
let srcip = "{{source_ip}}";
// Replace with the client's registered domains, e.g. dynamic(["contoso.com","contoso.co.uk"]).
let ClientDomains = dynamic(["__CLIENT_DOMAIN__"]);
DnsEvents
| where TimeGenerated > ago(lookback)
| where SubType == "LookupQuery"
| where srcip == "__NONE__" or ClientIP == srcip
| extend Labels = split(Name, ".")
| where array_length(Labels) >= 2
| extend ParentDomain = strcat(tostring(Labels[array_length(Labels) - 2]), ".", tostring(Labels[array_length(Labels) - 1]))
| where ParentDomain in~ (ClientDomains) or Name has_any (ClientDomains)
| summarize
    QueryCount = count(),
    DistinctNames = dcount(Name),
    MxOrTxtQueries = countif(QueryType in ("MX", "TXT", "SOA", "NS")),
    RecordTypes = make_set(QueryType, 10),
    SampleNames = make_set(Name, 30),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by ClientIP, ParentDomain
| where DistinctNames >= 20 or MxOrTxtQueries >= 10
| project ClientIP, ParentDomain, QueryCount, DistinctNames, MxOrTxtQueries,
          RecordTypes, SampleNames, FirstSeen, LastSeen
| sort by DistinctNames desc, MxOrTxtQueries desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

_No CrowdStrike Falcon NG-SIEM (LogScale) query for this stage._

---

## Vulnerability Hunting / Active-Exploitation Detection (`vulnerability-hunting`)

The live-log half of vulnerability hunting. Pair with the caseless `eql_vuln_hunt` Encore tool: that surfaces the exposed hosts and actively-exploited CVEs (EPSS/KEV prioritised); this playbook then pivots into the SIEM/EDR log layer to answer "is the vulnerability actually being exploited on those hosts?". Confirms vulnerable software is present, hunts host-side exploitation behaviour, inbound exploitation attempts against internet-facing services, and correlated alerts / post-exploitation. Exploitation IOCs are CVE-specific — the queries are scaffolds; add the named CVE's known exploit tooling, dropped files, and C2 from threat intel before relying on them.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `cve_id` | string | `__NONE__` | CVE to hunt (e.g. CVE-2023-44487). __NONE__ to hunt broadly on a host. |
| `device_name` | string | `__NONE__` | Host to scope to (substring/regex). __NONE__ to sweep all hosts. |
| `software_name` | string | `__NONE__` | Vulnerable product name for the TVM software check (e.g. "Apache"). __NONE__ to skip filter. |
| `lookback` | string | `14d` | Time range to investigate (default 14d). |

### Stage 1 — Confirm vulnerable software & patch status

- **Run:** ALWAYS — ground the hunt in which hosts are actually vulnerable.
- **Purpose:** Corroborate the Encore exposure finding against live MDE TVM — which hosts run the vulnerable software, severity, and the recommended update. Requires Defender TVM data.

**Microsoft Sentinel (KQL)**

```kql
// Vuln Hunting Stage 1 — Confirm vulnerable software & patch status (Defender TVM).
// Corroborates the Encore eql_vuln_hunt exposure finding against live MDE telemetry.
// Requires Microsoft Defender Vulnerability Management data (DeviceTvmSoftwareVulnerabilities)
// streamed to the workspace. If TVM is not ingested, rely on the Encore hunt's
// VulnerabilityPrioritization-Hosts / -Vulnerabilities output instead.
let cve = "{{cve_id}}";
let device = "{{device_name}}";
let software = "{{software_name}}";
DeviceTvmSoftwareVulnerabilities
| where (cve == "__NONE__" or CveId =~ cve)
| where (device == "__NONE__" or DeviceName has device)
| where (software == "__NONE__" or SoftwareName has software or SoftwareVendor has software)
// Summarise per CVE + severity — one row showing how many devices are affected,
// the software involved, and the fix. Pivot to per-device raw rows for a specific
// CveId once the worst exposures are identified.
| summarize AffectedDevices = dcount(DeviceName), Devices = make_set(DeviceName, 30),
    Software = make_set(strcat(SoftwareVendor, " ", SoftwareName), 20),
    Versions = make_set(SoftwareVersion, 20),
    RecommendedUpdate = make_set(RecommendedSecurityUpdate, 10)
    by CveId, VulnerabilitySeverityLevel
| sort by VulnerabilitySeverityLevel asc, AffectedDevices desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Vuln Hunting Stage 1 — Confirm vulnerable software & patch status.
// --- UNAVAILABLE in NG-SIEM ---
// CrowdStrike vulnerability/patch data comes from Falcon Spotlight (an API product),
// not the NG-SIEM/LogScale event stream — there is no #event_simpleName for a software-
// vulnerability inventory here. Use the Encore `eql_vuln_hunt` output instead: its
// CrowdStrike-Vulnerabilities and VulnerabilityPrioritization-Hosts tables already carry
// the per-host CVE exposure and exploit flags. This stage is intentionally a no-op on
// NG-SIEM; proceed to Stage 2 for the live exploitation hunt.
//
// (Best-effort asset corroboration: confirm the host is reporting at all.)
#event_simpleName=AgentOnline
| ComputerName = /{{device_name}}/i
| groupBy([ComputerName], function=[max(@timestamp, as=LastSeen)])
| sort(LastSeen, order=desc)
```

### Stage 2 — Host-side exploitation activity

- **Run:** ALWAYS — the exploitation behaviour itself.
- **Purpose:** Server/application processes (web, db, office, java) spawning shells or LOLBins on the affected host — the classic exploitation tell. Add CVE-specific IOCs.

**Microsoft Sentinel (KQL)**

```kql
// Vuln Hunting Stage 2 — Host-side exploitation activity.
// Generic exploitation tell: an internet-facing / document-handling process spawning
// a shell or LOLBin. ADD CVE-specific IOCs for {{cve_id}} (exploit tool names, dropped
// filenames, web-shell paths, C2 domains) from threat intel before relying on this.
let lookback = {{lookback}};
let device = "{{device_name}}";
let server_procs = dynamic(["w3wp.exe","httpd.exe","nginx.exe","java.exe","javaw.exe",
    "tomcat.exe","sqlservr.exe","outlook.exe","winword.exe","excel.exe","powerpnt.exe",
    "mysqld.exe","node.exe","php-cgi.exe"]);
let lolbins = dynamic(["cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe",
    "net1.exe","certutil.exe","bitsadmin.exe","rundll32.exe","mshta.exe","wmic.exe",
    "regsvr32.exe","curl.exe","wget.exe"]);
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where (device == "__NONE__" or DeviceName has device)
| where InitiatingProcessFileName has_any (server_procs) and FileName has_any (lolbins)
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
| sort by TimeGenerated asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Vuln Hunting Stage 2 — Host-side exploitation activity (CrowdStrike ProcessRollup2).
// Exploitation tell: an internet-facing / document-handling parent process spawning a
// shell or LOLBin. ADD CVE-specific IOCs for {{cve_id}} (exploit tooling, dropped files,
// web-shell names) before relying on this.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| ParentBaseFileName = /^(w3wp|httpd|nginx|java|javaw|tomcat|sqlservr|outlook|winword|excel|powerpnt|mysqld|node|php-cgi)\.exe$/i
| FileName = /^(cmd|powershell|pwsh|whoami|net|net1|certutil|bitsadmin|rundll32|mshta|wmic|regsvr32|curl|wget)\.exe$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 3 — Inbound exploitation attempts (internet-facing)

- **Run:** when the CVE is remotely / internet-exploitable.
- **Purpose:** Inbound/public connections to the exposed host around the window — initial-access vector.

**Microsoft Sentinel (KQL)**

```kql
// Vuln Hunting Stage 3 — Inbound exploitation attempts against internet-facing services.
// Public inbound connections to the exposed host around the window — the initial-access
// vector for a remotely-exploitable CVE. Correlate the RemoteIP with the host-side
// exploitation tell from Stage 2 (shared timestamp + host = a data-level link, not just
// temporal proximity).
let lookback = {{lookback}};
let device = "{{device_name}}";
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where (device == "__NONE__" or DeviceName has device)
| where ActionType == "InboundConnectionAccepted" and RemoteIPType == "Public"
| summarize Connections = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Ports = make_set(LocalPort, 20)
    by DeviceName, RemoteIP, RemoteIPType, InitiatingProcessFileName
| sort by Connections desc
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Vuln Hunting Stage 3 — Inbound exploitation attempts (CrowdStrike NetworkReceiveAcceptIP4).
// ⚠ Verify the inbound event name for this tenant — NetworkReceiveAcceptIP4 is the inbound
//   accept event; some sensor versions only emit NetworkConnectIP4 (outbound). Confirm with:
//     #event_simpleName=/Network.*IP4/ | groupBy(#event_simpleName, function=count())
// Public inbound connections to the exposed host — the initial-access vector. Correlate
// RemoteAddressIP4 with the Stage-2 exploitation tell on the same host + window.
#event_simpleName=NetworkReceiveAcceptIP4
| ComputerName = /{{device_name}}/i
| RemoteAddressIP4 != /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.)/
| groupBy([ComputerName, RemoteAddressIP4, LocalPort], function=[
    count(as=Connections),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(Connections, order=desc)
```

### Stage 4 — Correlated alerts & post-exploitation

- **Run:** when exploitation is suspected or confirmed.
- **Purpose:** Security alerts referencing the CVE or host, plus post-exploitation recon/lateral signals.

**Microsoft Sentinel (KQL)**

```kql
// Vuln Hunting Stage 4 — Correlated alerts & post-exploitation recon.
// Two independent signals: (A) security alerts naming the CVE or host, and (B)
// discovery / lateral-movement LOLBins on the host after exploitation. Treat (B) as
// confirmation only when it shares a host+time link with Stage 2/3 — recon commands
// alone are not proof of exploitation.
let lookback = {{lookback}};
let device = "{{device_name}}";
let cve = "{{cve_id}}";
let recon = dynamic(["whoami.exe","net.exe","net1.exe","nltest.exe","ipconfig.exe",
    "systeminfo.exe","tasklist.exe","quser.exe","arp.exe","route.exe","psexec.exe",
    "wmic.exe","reg.exe","schtasks.exe","sc.exe","vssadmin.exe"]);
// (A) Alerts referencing the CVE or host
SecurityAlert
| where TimeGenerated > ago(lookback)
| where (cve == "__NONE__" or AlertName has cve or Description has cve or ExtendedProperties has cve or Entities has cve)
| where (device == "__NONE__" or Entities has device)
| project TimeGenerated, Signal = "alert", AlertName, AlertSeverity, Description, Entities
| union (
    // (B) Post-exploitation recon / lateral LOLBins on the host
    DeviceProcessEvents
    | where TimeGenerated > ago(lookback)
    | where (device == "__NONE__" or DeviceName has device)
    | where FileName has_any (recon)
    | project TimeGenerated, Signal = "post-exploit-recon", AlertName = FileName,
        AlertSeverity = "informational", Description = ProcessCommandLine,
        Entities = DeviceName
)
| sort by TimeGenerated desc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Vuln Hunting Stage 4 — Correlated detections & post-exploitation recon.

// --- Sub-query A: CrowdStrike detections on the host ---
// ⚠ Detection event name varies by tenant (EppDetectionSummaryEvent / DetectionSummaryEvent).
//   Confirm with: #event_simpleName=/Detection/ | groupBy(#event_simpleName, function=count())
#event_simpleName=/Detection.*Summary/i
| ComputerName = /{{device_name}}/i
| table([@timestamp, ComputerName, Tactic, Technique, DetectName, DetectDescription,
         Severity, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: post-exploitation recon / lateral LOLBins (ProcessRollup2) ---
// Confirmation only when sharing a host + time link with Stage 2/3 — recon alone is
// not proof of exploitation.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(whoami|net|net1|nltest|ipconfig|systeminfo|tasklist|quser|arp|route|psexec|wmic|reg|schtasks|sc|vssadmin)\.exe$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

**Definitions**

- **Active Exploitation** — A vulnerability with confirmed exploitation in the wild (CISA KEV / EPSS-high / vendor exploited flag). Presence of the vulnerable software plus exploitation behaviour on the same host elevates exposure to a live incident.
- **Exploitation Tell** — An internet-facing or document-handling process (w3wp, httpd, java, winword, outlook) spawning a shell or LOLBin — strong evidence a vulnerability was exploited for code execution.

---

## Web Shell / Exploited Public-Facing App Investigation (`web-shell`)

Detects successful exploitation of a public-facing application and web-shell activity: a web-server process spawning a shell/LOLBin, web-shell file drops in web roots, and post-exploitation under a web-service identity. Complements reconnaissance (which covers inbound recon but not successful exploitation). Stages 1-2 always run; Stage 3 is conditional.

**Parameters**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `device_name` | string | `__NONE__` | Web/app server host to scope (regex/substring matched). __NONE__ to scan all. |
| `lookback` | string | `7d` | Time range to investigate (default 7d). |

### Stage 1 — Web-server process spawning a shell

- **Run:** ALWAYS — primary web-shell execution signal.
- **Purpose:** w3wp/httpd/nginx/tomcat/java/php/node spawning cmd/powershell/etc.

**Microsoft Sentinel (KQL)**

```kql
// Web Shell Stage 1 — Web-server process spawning a shell / LOLBin.
let lookback = {{lookback}};
let device = "{{device_name}}";
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where device == "__NONE__" or DeviceName has device
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe",
    "tomcat9.exe", "java.exe", "php-cgi.exe", "php.exe", "node.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe",
    "wscript.exe", "cscript.exe", "net.exe", "whoami.exe", "certutil.exe", "bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    FileName, ProcessCommandLine, InitiatingProcessCommandLine
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Web Shell Stage 1 — Web-server process spawning a shell / LOLBin.
// A web server (w3wp/httpd/nginx/tomcat/java/php/node) spawning cmd/powershell/etc is
//   the classic web-shell execution signal — detected here via ProcessRollup2 ancestry.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| ParentBaseFileName = /^(w3wp|httpd|nginx|tomcat|tomcat9|java|php-cgi|php|node)\.exe$/i
| FileName = /^(cmd|powershell|pwsh|bash|sh|wscript|cscript|net|whoami|certutil|bitsadmin)\.exe$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName,
         CommandLine, ParentCommandLine], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 2 — Web-shell file drops in web roots

- **Run:** ALWAYS.
- **Purpose:** script files (.aspx/.php/.jsp/etc.) written under web-root paths.

**Microsoft Sentinel (KQL)**

```kql
// Web Shell Stage 2 — Web-shell file drops in web roots.
let lookback = {{lookback}};
let device = "{{device_name}}";
DeviceFileEvents
| where Timestamp > ago(lookback)
| where device == "__NONE__" or DeviceName has device
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (@"\inetpub\wwwroot", @"\wwwroot", @"\webapps", @"\htdocs",
    @"\www\", @"\httpdocs", "tomcat", @"\App_Data")
| where FileName endswith ".aspx" or FileName endswith ".asp" or FileName endswith ".ashx"
    or FileName endswith ".php" or FileName endswith ".jsp" or FileName endswith ".jspx"
    or FileName endswith ".war" or FileName endswith ".cfm"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Web Shell Stage 2 — Web-shell file drops in web roots.
#event_simpleName=/^(NewScriptWritten|GenericFileWritten|NewExecutableWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /(inetpub\\wwwroot|\\wwwroot|webapps|htdocs|httpdocs|\\www\\|tomcat|App_Data).*\.(aspx?|ashx|php|jspx?|war|cfm)$/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
```

### Stage 3 — Post-exploitation from web identity

- **Run:** when Stage 1 or 2 shows web-shell activity.
- **Purpose:** recon commands under IIS APPPOOL / www-data and outbound egress.

**Microsoft Sentinel (KQL)**

```kql
// Web Shell Stage 3 — Post-exploitation from the web identity.
let lookback = {{lookback}};
let device = "{{device_name}}";
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where AccountName has_any ("IIS APPPOOL", "DefaultAppPool", "NETWORK SERVICE",
        "www-data", "apache", "tomcat")
    | where FileName in~ ("whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe",
        "tasklist.exe", "quser.exe", "nltest.exe", "arp.exe", "route.exe", "reg.exe", "sc.exe")
    | project Source = "Recon", Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
),
(
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where device == "__NONE__" or DeviceName has device
    | where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe",
        "tomcat.exe", "java.exe", "php-cgi.exe")
    | where ActionType == "ConnectionSuccess" and not(ipv4_is_private(RemoteIP))
    | project Source = "Egress", Timestamp, DeviceName,
        AccountName = InitiatingProcessFileName, FileName = RemoteUrl,
        ProcessCommandLine = strcat(RemoteIP, ":", tostring(RemotePort))
)
| sort by Timestamp asc
| take 200
```

**CrowdStrike Falcon NG-SIEM (LogScale)**

```cql
// Web Shell Stage 3 — Post-exploitation from the web identity.

// --- Sub-query A: Recon commands run under a web-service account ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| UserName = /IIS APPPOOL|DefaultAppPool|NETWORK SERVICE|www-data|apache|tomcat/i
| FileName = /^(whoami|net|net1|ipconfig|systeminfo|tasklist|quser|nltest|arp|route|reg|sc)\.exe$/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Outbound connections from the host (correlate with Stage 1 timeline) ---
// ⚠ Falcon NetworkConnectIP4 does not carry the initiating process, so this cannot be
//   scoped to the web-server parent — it is host-wide egress; pivot on ComputerName +
//   the Stage 1 process timeline. RFC1918 destinations excluded.

#event_simpleName=NetworkConnectIP4
| ComputerName = /{{device_name}}/i
| RemoteAddressIP4 != /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)/
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=[
    count(as=ConnCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(ConnCount, order=desc, limit=200)
```

**Definitions**

- **Web Shell** — MITRE T1505.003 — a script planted in a web-accessible directory that gives an attacker command execution on the server under the web-service account.

---

# Part 2 — Composite single-shot Sentinel scenarios

These are monolithic KQL queries (multiple `let` sections unioned together) that produce a full-picture result in a single execution. A missing section number in the output means zero results for that section.

## DLP / Data Exfiltration (`dlp-exfiltration`)

Composite query for DLP policy violations and data exfiltration investigations. Covers DLP-related security alerts, bulk file downloads and sharing activity, external sharing and anonymous links, email forwarding, sign-in context, and OAuth app grants that may facilitate data theft.

**Parameters**

| Name | Required | Description |
| --- | --- | --- |
| `upn` | yes | Target User Principal Name (suspected exfiltrator) |
| `ip` | yes | Source IP address |
| `object_id` | yes | Azure AD object ID |

**Tables:** `OfficeActivity`, `SigninLogs`, `SecurityAlert`

```kql
// DLP / Data Exfiltration — Composite Sentinel Query
// Generated by socai generate_sentinel_query

let TargetUPN = "{{upn}}";
let IncidentIP = "{{ip}}";
let ObjectId = "{{object_id}}";
let AdditionalUPNs = dynamic([{{additional_upns}}]);
let LookbackStart = datetime({{lookback_start}});
let LookbackEnd = datetime({{lookback_end}});

let AllUPNs = array_concat(pack_array(TargetUPN), AdditionalUPNs);

// --- SECTION 1: DLP and exfiltration security alerts ---
let DLPAlerts = SecurityAlert
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where Entities has TargetUPN
    or (isnotempty(ObjectId) and Entities has ObjectId)
| where AlertName has_any ("DLP", "exfiltration", "data loss", "sensitive",
    "bulk", "mass download", "unusual volume", "sharing")
    or Tactics has_any ("Exfiltration", "Collection")
| project TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
    Entities = substring(tostring(Entities), 0, 500)
| extend Section = "1_DLPAlerts";

// --- SECTION 2 removed: raw per-file download events were duplicated by the
// 3_DownloadSummary volume rollup below. Pivot to raw FileDownloaded rows for a
// specific user/hour from that summary when the per-file list is needed. ---

// --- SECTION 3: File download summary (volume anomaly detection) ---
let DownloadSummary = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where UserId in (AllUPNs)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileCopied")
| summarize DownloadCount = count(),
    FirstDownload = min(TimeGenerated),
    LastDownload = max(TimeGenerated),
    UniqueFiles = dcount(OfficeObjectId),
    IPs = make_set(ClientIP)
    by UserId, bin(TimeGenerated, 1h)
| project TimeGenerated, UserId, DownloadCount, UniqueFiles,
    FirstDownload, LastDownload, IPs
| extend Section = "3_DownloadSummary";

// --- SECTION 4: External sharing and anonymous links ---
let ExternalSharing = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where UserId in (AllUPNs)
| where Operation in ("SharingSet", "AnonymousLinkCreated", "CompanyLinkCreated",
    "SharingInvitationCreated", "AddedToSecureLink",
    "AccessRequestCreated", "SharingPolicyChanged")
| project TimeGenerated, Operation, UserId, ClientIP,
    OfficeObjectId, OfficeWorkload,
    Parameters = tostring(Parameters), ResultStatus
| extend Section = "4_ExternalSharing";

// --- SECTION 5: Email forwarding and send activity (email-based exfil) ---
let EmailExfil = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where UserId in (AllUPNs)
| where Operation in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule",
    "UpdateInboxRules", "Send", "SendAs", "SendOnBehalf",
    "New-TransportRule")
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    Parameters = tostring(Parameters), ResultStatus, ExternalAccess
| extend Section = "5_EmailExfil";

// --- SECTION 6: OAuth apps with mail/file access (app-based exfil) ---
let OAuthGrants = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "AzureActiveDirectory"
| where UserId in (AllUPNs)
| where Operation in ("Consent to application.", "Add OAuth2PermissionGrant.",
    "Add app role assignment to user.", "Add delegated permission grant.")
| project TimeGenerated, Operation, UserId, ClientIP,
    Parameters = tostring(Parameters)
| extend Section = "6_OAuthGrants";

// --- SECTION 7: Sign-in context, summarised per source IP / geo ---
let SignIns = SigninLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where UserPrincipalName in (AllUPNs)
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count(), Successes = countif(ResultType == 0), Failures = countif(ResultType != 0),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName, 20), Risks = make_set(RiskLevelDuringSignIn, 10)
    by IPAddress, City, Country, UserPrincipalName
| project FirstSeen, LastSeen, UserPrincipalName, IPAddress, City, Country,
    SignInCount, Successes, Failures, Apps, Risks
| extend Section = "7_SignIns", TimeGenerated = FirstSeen;

// --- SECTION 8: All other security alerts for context ---
let OtherAlerts = SecurityAlert
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where Entities has TargetUPN
    or (isnotempty(ObjectId) and Entities has ObjectId)
| where not(AlertName has_any ("DLP", "exfiltration", "data loss"))
| project TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
    Entities = substring(tostring(Entities), 0, 500)
| extend Section = "8_OtherAlerts";

// --- UNION ALL ---
union isfuzzy=true
    (DLPAlerts | extend SortTime = TimeGenerated),
    (DownloadSummary | extend SortTime = TimeGenerated),
    (ExternalSharing | extend SortTime = TimeGenerated),
    (EmailExfil | extend SortTime = TimeGenerated),
    (OAuthGrants | extend SortTime = TimeGenerated),
    (SignIns | extend SortTime = TimeGenerated),
    (OtherAlerts | extend SortTime = TimeGenerated)
| sort by Section asc, SortTime asc
```

---

## Email Threat / ZAP (`email-threat-zap`)

Composite query for email threat and Zero-hour Auto Purge investigations. Covers MDO security alerts for email threats, post-delivery user activity in Exchange (message access, attachment interaction), SharePoint/OneDrive file activity, sign-in anomalies after delivery, and inbox rule changes that may indicate compromise following email interaction.

**Parameters**

| Name | Required | Description |
| --- | --- | --- |
| `upn` | yes | Recipient User Principal Name |
| `ip` | yes | Suspicious source IP address |
| `object_id` | yes | Azure AD object ID |

**Tables:** `OfficeActivity`, `SigninLogs`, `SecurityAlert`, `AlertEvidence`

```kql
// Email Threat / ZAP — Composite Sentinel Query
// Generated by socai generate_sentinel_query

let TargetUPN = "{{upn}}";
let IncidentIP = "{{ip}}";
let ObjectId = "{{object_id}}";
let AdditionalUPNs = dynamic([{{additional_upns}}]);
let LookbackStart = datetime({{lookback_start}});
let LookbackEnd = datetime({{lookback_end}});

let AllUPNs = array_concat(pack_array(TargetUPN), AdditionalUPNs);

// --- SECTION 1: Email-related security alerts (MDO detections, ZAP) ---
let EmailAlerts = SecurityAlert
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where Entities has TargetUPN
    or (isnotempty(ObjectId) and Entities has ObjectId)
| where AlertName has_any ("Email", "Phish", "Malware", "malicious",
    "ZAP", "spam", "delivery", "URL", "attachment", "click",
    "permission", "forwarding")
    or ProductName has_any ("Office 365", "Microsoft Defender for Office")
| project TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
    ProductName,
    Entities = substring(tostring(Entities), 0, 500)
| extend Section = "1_EmailAlerts";

// --- SECTION 2: Alert evidence (IOCs from the email alerts) ---
let Evidence = AlertEvidence
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where EntityType in ("MailMessage", "Url", "File", "Mailbox", "MailCluster")
    or AccountName has TargetUPN
| project TimeGenerated, Title, EntityType, RemoteIP, AccountName,
    AccountDomain, FileName, FileHash = SHA256,
    EvidenceRole, AdditionalFields = substring(tostring(AdditionalFields), 0, 500)
| extend Section = "2_AlertEvidence";

// --- SECTION 3: Post-delivery Exchange activity (message interaction) ---
let PostDeliveryExchange = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where UserId in (AllUPNs)
| where Operation in ("MailItemsAccessed", "FolderBind", "MessageBind",
    "New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
    "Set-Mailbox", "Add-MailboxPermission", "Send", "SendAs",
    "MoveToDeletedItems", "SoftDelete", "HardDelete")
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    Parameters = tostring(Parameters), ResultStatus, ExternalAccess
| extend Section = "3_PostDeliveryExchange";

// --- SECTION 4: File downloads and SharePoint activity (payload interaction) ---
let FileActivity = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where UserId in (AllUPNs)
| where Operation in ("FileDownloaded", "FileUploaded", "FileAccessed",
    "FilePreviewed", "FileModified", "AnonymousLinkCreated",
    "SharingSet", "SharingInvitationCreated")
| project TimeGenerated, Operation, UserId, ClientIP,
    OfficeObjectId, OfficeWorkload, ResultStatus
| extend Section = "4_FileActivity";

// --- SECTION 5: Post-delivery sign-ins, summarised per source IP / geo ---
let SignIns = SigninLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where UserPrincipalName in (AllUPNs)
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count(), Successes = countif(ResultType == 0), Failures = countif(ResultType != 0),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName, 20), Risks = make_set(RiskLevelDuringSignIn, 10),
    CA = make_set(ConditionalAccessStatus, 5)
    by IPAddress, City, Country, UserPrincipalName
| project FirstSeen, LastSeen, UserPrincipalName, IPAddress, City, Country,
    SignInCount, Successes, Failures, Apps, Risks, CA
| extend Section = "5_SignIns", TimeGenerated = FirstSeen;

// --- SECTION 6: Suspicious IP sign-ins across tenant (same attacker, other victims) ---
let IPSpread = SigninLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where isnotempty(IncidentIP) and IPAddress == IncidentIP
| where UserPrincipalName !in (AllUPNs)
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName)
    by UserPrincipalName, City, Country
| project FirstSeen, UserPrincipalName, City, Country,
    SignInCount, LastSeen, Apps
| extend Section = "6_IPSpread", TimeGenerated = FirstSeen;

// --- SECTION 7: All security alerts for the target (broader context) ---
let AllAlerts = SecurityAlert
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where Entities has TargetUPN
    or (isnotempty(ObjectId) and Entities has ObjectId)
| where not(AlertName has_any ("Email", "Phish", "Malware", "ZAP"))
| project TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
    Entities = substring(tostring(Entities), 0, 500)
| extend Section = "7_OtherAlerts";

// --- UNION ALL ---
union isfuzzy=true
    (EmailAlerts | extend SortTime = TimeGenerated),
    (Evidence | extend SortTime = TimeGenerated),
    (PostDeliveryExchange | extend SortTime = TimeGenerated),
    (FileActivity | extend SortTime = TimeGenerated),
    (SignIns | extend SortTime = TimeGenerated),
    (IPSpread | extend SortTime = TimeGenerated),
    (AllAlerts | extend SortTime = TimeGenerated)
| sort by Section asc, SortTime asc
```

---

## Inbox Rule / BEC Investigation (`inbox-rule-bec`)

Composite query for inbox rule creation and business email compromise investigations. Covers inbox rule changes, mail forwarding configuration, mailbox permission grants, sign-in context, email send activity from the compromised account, and correlated security alerts.

**Parameters**

| Name | Required | Description |
| --- | --- | --- |
| `upn` | yes | Target User Principal Name (suspected compromised account) |
| `ip` | yes | Suspicious source IP address |
| `object_id` | yes | Azure AD object ID |

**Tables:** `OfficeActivity`, `SigninLogs`, `SecurityAlert`

```kql
// Inbox Rule / BEC — Composite Sentinel Query
// Generated by socai generate_sentinel_query

let TargetUPN = "{{upn}}";
let IncidentIP = "{{ip}}";
let ObjectId = "{{object_id}}";
let AdditionalUPNs = dynamic([{{additional_upns}}]);
let LookbackStart = datetime({{lookback_start}});
let LookbackEnd = datetime({{lookback_end}});

let AllUPNs = array_concat(pack_array(TargetUPN), AdditionalUPNs);

// --- SECTION 1: Inbox rule creation and modification ---
let InboxRules = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where UserId in (AllUPNs) or OfficeObjectId has TargetUPN
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "Remove-InboxRule", "Disable-InboxRule", "UpdateInboxRules")
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    Parameters = tostring(Parameters), ResultStatus, ExternalAccess
| extend Section = "1_InboxRules";

// --- SECTION 2: Mail forwarding and redirect configuration ---
let Forwarding = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where UserId in (AllUPNs) or OfficeObjectId has TargetUPN
| where Operation == "Set-Mailbox"
| where tostring(Parameters) has_any ("ForwardingSmtpAddress", "ForwardingAddress",
    "DeliverToMailboxAndForward", "RedirectTo")
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    Parameters = tostring(Parameters), ResultStatus
| extend Section = "2_Forwarding";

// --- SECTION 3: Mailbox permission changes (persistence) ---
let PermissionChanges = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where Operation has_any ("MailboxPermission", "RecipientPermission", "FolderPermission")
| where UserId in (AllUPNs) or OfficeObjectId has TargetUPN
| extend GrantedTo = tostring(parse_json(tostring(Parameters))[1].Value),
    AccessRights = tostring(parse_json(tostring(Parameters))[2].Value)
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    GrantedTo, AccessRights, ResultStatus, ExternalAccess
| extend Section = "3_PermissionChanges";

// --- SECTION 4: Email send activity (BEC — attacker sending as victim) ---
let SendActivity = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where UserId in (AllUPNs)
| where Operation in ("Send", "SendAs", "SendOnBehalf")
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    ResultStatus, ExternalAccess
| extend Section = "4_SendActivity";

// --- SECTION 5 removed: raw sign-in rows were duplicated by the 6_SignInBaseline
// summary below (same data, one row per IP/location). Pivot to raw SigninLogs for
// a specific IP from that summary when per-event detail is needed. ---

// --- SECTION 6: Sign-in summary by IP (baseline vs anomalous) ---
let SignInBaseline = SigninLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where UserPrincipalName in (AllUPNs)
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName)
    by IPAddress, City, Country, UserPrincipalName
| project FirstSeen, UserPrincipalName, IPAddress, City, Country,
    SignInCount, LastSeen, Apps
| extend Section = "6_SignInBaseline", TimeGenerated = FirstSeen;

// --- SECTION 7: OAuth / consent grants (illicit consent as persistence) ---
let OAuthGrants = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "AzureActiveDirectory"
| where UserId in (AllUPNs)
| where Operation in ("Consent to application.", "Add OAuth2PermissionGrant.",
    "Add app role assignment to user.", "Add delegated permission grant.")
| project TimeGenerated, Operation, UserId, ClientIP,
    Parameters = tostring(Parameters)
| extend Section = "7_OAuthGrants";

// --- SECTION 8: Correlated security alerts ---
let Alerts = SecurityAlert
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where Entities has TargetUPN
    or (isnotempty(IncidentIP) and Entities has IncidentIP)
    or (isnotempty(ObjectId) and Entities has ObjectId)
| project TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
    Entities = substring(tostring(Entities), 0, 500)
| extend Section = "8_Alerts";

// --- UNION ALL ---
union isfuzzy=true
    (InboxRules | extend SortTime = TimeGenerated),
    (Forwarding | extend SortTime = TimeGenerated),
    (PermissionChanges | extend SortTime = TimeGenerated),
    (SendActivity | extend SortTime = TimeGenerated),
    (SignInBaseline | extend SortTime = TimeGenerated),
    (OAuthGrants | extend SortTime = TimeGenerated),
    (Alerts | extend SortTime = TimeGenerated)
| sort by Section asc, SortTime asc
```

---

## Mailbox Permission Change (`mailbox-permission-change`)

Composite query for mailbox permission change investigations. Covers permission grants (FullAccess, SendAs, SendOnBehalf), inbox rule creation, email forwarding, delegate access usage, IP activity footprint, tenant-wide lateral permission changes, sign-in context for all involved accounts, and correlated security alerts.

**Parameters**

| Name | Required | Description |
| --- | --- | --- |
| `upn` | yes | Primary target UPN (the account that made or received the permission change) |
| `ip` | yes | Suspicious source IP address |
| `additional_upns` | yes | Comma-separated additional UPNs (e.g. grantee accounts) |
| `object_id` | yes | Azure AD object ID of the target account |
| `mailbox_id` | yes | Mailbox GUID (OfficeObjectId) if known |

**Tables:** `OfficeActivity`, `SigninLogs`, `SecurityAlert`, `AlertEvidence`

```kql
// Mailbox Permission Change — Composite Sentinel Query
// Generated by socai generate_sentinel_query

let TargetUPN = "{{upn}}";
let IncidentIP = "{{ip}}";
let ObjectId = "{{object_id}}";
let MailboxId = "{{mailbox_id}}";
let AdditionalUPNs = dynamic([{{additional_upns}}]);
let LookbackStart = datetime({{lookback_start}});
let LookbackEnd = datetime({{lookback_end}});

// All UPNs to monitor (target + any additional)
let AllUPNs = array_concat(pack_array(TargetUPN), AdditionalUPNs);

// --- SECTION 1: Permission changes on/by the target account ---
let PermissionChanges = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where Operation has_any ("MailboxPermission", "RecipientPermission", "FolderPermission")
| where UserId =~ TargetUPN
    or OfficeObjectId == MailboxId
    or (isnotempty(ObjectId) and tostring(parse_json(tostring(Parameters))[1].Value) == ObjectId)
| extend GrantedTo = tostring(parse_json(tostring(Parameters))[1].Value),
    AccessRights = tostring(parse_json(tostring(Parameters))[2].Value),
    Inheritance = tostring(parse_json(tostring(Parameters))[3].Value)
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    GrantedTo, AccessRights, Inheritance, ResultStatus, ExternalAccess
| extend Section = "1_PermissionChanges";

// --- SECTION 2: Inbox rules, forwarding, transport rules ---
let MailboxConfig = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where UserId in (AllUPNs) or OfficeObjectId == MailboxId
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "Remove-InboxRule", "UpdateInboxRules", "Set-Mailbox",
    "New-TransportRule", "Set-TransportRule")
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    Parameters = tostring(Parameters), ResultStatus, ExternalAccess
| extend Section = "2_MailboxConfig";

// --- SECTION 3: Email forwarding specifically ---
let Forwarding = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where Operation == "Set-Mailbox"
| where UserId in (AllUPNs) or OfficeObjectId == MailboxId
| where tostring(Parameters) has_any ("ForwardingSmtpAddress", "ForwardingAddress", "DeliverToMailboxAndForward")
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    Parameters = tostring(Parameters), ResultStatus
| extend Section = "3_Forwarding";

// --- SECTION 4: Delegate access usage (did anyone use the granted permissions?) ---
let DelegateAccess = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where UserId in (AllUPNs)
| where OfficeObjectId == MailboxId
    or Operation in ("MailItemsAccessed", "FolderBind", "MessageBind",
        "SendAs", "SendOnBehalf", "MoveToDeletedItems", "SoftDelete",
        "HardDelete", "Copy", "Update")
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    ResultStatus, ExternalAccess
| extend Section = "4_DelegateAccess";

// --- SECTION 5: All activity from the incident IP ---
// Summarised per (user, operation) — a raw projection of every OfficeActivity
// event from the IP (no operation filter) is unbounded. Pivot to raw rows for a
// specific user/operation if the footprint warrants it.
let IPActivity = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where isnotempty(IncidentIP) and ClientIP has IncidentIP
| summarize EventCount = count(),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Workloads = make_set(OfficeWorkload, 10)
    by UserId, Operation
| project FirstSeen, LastSeen, UserId, Operation, EventCount, Workloads
| extend Section = "5_IPActivity", TimeGenerated = FirstSeen;

// --- SECTION 6: Tenant-wide permission changes (catch lateral moves) ---
// Summarised per (actor, source IP) — a raw per-event projection of every
// tenant permission change can be thousands of rows. Pivot to raw rows for a
// suspect actor if their change footprint looks anomalous.
let TenantWidePerms = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where Operation has_any ("MailboxPermission", "RecipientPermission", "FolderPermission")
| where UserId !in (AllUPNs) and OfficeObjectId != MailboxId
| summarize ChangeCount = count(),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Operations = make_set(Operation, 10), Mailboxes = make_set(OfficeObjectId, 20)
    by UserId, ClientIP
| project FirstSeen, LastSeen, UserId, ClientIP, ChangeCount, Operations, Mailboxes
| extend Section = "6_TenantWidePerms", TimeGenerated = FirstSeen;

// --- SECTION 7: Sign-ins for all involved accounts ---
let SignIns = SigninLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where UserPrincipalName in (AllUPNs)
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    State = tostring(LocationDetails.state),
    MfaMethod = tostring(MfaDetail.authMethod),
    MfaPhone = tostring(MfaDetail.authDetail),
    ErrorCode = tostring(Status.errorCode)
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country, State,
    AppDisplayName, ResourceDisplayName, RiskLevelDuringSignIn, RiskState,
    AuthenticationRequirement, ConditionalAccessStatus, ErrorCode,
    MfaMethod, MfaPhone
| extend Section = "7_SignIns";

// --- SECTION 8: OAuth / consent grants ---
let OAuthGrants = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "AzureActiveDirectory"
| where UserId in (AllUPNs)
| where Operation in ("Consent to application.", "Add OAuth2PermissionGrant.",
    "Add app role assignment to user.", "Add delegated permission grant.")
| project TimeGenerated, Operation, UserId, ClientIP,
    Parameters = tostring(Parameters)
| extend Section = "8_OAuthGrants";

// --- SECTION 9: Correlated security alerts ---
let Alerts = SecurityAlert
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where Entities contains TargetUPN
    or (isnotempty(ObjectId) and Entities contains ObjectId)
| project TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
    Entities = substring(tostring(Entities), 0, 500)
| extend Section = "9_Alerts";

// --- UNION ALL ---
union isfuzzy=true
    (PermissionChanges | extend SortTime = TimeGenerated),
    (MailboxConfig | extend SortTime = TimeGenerated),
    (Forwarding | extend SortTime = TimeGenerated),
    (DelegateAccess | extend SortTime = TimeGenerated),
    (IPActivity | extend SortTime = TimeGenerated),
    (TenantWidePerms | extend SortTime = TimeGenerated),
    (SignIns | extend SortTime = TimeGenerated),
    (OAuthGrants | extend SortTime = TimeGenerated),
    (Alerts | extend SortTime = TimeGenerated)
| sort by Section asc, SortTime asc
```

---

## OAuth Consent Grant (`oauth-consent-grant`)

Composite query for illicit OAuth consent grant investigations. Covers consent events and app role assignments, service principal sign-in activity post-consent, data access by the consented app, user sign-in context around the consent event, and correlated security alerts.

**Parameters**

| Name | Required | Description |
| --- | --- | --- |
| `upn` | yes | User Principal Name who granted consent |
| `ip` | yes | IP address at time of consent |
| `object_id` | yes | Azure AD object ID of the user |

**Tables:** `OfficeActivity`, `SigninLogs`, `AADServicePrincipalSignInLogs`, `SecurityAlert`, `MicrosoftGraphActivityLogs`

```kql
// OAuth Consent Grant — Composite Sentinel Query
// Generated by socai generate_sentinel_query

let TargetUPN = "{{upn}}";
let IncidentIP = "{{ip}}";
let ObjectId = "{{object_id}}";
let AdditionalUPNs = dynamic([{{additional_upns}}]);
let LookbackStart = datetime({{lookback_start}});
let LookbackEnd = datetime({{lookback_end}});

let AllUPNs = array_concat(pack_array(TargetUPN), AdditionalUPNs);

// --- SECTION 1: Consent and app role assignment events ---
let ConsentEvents = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "AzureActiveDirectory"
| where UserId in (AllUPNs)
| where Operation in ("Consent to application.", "Add OAuth2PermissionGrant.",
    "Add app role assignment to user.", "Add app role assignment to service principal.",
    "Add delegated permission grant.", "Add service principal.",
    "Add service principal credentials.", "Update application.",
    "Update service principal.")
| project TimeGenerated, Operation, UserId, ClientIP,
    Parameters = tostring(Parameters), ResultStatus
| extend Section = "1_ConsentEvents";

// --- SECTION 2: All AAD admin activity by the user (context) ---
let AADActivity = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "AzureActiveDirectory"
| where UserId in (AllUPNs)
| where Operation !in ("UserLoggedIn", "UserLoginFailed")
| project TimeGenerated, Operation, UserId, ClientIP,
    Parameters = tostring(Parameters), ResultStatus
| extend Section = "2_AADActivity";

// --- SECTION 3: Service principal sign-ins (app activity post-consent) ---
// Summarised per service principal — a raw per-event projection here returns the
// ENTIRE tenant's SP sign-in log (no app filter). Pivot to raw events for the
// suspect AppId once Section 1 identifies the consented app.
let SPSignIns = AADServicePrincipalSignInLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| summarize SignInCount = count(), Failures = countif(ResultType != 0),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Resources = make_set(ResourceDisplayName, 20), IPs = make_set(IPAddress, 20)
    by AppId, ServicePrincipalName, ServicePrincipalId
| project FirstSeen, LastSeen, AppId, ServicePrincipalName, ServicePrincipalId,
    SignInCount, Failures, Resources, IPs
| extend Section = "3_ServicePrincipalSignIns", TimeGenerated = FirstSeen;

// --- SECTION 4: Microsoft Graph API activity (what the app accessed) ---
// Summarised per calling app — a raw per-event projection here returns ALL
// tenant Graph API traffic (no AppId filter). Pivot to raw RequestUri rows for
// the suspect AppId once Section 1 identifies the consented app.
let GraphActivity = MicrosoftGraphActivityLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| summarize Calls = count(),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Methods = make_set(RequestMethod, 10), Statuses = make_set(ResponseStatusCode, 15),
    IPs = make_set(IPAddress, 20), SampleUris = make_set(substring(RequestUri, 0, 80), 25)
    by AppId
| project FirstSeen, LastSeen, AppId, Calls, Methods, Statuses, IPs, SampleUris
| extend Section = "4_GraphActivity", TimeGenerated = FirstSeen;

// --- SECTION 5: Post-consent data access (Exchange, SharePoint) ---
let PostConsentDataAccess = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where UserId in (AllUPNs)
| where Operation in ("MailItemsAccessed", "FileDownloaded", "FileAccessed",
    "Send", "SendAs", "SharingSet", "AnonymousLinkCreated")
| project TimeGenerated, Operation, UserId, ClientIP,
    OfficeObjectId, OfficeWorkload, ResultStatus, ExternalAccess
| extend Section = "5_PostConsentDataAccess";

// --- SECTION 6: User sign-in context around consent ---
let SignIns = SigninLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where UserPrincipalName in (AllUPNs)
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    State = tostring(LocationDetails.state),
    MfaMethod = tostring(MfaDetail.authMethod),
    MfaPhone = tostring(MfaDetail.authDetail),
    ErrorCode = tostring(Status.errorCode),
    FailureReason = tostring(Status.failureReason)
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country, State,
    AppDisplayName, ResourceDisplayName, RiskLevelDuringSignIn, RiskState,
    AuthenticationRequirement, ConditionalAccessStatus,
    ErrorCode, FailureReason, MfaMethod, MfaPhone
| extend Section = "6_SignIns";

// --- SECTION 7: Suspicious IP activity across tenant ---
let IPActivity = SigninLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where isnotempty(IncidentIP) and IPAddress == IncidentIP
| where UserPrincipalName !in (AllUPNs)
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName)
    by UserPrincipalName, City, Country
| project FirstSeen, UserPrincipalName, City, Country,
    SignInCount, LastSeen, Apps
| extend Section = "7_IPActivity", TimeGenerated = FirstSeen;

// --- SECTION 8: Correlated security alerts ---
let Alerts = SecurityAlert
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where Entities has TargetUPN
    or (isnotempty(IncidentIP) and Entities has IncidentIP)
    or (isnotempty(ObjectId) and Entities has ObjectId)
| project TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
    Entities = substring(tostring(Entities), 0, 500)
| extend Section = "8_Alerts";

// --- UNION ALL ---
union isfuzzy=true
    (ConsentEvents | extend SortTime = TimeGenerated),
    (AADActivity | extend SortTime = TimeGenerated),
    (SPSignIns | extend SortTime = TimeGenerated),
    (GraphActivity | extend SortTime = TimeGenerated),
    (PostConsentDataAccess | extend SortTime = TimeGenerated),
    (SignIns | extend SortTime = TimeGenerated),
    (IPActivity | extend SortTime = TimeGenerated),
    (Alerts | extend SortTime = TimeGenerated)
| sort by Section asc, SortTime asc
```

---

## Suspicious Sign-In (`suspicious-signin`)

Composite query for suspicious sign-in investigations. Covers interactive and non-interactive sign-ins with risk levels, MFA detail, conditional access outcomes, location analysis, post-authentication activity in Exchange and SharePoint, and correlated security alerts.

**Parameters**

| Name | Required | Description |
| --- | --- | --- |
| `upn` | yes | Target User Principal Name |
| `ip` | yes | Suspicious source IP address |
| `object_id` | yes | Azure AD object ID |

**Tables:** `SigninLogs`, `OfficeActivity`, `SecurityAlert`, `AlertEvidence`

```kql
// Suspicious Sign-In — Composite Sentinel Query
// Generated by socai generate_sentinel_query

let TargetUPN = "{{upn}}";
let IncidentIP = "{{ip}}";
let ObjectId = "{{object_id}}";
let AdditionalUPNs = dynamic([{{additional_upns}}]);
let LookbackStart = datetime({{lookback_start}});
let LookbackEnd = datetime({{lookback_end}});

let AllUPNs = array_concat(pack_array(TargetUPN), AdditionalUPNs);

// --- SECTION 1 removed: raw interactive sign-ins were fully duplicated by the
// 2_SignInPatterns summary below. The summary collapses the same data to one row
// per IP/location; pivot to raw SigninLogs for a specific IP only when per-event
// detail is needed. ---

// --- SECTION 2: Sign-in summary by IP and location (pattern detection) ---
let SignInPatterns = SigninLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where UserPrincipalName in (AllUPNs)
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName),
    RiskLevels = make_set(RiskLevelDuringSignIn),
    MfaMethods = make_set(tostring(MfaDetail.authMethod))
    by IPAddress, City, Country, UserPrincipalName
| project FirstSeen, UserPrincipalName, IPAddress, City, Country,
    SignInCount, LastSeen, Apps, RiskLevels, MfaMethods
| extend Section = "2_SignInPatterns", TimeGenerated = FirstSeen;

// --- SECTION 3: Failed sign-ins summarised per IP / error (spray indicators) ---
let FailedSignIns = SigninLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where UserPrincipalName in (AllUPNs)
| where ResultType != "0" and ResultType != 0
| extend ErrorCode = tostring(Status.errorCode),
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize Failures = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Users = make_set(UserPrincipalName, 30), Apps = make_set(AppDisplayName, 20),
    ErrorCodes = make_set(ErrorCode, 15)
    by IPAddress, City, Country
| project FirstSeen, LastSeen, IPAddress, City, Country, Failures, Users, Apps, ErrorCodes
| extend Section = "3_FailedSignIns", TimeGenerated = FirstSeen;

// --- SECTION 4: Activity from the suspicious IP across all users ---
let IPFootprint = SigninLogs
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where isnotempty(IncidentIP) and IPAddress == IncidentIP
| where UserPrincipalName !in (AllUPNs)
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName)
    by UserPrincipalName, City, Country
| project FirstSeen, UserPrincipalName, City, Country,
    SignInCount, LastSeen, Apps
| extend Section = "4_IPFootprint", TimeGenerated = FirstSeen,
    IPAddress = IncidentIP;

// --- SECTION 5: Post-authentication Exchange activity ---
let PostAuthExchange = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "Exchange"
| where UserId in (AllUPNs)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
    "Set-Mailbox", "Add-MailboxPermission", "Add-RecipientPermission",
    "MailItemsAccessed", "SendAs", "SendOnBehalf",
    "MoveToDeletedItems", "SoftDelete", "HardDelete")
| project TimeGenerated, Operation, UserId, ClientIP, OfficeObjectId,
    Parameters = tostring(Parameters), ResultStatus, ExternalAccess
| extend Section = "5_PostAuthExchange";

// --- SECTION 6: Post-authentication SharePoint/OneDrive activity ---
let PostAuthSharePoint = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where UserId in (AllUPNs)
| where Operation in ("FileDownloaded", "FileUploaded", "FileAccessed",
    "FileDeleted", "FileMoved", "FileRenamed",
    "SharingSet", "AnonymousLinkCreated", "CompanyLinkCreated",
    "SharingInvitationCreated", "AccessRequestCreated")
| project TimeGenerated, Operation, UserId, ClientIP,
    OfficeObjectId, OfficeWorkload, ResultStatus
| extend Section = "6_PostAuthSharePoint";

// --- SECTION 7: AAD directory changes (role/group modifications) ---
let DirectoryChanges = OfficeActivity
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where OfficeWorkload == "AzureActiveDirectory"
| where UserId in (AllUPNs)
| where Operation in ("Add member to role.", "Add member to group.",
    "Add user.", "Update user.", "Reset user password.",
    "Consent to application.", "Add OAuth2PermissionGrant.",
    "Add app role assignment to user.", "Add delegated permission grant.",
    "Add service principal credentials.")
| project TimeGenerated, Operation, UserId, ClientIP,
    Parameters = tostring(Parameters), ResultStatus
| extend Section = "7_DirectoryChanges";

// --- SECTION 8: Correlated security alerts ---
let Alerts = SecurityAlert
| where TimeGenerated between (LookbackStart .. LookbackEnd)
| where Entities has TargetUPN
    or (isnotempty(IncidentIP) and Entities has IncidentIP)
    or (isnotempty(ObjectId) and Entities has ObjectId)
| project TimeGenerated, AlertName, AlertSeverity, Tactics, Status,
    Entities = substring(tostring(Entities), 0, 500)
| extend Section = "8_Alerts";

// --- UNION ALL ---
union isfuzzy=true
    (SignInPatterns | extend SortTime = TimeGenerated),
    (FailedSignIns | extend SortTime = TimeGenerated),
    (IPFootprint | extend SortTime = TimeGenerated),
    (PostAuthExchange | extend SortTime = TimeGenerated),
    (PostAuthSharePoint | extend SortTime = TimeGenerated),
    (DirectoryChanges | extend SortTime = TimeGenerated),
    (Alerts | extend SortTime = TimeGenerated)
| sort by Section asc, SortTime asc
```

---

_Exported 18 multi-stage playbooks and 6 composite scenarios from `config/`._
