# NGSiEM (LogScale/Humio CQL) Authoring Rules

> **Scope:** Syntax conventions, proven patterns, and anti-patterns for writing NGSIEM/CQL detection rules.
> Function signatures and parameters are in `config/ngsiem/cql_grammar.json` (MCP: `socai://cql-grammar`).
> Table names and field lists are in `config/ngsiem/ngsiem_columns.yaml` (MCP: `socai://ngsiem-columns`).

---

## 1. Syntax Fundamentals

### Pipe-per-line
Every line except the first must start with a pipe (`|`).
```cql
// CORRECT
observer.vendor="fortinet"
| observer.product="fortigate"
| network.direction="inbound"

// WRONG
observer.vendor="fortinet"
observer.product="fortigate"
network.direction="inbound"
```

### Implicit AND
Consecutive filter expressions are implicitly ANDed — do not write `AND` between lines.
```cql
// CORRECT
observer.vendor="fortinet"
| observer.product="fortigate"

// WRONG
observer.vendor="fortinet" AND observer.product="fortigate"
```

### Tag-based Source Filtering
Tags (`#field=value`) are repo/index-level filters applied before the pipeline. They must appear on the first line.

**Preferred log source tags** (in order of preference):
1. `#Vendor` + `#event.module` — portable across clients and repos
2. `#event.module` + `#event.kind` — when vendor tag is unavailable
3. `#repo` — **avoid** unless absolutely necessary; `#repo` values are GUIDs or client-specific names that differ per deployment and cannot be mapped across environments

```cql
// CORRECT — vendor + module scoping (portable)
#Vendor="Microsoft" #event.module=windows EventCode=4769

// CORRECT — module + kind when vendor tag unavailable
#event.module=windows #event.kind=event EventCode=4769

// CORRECT — vendor-specific component filtering
#Vendor="fortinet" #event.module=fortigate

// CORRECT — exclude non-relevant repos (wildcard)
#Vendor="Microsoft" #event.module=windows #repo!=xdr*

// CORRECT — AWS CloudTrail
#Vendor="AWS" #event.module=cloudtrail

// AVOID — #repo is client-specific and non-portable
#repo="winlog" EventCode=4769
```

**Key rule:** `#tag=value` is not a pipe stage — it cannot appear mid-pipeline after a `|`.
`| winlog` is NOT valid syntax. Declare the source via tags on line 1, not as a pipe step.

**Key rule:** Never use `#repo` as the primary log source filter. `#repo` values (e.g. GUIDs, custom names) are specific to each NGSIEM deployment and break when rules are deployed to different clients. Use `#Vendor` and `#event.module` to identify the data source portably.

### Field Values Are Lowercase
String literal values are lowercase.
```cql
// CORRECT
observer.vendor="fortinet"

// WRONG
observer.vendor="Fortinet"
```

### Multi-value Matching: `in()`
Use `in()` — not SQL-style `IN (...)`.
```cql
// CORRECT
| in(field="event.action", values=["firewall permit", "firewall deny"])

// WRONG
event.action IN ("Firewall Permit", "Firewall Deny")
```

### Tag Field Multi-Value Matching
Tag fields (`#field`) have different syntax from regular fields. `in()` and `IN` do NOT
work on tag fields. Use regex alternation:
```cql
// CORRECT — regex alternation for multi-value tag match
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|DnsRequest)$/

// CORRECT — single tag value
#event_simpleName=ProcessRollup2

// WRONG — IN() is not valid CQL syntax for tag fields
#event_simpleName IN (ProcessRollup2, DnsRequest)

// WRONG — in() is a pipeline function, not a filter on tags
in(#event_simpleName, values=["ProcessRollup2", "DnsRequest"])
```

Note: `in()` works on **regular fields** as a pipeline step (`| in(field, values=[...])`).
It does NOT work on tag fields in any position.

### Filter Expressions — No `where`
Write filter conditions directly; do not wrap in `where`.
```cql
// CORRECT
| unique_dst_ports >= 15

// WRONG
| where unique_dst_ports >= 15
```

### Negation
Use the `not` keyword before a function call, or `!=` / `!in()` for field comparisons.
```cql
| not match(field=source.ip, file="allowlist.csv", strict=false)
| !endsWith(ServiceName, suffix="$")
| UserName != /\$$/
```

### Regex Syntax
Regex literals are wrapped in `/slashes/`. Use `i` flag for case-insensitive.
```cql
// Case-insensitive match
| TicketEncryptionType = /^0x1[78]$/i

// Exclude computer accounts (end with $)
| UserName != /\$$/

// Case-insensitive field comparison operator
| field =~ "pattern"
```

### Lookup / Reference Lists
Use `match()` to check a field against a named lookup file (CSV).
```cql
| not match(field=source.ip, file="Customer Domain Controllers - IP", strict=false)
| not match(field=source.ip, file="Customer VA Scanners - AlphaNumeric", strict=false)
```

---

## 2. Pipeline Structure

Line 1 is always a bare filter expression (with optional tags). Every subsequent step starts with `|`.

```cql
#Vendor="Microsoft" #event.module=windows EventCode=4769
| in(TicketEncryptionType, values=["0x17", "0x18"])
| not match(field=UserName, file="suppressed-accounts.csv", strict=false)
| groupBy([UserName, HostName, SourceIP], function=[count(as=RequestCount), min(timestamp, as=FirstSeen), max(timestamp, as=LastSeen)])
| RequestCount >= 5
| table([FirstSeen, LastSeen, HostName, UserName, SourceIP, RequestCount])
```

---

## 3. Field Name Conventions

Use ECS-mapped fields. Fall back to `Vendor.*` only when the ECS field is unpopulated.

| Concept | Correct Field | Do Not Use |
|---|---|---|
| Vendor name | `observer.vendor` | `metadata.vendor`, `Vendor` |
| Product name | `observer.product` | `metadata.product` |
| Event action/name | `event.action` | `event.name` |
| Source IP | `source.ip` | `Vendor.srcip`, `NetworkSourceIP` (raw) |
| Destination IP | `destination.ip` | `Vendor.dstip` |
| Destination port | `destination.port` | `Vendor.dstport` |
| Traffic direction | `network.direction` | `Vendor.direction` |
| Username | `user.name` | `username` (no namespace) |

Full field lists per connector are in `config/ngsiem/ngsiem_columns.yaml` (MCP: `socai://ngsiem-columns`).

---

## 4. Log Source Filter Mapping

When writing or migrating rules, use `#Vendor` and `#event.module` to scope queries to the correct data source. The table below maps common vendors/products to their correct tag values:

| Vendor | Product/Component | Tags |
|---|---|---|
| Microsoft | Windows Event Logs | `#Vendor="Microsoft" #event.module=windows` |
| Microsoft | Entra ID (Azure AD) | `#Vendor="Microsoft" #event.module=entraid` |
| Microsoft | Microsoft 365 | `#Vendor="Microsoft" #event.module=m365` |
| Microsoft | Defender | `#Vendor="Microsoft" #event.module=defender` |
| Fortinet | FortiGate | `#Vendor="fortinet" #event.module=fortigate` |
| Fortinet | FortiWeb | `#Vendor="fortinet" #event.module=fortiweb` |
| Cisco | ISE | `#Vendor="cisco" #event.module=ise` |
| Cisco | Duo | `#Vendor="cisco" #event.module=duo` |
| Cisco | ASA | `#Vendor="cisco" #event.module=asa` |
| Check Point | Firewall | `#Vendor="checkpoint" #event.module=checkpoint` |
| CrowdStrike | Falcon (XDR) | `#Vendor="CrowdStrike" #event.module=falcon` |
| Darktrace | Darktrace | `#Vendor="darktrace" #event.module=darktrace` |
| Delinea | Secret Server | `#Vendor="delinea" #event.module=delinea` |
| Netskope | Cloud Security | `#Vendor="netskope" #event.module=netskope` |
| AWS | CloudTrail | `#Vendor="AWS" #event.module=cloudtrail` |
| Linux | Syslog / auditd | `#Vendor="linux" #event.module=linux` |

**Migration rule:** When converting from Sentinel KQL or other platforms, map the source table/workspace to the appropriate `#Vendor` + `#event.module` tags from this table. Never map to `#repo`.

For the full list of fields available per connector, see `config/ngsiem/ngsiem_columns.yaml` (MCP: `socai://ngsiem-columns`).

---

## 5. Proven Query Patterns

### Threshold Detection with GroupBy
The standard pattern for counting events per group over the lookback window:

```cql
#Vendor="Microsoft" #event.module=windows EventCode=4769
| in(TicketEncryptionType, values=["0x17", "0x18"])
| !endsWith(ServiceName, suffix="$")
| ServiceName != "krbtgt"
| UserName != /\$$/
| groupBy(
    [UserName, HostName, TargetUserName, TicketEncryptionType, SourceIP],
    function=[count(as=RequestCount), min(timestamp, as=FirstSeen), max(timestamp, as=LastSeen)]
  )
| RequestCount >= 5
```

### Time Window Tracking (FirstSeen / LastSeen)
After `groupBy()`, capture the earliest and latest event time using `min`/`max` on timestamp:
```cql
| groupBy([UserName, SourceIP], function=[
    count(as=EventCount),
    min(timestamp, as=FirstSeen),
    max(timestamp, as=LastSeen)
  ])
```
Reference `FirstSeen` and `LastSeen` in subsequent steps and `table()`. Do **not** reference `timestamp` after `groupBy()` — it is out of scope.

### Conditional Severity Scoring
```cql
| ThreatScore := if(RequestCount > 10, "HIGH", if(RequestCount > 5, "MEDIUM", "LOW"))
```

### Detection Summary String
Use `format()` to build a human-readable summary field. Use `%s` for all placeholders — do **not** use `%d` (integer format specifiers have inconsistent platform support):
```cql
| format(
    format="%s requested RC4 Kerberos tickets (%s). Source: %s, Target: %s, Count: %s, Risk: %s",
    field=[UserName, TicketEncryptionType, SourceIP, TargetUserName, RequestCount, ThreatScore],
    as=DetectionSummary
  )
```

### Bucket + GroupBy for Time-Windowed Port Counting
For scan/recon detection where you need to count distinct values within a time window:
```cql
| bucket(field=[source.ip, destination.ip], span="2m", function=[collect([destination.port])])
| groupBy([source.ip, destination.ip], function=count(destination.port, as=unique_dst_ports))
| unique_dst_ports >= 15
```

### Computer Account Exclusion
Exclude machine accounts (AD convention: names ending with `$`):
```cql
| UserName != /\$$/
| !endsWith(ServiceName, suffix="$")
```

---

## 6. Post-Aggregation Field Scope

After `groupBy()`, only the grouped fields and named aggregate outputs remain in scope. All original event fields are dropped.

```cql
| groupBy([UserName, HostName], function=[count(as=Total), min(timestamp, as=FirstSeen)])

// CORRECT — fields available after groupBy
| table([UserName, HostName, Total, FirstSeen])

// WRONG — original event fields are no longer available
| table([UserName, HostName, Total, timestamp, EventCode])
```

---

## 7. DaC Template Fields

All rules use the YAML template at `templates/ngsiem/ngsiemDAC_template.yaml`. Fixed values:

| Field | Value | Notes |
|---|---|---|
| `type` | `correlation` | Never change |
| `outcome` | `detection` | Never change |
| `trigger_mode` | `summary` | Never change |
| `use_ingest_time` | `false` | Use event time, not ingest time |
| `status` | `active` | `inactive` to disable without deletion |
| `severity` | `10 / 30 / 50 / 70 / 90` | Informational / Low / Medium / High / Critical |
| `lookback` | `1h0m` format | e.g. `1h0m`, `15m0s`, `1d0h0m` |
| `schedule` | same format as lookback | Run frequency |
| `stopon` | `null` | Overwritten on deployment |
| `expirationon` | `null` | Ignored field |

MITRE ATT&CK fields — both `tactic` (primary) and `mitreattack` list must be populated:
```yaml
tactic: TA0006
technique: T1558.003
mitreattack:
  - tacticid: TA0006
    techniqueid: T1558.003
```

---

## 8. Anti-Patterns

These are recurring errors seen in rule reviews. Do not repeat them.

| Anti-Pattern | Problem | Fix |
|---|---|---|
| `#repo="winlog"` as primary filter | `#repo` values are GUIDs or client-specific names — non-portable across deployments | Use `#Vendor="Microsoft" #event.module=windows` |
| `\| winlog` mid-pipeline | `winlog` is a table name, not a pipe stage | Use `#Vendor="Microsoft" #event.module=windows` on line 1 |
| `#event_simpleName=HashSpanningTrees` on a Windows 4769 rule | `HashSpanningTrees` is a CrowdStrike Falcon event — unrelated to Windows Security EventCode 4769 | Use `#Vendor="Microsoft" #event.module=windows EventCode=4769` |
| `\| RequestCount >= 1` after `count()` | Every group has count ≥ 1 by definition — this filter does nothing | Use a meaningful threshold: `>= 3`, `>= 5` |
| `timestamp` in `table()` after `groupBy()` | Field is out of scope after aggregation | Use `FirstSeen` / `LastSeen` from `min/max(timestamp, ...)` |
| `format(..., "%d", ...)` | `%d` has inconsistent support across CQL versions | Replace all `%d` with `%s` |
| `AND` between pipeline lines | CQL uses implicit AND; keyword `AND` is for single-line compound conditions only | Split to pipe-per-line or use within one line for readability |
| Unpopulated DaC template fields | Bare `tactic:` / `technique:` without values fails validation | Always set all mandatory fields before deployment |
| `Vendor.srcip` instead of `source.ip` | Raw Vendor fields bypass ECS normalisation | Use ECS fields; fall back to `Vendor.*` only if ECS is unmapped |
| `#event_simpleName IN (A, B)` | `IN()` is not valid CQL syntax for tag fields | Use regex alternation: `#event_simpleName=/^(A\|B)$/` |
| `in(#tag, values=[...])` as filter | `in()` is a pipeline function, not a bare filter on tag fields | Use regex alternation on line 1, or `\| in(field, values=[...])` for regular fields in pipeline |
| `table(f1, f2, f3)` without array | `table()` argument is an array parameter | Use `table([f1, f2, f3])` with square brackets |
| `in()` before first `\|` | `in()` is a function, not a filter operator — cannot appear in filter expressions | Move to pipeline: `\| in(field, values=[...])` |

---

## 9. Worked Examples

### Windows Kerberoasting Detection (EventCode 4769)
```cql
#Vendor="Microsoft" #event.module=windows #event.kind=event
| EventCode=4769
| in(TicketEncryptionType, values=["0x17", "0x18"])
| !endsWith(ServiceName, suffix="$")
| ServiceName != "krbtgt"
| UserName != /\$$/
| groupBy(
    [UserName, HostName, TargetUserName, TicketEncryptionType, SourceIP],
    function=[count(as=RequestCount), min(timestamp, as=FirstSeen), max(timestamp, as=LastSeen)]
  )
| RequestCount >= 5
| ThreatScore := if(RequestCount > 10, "HIGH", if(RequestCount > 5, "MEDIUM", "LOW"))
| format(
    format="%s requesting Kerberos TGS with RC4 encryption (%s). Source: %s, Target: %s, Count: %s, Risk: %s",
    field=[UserName, TicketEncryptionType, SourceIP, TargetUserName, RequestCount, ThreatScore],
    as=DetectionSummary
  )
| table([FirstSeen, LastSeen, HostName, UserName, TargetUserName, SourceIP, TicketEncryptionType, RequestCount, ThreatScore, DetectionSummary])
```

### Vertical Port Scan — Fortinet FortiGate (Inbound)
```cql
#Vendor="fortinet" #event.module=fortigate
| network.direction="inbound"
| in(field="destination.port", values=[21, 22, 23, 25, 53, 79, 80, 110, 111, 135, 139, 143, 161, 443, 445, 1080, 1433, 1434, 1521, 1522, 1523, 1524, 1525, 1526, 1527, 1723, 3128, 3306, 3389, 5985, 8080])
| not match(field=source.ip, file="Customer Domain Controllers - IP", strict=false)
| not match(field=source.ip, file="Customer VA Scanners - AlphaNumeric", strict=false)
| not match(field=source.ip, file="Customer ISE Servers - IP", strict=false)
| not match(field=source.ip, file="Rule Suppression 0064 Generic Network Service Vertical Recon - AlphaNumeric", strict=false)
| bucket(field=[source.ip, destination.ip], span="2m", function=[collect([destination.port])])
| groupBy([source.ip, destination.ip], function=count(destination.port, as=unique_dst_ports))
| unique_dst_ports >= 15
```

### Outbound Threat / Malware Communication — Multi-vendor
```cql
#Vendor="fortinet" #event.module=fortigate
| network.direction="outbound"
| in(field="event.category", values=["misc exploit", "misc malware", "backdoor detected", "web exploit", "potential botnet connection", "command execution"])
| not match(field=source.ip, file="Customer VA Scanners - AlphaNumeric", strict=false)
| not match(field=source.ip, file="Customer Domain Controllers - IP", strict=false)
```

### AWS CloudTrail — IAM Privilege Escalation
```cql
#Vendor="AWS" #event.module=cloudtrail
| Vendor.eventSource="iam.amazonaws.com"
| in(field="Vendor.eventName", values=["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreatePolicyVersion", "AddUserToGroup", "CreateAccessKey", "UpdateAssumeRolePolicy"])
| table([@timestamp, Vendor.eventName, user.name, Vendor.userIdentity.type, Vendor.userIdentity.arn, Vendor.sourceIPAddress, Vendor.awsRegion, Vendor.recipientAccountId])
```
