// ---
// name: Account Investigation
// description: >
//   Account investigation playbook covering Azure AD sign-in activity
//   (interactive and non-interactive), on-prem Active Directory logon
//   events (Windows Security), and CrowdStrike Falcon endpoint logon
//   context. Designed for account compromise, lockout investigations,
//   suspicious sign-in activity, and service account abuse.
//   Time scope is controlled by the LogScale search time picker.
// parameters:
//   - name: upn
//     type: string
//     description: UserPrincipalName of the suspect account (e.g. user@domain.com)
//   - name: username
//     type: string
//     description: On-prem sAMAccountName (e.g. m.chalkiadaki). Derive from UPN if not provided.
//   - name: ip
//     type: string
//     description: Suspicious source IP address (optional; omit to investigate all activity)
// stages:
//   - stage: 1
//     name: Cloud identity triage (Azure AD)
//     description: >
//       Summarised sign-in activity across interactive and non-interactive Azure AD
//       logs. Returns aggregate counts by IP, location, app, result, and sign-in type.
//     run: always
//   - stage: 2
//     name: On-prem AD logon and lockout triage
//     description: >
//       Summarised on-prem Active Directory logon activity from Windows Security
//       Event Logs. Covers successful logons (4624), failed logons (4625),
//       Kerberos pre-auth failures (4771), NTLM validation (4776), TGT requests
//       (4768), service tickets (4769), and account lockouts (4740).
//     run: always (primary stage for on-prem AD and lockout investigations)
//   - stage: 3
//     name: Endpoint logon context
//     description: >
//       CrowdStrike Falcon endpoint logon events for the target user. Shows
//       authentication type, source IP, and host context.
//     run: always
//   - stage: 4
//     name: Source host enumeration
//     description: >
//       Given a source IP identified in earlier stages, determine what other
//       accounts authenticate from the same host. Identifies service accounts,
//       machine accounts, and multi-user patterns.
//     run: when a source IP warrants investigation
// data_sources:
//   - Azure AD Sign-In Logs (azure.signinlogs)
//   - Windows Event Logs (Microsoft windows — SecurityEvent equivalent)
//   - CrowdStrike Falcon (UserLogon)
//   - UNAVAILABLE: IdentityLogonEvents, IdentityDirectoryEvents (MDI)
//   - UNAVAILABLE: BehaviorAnalytics (UEBA)
//   - UNAVAILABLE: AuditLogs, OfficeActivity (post-compromise persistence — check Entra admin center)
//   - UNAVAILABLE: DeviceNetworkInfo (hostname resolution — use Falcon host lookup instead)
// ---


// ============================================================================
// STAGE 1 — Cloud identity triage (Azure AD)
// ============================================================================
// Parameters: upn
// Run: ALWAYS — starting point for cloud identity investigations.
// Returns: sign-in activity by IP, location, app, result, sign-in type.

// --- Sub-query A: Interactive sign-ins ---

#event.dataset="azure.signinlogs"
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

#event.dataset="azure.signinlogs"
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


// ============================================================================
// STAGE 2 — On-prem AD logon and lockout triage
// ============================================================================
// Parameters: username
// Run: ALWAYS — primary stage for on-prem AD and lockout investigations.
// Returns: logon summary by source IP, event type, and result.

// --- Sub-query A: Logon events summary (4624, 4625, 4771, 4776, 4768, 4769) ---

#Vendor="Microsoft" #event.module=windows
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

#Vendor="Microsoft" #event.module=windows EventCode=4625
| user.name = /{{username}}/i
| table([@timestamp, host.hostname, user.name,
         windows.EventData.IpAddress, windows.EventData.SubStatus,
         windows.EventData.LogonType, windows.EventData.FailureReason])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query C: Account lockout events (4740) ---

#Vendor="Microsoft" #event.module=windows EventCode=4740
| user.name = /{{username}}/i
| table([@timestamp, host.hostname, user.name,
         windows.EventData.TargetDomainName])
| sort(@timestamp, order=desc)


// --- Sub-query D: Kerberos pre-auth failures (4771) with status decode ---

#Vendor="Microsoft" #event.module=windows EventCode=4771
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


// ============================================================================
// STAGE 3 — Endpoint logon context
// ============================================================================
// Parameters: username
// Run: ALWAYS — CrowdStrike Falcon endpoint logon events.
// Returns: authentication events with logon type, source IP, and host.

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


// ============================================================================
// STAGE 4 — Source host enumeration
// ============================================================================
// Parameters: ip
// Run: When a source IP warrants investigation — automated auth pattern,
//      DC-sourced activity, or unknown origin.
// Returns: all accounts authenticating from the target IP.

// --- Sub-query A: Windows logon events from the target IP ---

#Vendor="Microsoft" #event.module=windows
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


// --- Sub-query C: Azure AD sign-ins from the target IP ---

#event.dataset="azure.signinlogs"
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
