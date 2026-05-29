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
