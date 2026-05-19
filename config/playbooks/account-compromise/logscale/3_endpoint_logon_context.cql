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
