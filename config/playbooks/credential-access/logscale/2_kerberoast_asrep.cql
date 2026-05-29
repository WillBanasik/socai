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
