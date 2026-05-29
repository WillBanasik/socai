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
