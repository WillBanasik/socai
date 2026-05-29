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
