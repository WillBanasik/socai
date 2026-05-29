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
