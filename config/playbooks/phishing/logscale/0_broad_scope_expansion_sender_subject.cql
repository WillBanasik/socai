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
