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
