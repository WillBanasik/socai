// BEC Stage 3 — ZAP and remediation status.
// Goal: which campaign emails were delivered, which were remediated (ZAP / admin
//   purge), which were missed and still in mailboxes, and the exposure window.
// Source: Defender advanced-hunting (windows-defender-365); see Stage 0 header.
// CQL is join-free: pivot on NetworkMessageId (+ RecipientEmailAddress) and compute
//   ExposureMinutes = (remediation @timestamp − delivery @timestamp). Recipients in
//   A with no matching row in B were NOT remediated (still exposed).

// --- Sub-query A: Delivered campaign mail (per recipient) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| Vendor.properties.DeliveryAction = "Delivered"
| table([@timestamp, Vendor.properties.NetworkMessageId, Vendor.properties.RecipientEmailAddress,
         Vendor.properties.Subject, Vendor.properties.DeliveryLocation,
         Vendor.properties.SenderFromAddress], limit=500)
| sort(@timestamp, order=asc, limit=500)


// --- Sub-query B: Post-delivery remediation events (ZAP / purge) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailPostDeliveryEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| table([@timestamp, Vendor.properties.NetworkMessageId, Vendor.properties.RecipientEmailAddress,
         Vendor.properties.ActionType], limit=500)
| sort(@timestamp, order=asc, limit=500)
