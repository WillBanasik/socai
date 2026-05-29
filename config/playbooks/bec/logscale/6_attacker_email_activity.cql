// BEC Stage 6 — Attacker email activity (the BEC payoff phase).
// Goal: did the attacker send mail from the compromised account {{upn}} — outbound
//   or intra-org (invoice fraud, payment redirection, internal phishing).
// Sub-query A: Defender advanced-hunting EmailEvents (windows-defender-365) for the
//   sent mail itself. Sub-query B: Exchange Send / SendAs / SendOnBehalf operations
//   from the M365 unified audit log (#event.module=m365).

// --- Sub-query A: Outbound / intra-org mail sent from the compromised account ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| Vendor.properties.SenderFromAddress = /{{upn}}/i OR Vendor.properties.SenderMailFromAddress = /{{upn}}/i
| Vendor.properties.EmailDirection = /Outbound|Intra-org/i
| table([@timestamp, Vendor.properties.Subject, Vendor.properties.SenderFromAddress,
         Vendor.properties.RecipientEmailAddress, Vendor.properties.SenderIPv4,
         Vendor.properties.EmailDirection, Vendor.properties.DeliveryAction,
         Vendor.properties.NetworkMessageId], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: Exchange Send / SendAs / SendOnBehalf operations ---

#Vendor="microsoft" #event.module=m365
| Vendor.Workload = "Exchange"
| Vendor.UserId = /{{upn}}/i
| in(field=Vendor.Operation, values=["Send", "SendAs", "SendOnBehalf"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP,
         Vendor.ExternalAccess], limit=200)
| sort(@timestamp, order=desc, limit=200)
