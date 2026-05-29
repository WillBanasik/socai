// BEC Stage 7 — Attacker IP tenant sweep.
// Goal: scope {{attacker_ip}} across the whole tenant — every account the attacker
//   touched, not just the alert's. Critical for finding unreported compromises.
// Source: Entra ID sign-ins (entraid connector, dataset entraid.signin — verified).
//   A successful sign-in has Vendor.properties.status.errorCode = "0".

// --- Sub-query A: Interactive sign-ins from the attacker IP, per account ---

#event.module=entraid #event.dataset="entraid.signin"
| source.ip = "{{attacker_ip}}"
| Vendor.properties.isInteractive = "true"
| groupBy([Vendor.properties.userPrincipalName], function=[
    count(as=InteractiveCount),
    count(field=Vendor.properties.status.errorCode, distinct=true, as=DistinctResultCodes),
    collect([Vendor.properties.status.errorCode], limit=20),
    collect([Vendor.properties.appDisplayName], limit=20),
    collect([Vendor.properties.location.countryOrRegion], limit=10),
    collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
    collect([Vendor.properties.conditionalAccessStatus], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(InteractiveCount, order=desc, limit=200)


// --- Sub-query B: Non-interactive sign-ins from the attacker IP, per account ---

#event.module=entraid #event.dataset="entraid.signin"
| source.ip = "{{attacker_ip}}"
| Vendor.properties.isInteractive = "false"
| groupBy([Vendor.properties.userPrincipalName], function=[
    count(as=NonInteractiveCount),
    collect([Vendor.properties.status.errorCode], limit=20),
    collect([Vendor.properties.appDisplayName], limit=20),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(NonInteractiveCount, order=desc, limit=200)


// --- Sub-query C: Successful sign-ins only (errorCode 0) — highest priority ---

#event.module=entraid #event.dataset="entraid.signin"
| source.ip = "{{attacker_ip}}"
| Vendor.properties.status.errorCode = "0"
| groupBy([Vendor.properties.userPrincipalName], function=[
    count(as=SuccessCount),
    collect([Vendor.properties.appDisplayName], limit=20),
    collect([Vendor.properties.isInteractive], limit=5),
    min(@timestamp, as=FirstSuccess),
    max(@timestamp, as=LastSuccess)
  ])
| sort(SuccessCount, order=desc, limit=200)
