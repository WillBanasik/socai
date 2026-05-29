// OAuth Consent Stage 4 — Granting-user sign-in context.
// Source: Entra ID sign-ins (entraid connector, dataset entraid.signin — verified).
#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{upn}}/i
| groupBy([source.ip, Vendor.properties.location.city,
           Vendor.properties.location.countryOrRegion], function=[
    count(as=TotalCount),
    collect([Vendor.properties.appDisplayName], limit=20),
    collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
    collect([Vendor.properties.conditionalAccessStatus], limit=10),
    collect([Vendor.properties.status.errorCode], limit=15),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(TotalCount, order=desc, limit=200)
