// --- Sub-query A: Interactive sign-ins ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{upn}}/i
| Vendor.properties.isInteractive = "true"
| groupBy([source.ip, Vendor.properties.location.city, Vendor.properties.location.countryOrRegion], function=[
    count(as=TotalCount),
    collect([Vendor.properties.appDisplayName], limit=15),
    collect([Vendor.properties.status.errorCode], limit=15),
    collect([Vendor.properties.clientAppUsed], limit=10),
    collect([Vendor.properties.riskLevelDuringSignIn], limit=5),
    collect([Vendor.properties.conditionalAccessStatus], limit=5),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(TotalCount, order=desc)


// --- Sub-query B: Non-interactive sign-ins ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{upn}}/i
| Vendor.properties.isInteractive = "false"
| groupBy([source.ip, Vendor.properties.location.city, Vendor.properties.location.countryOrRegion], function=[
    count(as=TotalCount),
    collect([Vendor.properties.appDisplayName], limit=15),
    collect([Vendor.properties.status.errorCode], limit=15),
    collect([Vendor.properties.clientAppUsed], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(TotalCount, order=desc)
