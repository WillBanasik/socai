// OAuth Consent Stage 5 — IP tenant sweep + correlated alerts.

// --- Sub-query A: Other accounts seen from the consent IP (tenant sweep) ---

#event.module=entraid #event.dataset="entraid.signin"
| source.ip = "{{ip}}"
| Vendor.properties.userPrincipalName != /{{upn}}/i
| groupBy([Vendor.properties.userPrincipalName,
           Vendor.properties.location.countryOrRegion], function=[
    count(as=SignInCount),
    collect([Vendor.properties.appDisplayName], limit=20),
    collect([Vendor.properties.status.errorCode], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(SignInCount, order=desc, limit=200)


// --- Sub-query B: Correlated alerts (Defender AlertInfo) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "AlertInfo"
| @rawstring = /{{upn}}/i OR @rawstring = /{{ip}}/i OR @rawstring = /{{object_id}}/i
| table([@timestamp, Vendor.properties.Title, Vendor.properties.Severity,
         Vendor.properties.Category], limit=200)
| sort(@timestamp, order=desc, limit=200)
