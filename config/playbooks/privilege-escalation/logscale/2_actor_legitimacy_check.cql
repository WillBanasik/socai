// Privilege Escalation Stage 2 — Actor legitimacy check for {{actor_upn}}.
// Is the actor's sign-in context legitimate (location, risk, device, CA)?
// Source: Entra ID sign-ins (entraid connector, dataset entraid.signin — verified).
//   The Sentinel IdentityInfo enrichment (department / job title) has no portable
//   NG-SIEM equivalent — pull it from the directory if role context is needed.

// --- Sub-query A: Interactive sign-ins with risk / device / CA context ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{actor_upn}}/i
| Vendor.properties.isInteractive = "true"
| groupBy([source.ip, Vendor.properties.location.city, Vendor.properties.location.countryOrRegion],
    function=[
      count(as=TotalCount),
      collect([Vendor.properties.appDisplayName], limit=20),
      collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
      collect([Vendor.properties.riskState], limit=10),
      collect([Vendor.properties.riskDetail], limit=10),
      collect([Vendor.properties.conditionalAccessStatus], limit=10),
      collect([Vendor.properties.authenticationRequirement], limit=10),
      collect([Vendor.properties.deviceDetail.operatingSystem], limit=10),
      collect([Vendor.properties.deviceDetail.isCompliant], limit=5),
      collect([Vendor.properties.deviceDetail.isManaged], limit=5),
      collect([Vendor.properties.deviceDetail.trustType], limit=5),
      collect([Vendor.properties.userAgent], limit=10),
      min(@timestamp, as=FirstSeen),
      max(@timestamp, as=LastSeen)
    ])
| sort(TotalCount, order=desc, limit=200)


// --- Sub-query B: Non-interactive sign-ins ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{actor_upn}}/i
| Vendor.properties.isInteractive = "false"
| groupBy([source.ip, Vendor.properties.location.countryOrRegion], function=[
    count(as=TotalCount),
    collect([Vendor.properties.appDisplayName], limit=20),
    collect([Vendor.properties.status.errorCode], limit=15),
    collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(TotalCount, order=desc, limit=200)
