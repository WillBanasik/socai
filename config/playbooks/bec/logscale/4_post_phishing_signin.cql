// BEC Stage 4 — Post-phishing sign-in analysis.
// Goal: for the compromised / clicked account {{upn}}, surface sign-ins from
//   unfamiliar IPs (AiTM token theft, credential reuse). The attacker IP is an
//   OUTPUT of this stage — feed it into {{attacker_ip}} for Stages 5–7.
// Source: Entra ID sign-ins (dedicated entraid connector, dataset entraid.signin —
//   verified). Interactive vs non-interactive split on Vendor.properties.isInteractive.

// --- Sub-query A: Interactive sign-ins ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{upn}}/i
| Vendor.properties.isInteractive = "true"
| groupBy([source.ip, Vendor.properties.location.city, Vendor.properties.location.countryOrRegion],
    function=[
      count(as=TotalCount),
      collect([Vendor.properties.appDisplayName], limit=20),
      collect([Vendor.properties.status.errorCode], limit=15),
      collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
      collect([Vendor.properties.riskState], limit=10),
      collect([Vendor.properties.conditionalAccessStatus], limit=10),
      collect([Vendor.properties.authenticationRequirement], limit=10),
      collect([Vendor.properties.clientAppUsed], limit=10),
      collect([Vendor.properties.deviceDetail.operatingSystem], limit=10),
      collect([Vendor.properties.deviceDetail.browser], limit=10),
      min(@timestamp, as=FirstSeen),
      max(@timestamp, as=LastSeen)
    ])
| sort(TotalCount, order=desc, limit=200)


// --- Sub-query B: Non-interactive sign-ins (token replay, app access) ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{upn}}/i
| Vendor.properties.isInteractive = "false"
| groupBy([source.ip, Vendor.properties.location.city, Vendor.properties.location.countryOrRegion],
    function=[
      count(as=TotalCount),
      collect([Vendor.properties.appDisplayName], limit=20),
      collect([Vendor.properties.status.errorCode], limit=15),
      collect([Vendor.properties.riskLevelDuringSignIn], limit=10),
      collect([Vendor.properties.conditionalAccessStatus], limit=10),
      min(@timestamp, as=FirstSeen),
      max(@timestamp, as=LastSeen)
    ])
| sort(TotalCount, order=desc, limit=200)
