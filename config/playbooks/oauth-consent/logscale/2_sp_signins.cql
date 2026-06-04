// OAuth Consent Stage 2 — Service-principal sign-ins post-consent.
// ⚠ Service-principal sign-ins ride the entraid connector. The discovered entraid
//   schema populates Vendor.properties.servicePrincipalName on SP sign-ins, but the
//   exact dataset (entraid.signin vs a sibling like entraid.serviceprincipalsignin)
//   is NOT confirmed in this repo — verify before relying on this:
//     #event.module=entraid | groupBy(#event.dataset, function=count())
//   then set the dataset filter on line 1 accordingly.
// Scoped to the consented app (app_id from Stage 1). app_id=__NONE__ matches
// nothing rather than returning every SP sign-in in the tenant.
#event.module=entraid #event.dataset=/entraid\..*signin/i
| Vendor.properties.servicePrincipalName = /.+/
| Vendor.properties.appId = "{{app_id}}" OR Vendor.properties.servicePrincipalName = /{{app_id}}/i
| table([@timestamp, Vendor.properties.servicePrincipalName, Vendor.properties.appId,
         source.ip, Vendor.properties.resourceDisplayName,
         Vendor.properties.status.errorCode], limit=200)
| sort(@timestamp, order=asc, limit=200)
