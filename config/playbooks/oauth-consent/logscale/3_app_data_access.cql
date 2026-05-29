// OAuth Consent Stage 3 — Post-consent data access by the user / app.
// Source: M365 unified audit log. ⚠ The Sentinel original also reads
//   MicrosoftGraphActivityLogs (the consented app's Graph API calls) — there is NO
//   NG-SIEM equivalent for that table, so app-side Graph access is Sentinel-only.
#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i
| in(field=Vendor.Operation, values=["MailItemsAccessed", "FileDownloaded", "FileAccessed",
    "Send", "SendAs", "SharingSet", "AnonymousLinkCreated"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload,
         Vendor.ExternalAccess], limit=200)
| sort(@timestamp, order=asc, limit=200)
