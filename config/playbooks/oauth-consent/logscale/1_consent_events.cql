// OAuth Consent Stage 1 — Consent & app-role / SP-credential events.
// Source: M365 unified audit log, AzureActiveDirectory workload (verified m365 module).
#Vendor="microsoft" #event.module=m365
| Vendor.Workload = "AzureActiveDirectory"
| Vendor.UserId = /{{upn}}/i
| in(field=Vendor.Operation, values=["Consent to application.", "Add OAuth2PermissionGrant.",
    "Add app role assignment to user.", "Add app role assignment to service principal.",
    "Add delegated permission grant.", "Add service principal.",
    "Add service principal credentials.", "Update application.", "Update service principal."])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.ResultStatus], limit=200)
| sort(@timestamp, order=asc, limit=200)
