// Account Compromise Stage 5 — Post-compromise persistence for {{upn}}.
// MFA / credential changes, OAuth consent, conditional-access tampering, and
//   inbox-rule / mail-forwarding persistence after a confirmed compromise.
// Source: Microsoft 365 unified audit log (#Vendor="microsoft" #event.module=m365 —
//   verified). AzureActiveDirectory and Exchange workloads both flow through this
//   module; rule/forwarding parameters live in the raw event (inspect matched rows).

// --- Sub-query A: Entra credential / MFA / OAuth / conditional-access changes ---

#Vendor="microsoft" #event.module=m365
| Vendor.Workload = "AzureActiveDirectory"
| @rawstring = /{{upn}}/i
| in(field=Vendor.Operation, values=["User registered security info",
    "User registered all required security info", "User started security info registration",
    "User deleted security info", "Admin registered security info",
    "Reset password (by admin)", "Reset password (self-service)",
    "Change password (self-service)", "User performed a self-service password reset",
    "Consent to application", "Add conditional access policy",
    "Update conditional access policy", "Delete conditional access policy",
    "Add service principal credentials",
    "Update application – Certificates and secrets management"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.ResultStatus], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: Inbox rules / mail forwarding ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| in(field=Vendor.Operation, values=["New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "New-TransportRule", "Set-TransportRule", "UpdateInboxRules",
    "Set-Mailbox", "Set-MailboxJunkEmailConfiguration"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=desc, limit=200)
