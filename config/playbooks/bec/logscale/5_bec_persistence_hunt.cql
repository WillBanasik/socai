// BEC Stage 5 — BEC persistence hunt.
// Goal: inbox rules (esp. delete/StopProcessing), mail forwarding, mailbox
//   permission grants, OAuth consent, and MFA-method changes on {{upn}}.
// Source: Microsoft 365 unified audit log via the M365 connector
//   (#Vendor="microsoft" #event.module=m365 — verified, config/ngsiem/ngsiem_rules.md §4).
//   Operations are in Vendor.Operation; Exchange and AzureActiveDirectory workloads
//   both flow through this module (Vendor.Workload distinguishes them).
//   Forwarding/rule parameters are in the raw event (Vendor.* / @rawstring) — inspect
//   the matched rows for ForwardingSmtpAddress / DeleteMessage / StopProcessingRules.

// --- Sub-query A: Inbox rules ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| in(field=Vendor.Operation, values=["New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "UpdateInboxRules", "Remove-InboxRule", "Disable-InboxRule"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Mail forwarding configuration ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| Vendor.Operation = "Set-Mailbox"
| @rawstring = /ForwardingSmtpAddress|ForwardingAddress|DeliverToMailboxAndForward|RedirectTo/i
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query C: Mailbox permission grants (SendAs, FullAccess, delegation) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| Vendor.Operation = /MailboxPermission|RecipientPermission|FolderPermission|MailboxLogin/i
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query D: OAuth / consent grants (illicit app consent for persistence) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| in(field=Vendor.Operation, values=["Consent to application.", "Add OAuth2PermissionGrant.",
    "Add app role assignment to user.", "Add delegated permission grant.",
    "Add service principal.", "Add service principal credentials."])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query E: MFA method changes (attacker registering their own MFA) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{upn}}/i OR Vendor.MailboxOwnerUPN = /{{upn}}/i
| Vendor.Operation = /security info|Update user/i
| @rawstring = /StrongAuthentication|PhoneNumber|AuthenticatorApp|SecurityInfo|Fido2/i
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=asc, limit=200)
