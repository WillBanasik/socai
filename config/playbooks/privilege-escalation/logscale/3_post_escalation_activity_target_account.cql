// Privilege Escalation Stage 3 — Post-escalation activity for {{target_user}}.
// What did the escalated account do with its new privileges — admin-portal access,
//   cascading directory/app/credential/MFA changes, and Exchange/SharePoint abuse.
// Sources: Entra sign-ins (entraid.signin) and the M365 unified audit log (m365) —
//   both verified modules.

// --- Sub-query A: Sign-ins to admin portals / management apps ---

#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.userPrincipalName = /{{target_user}}/i
| in(field=Vendor.properties.appDisplayName, values=["Azure Portal",
    "Microsoft Azure Management", "Microsoft 365 admin center", "Exchange Admin Center",
    "Microsoft Entra admin center", "Microsoft Graph", "Microsoft Graph PowerShell",
    "Azure Active Directory PowerShell", "Microsoft Teams Admin Center",
    "SharePoint Online Management Shell"])
| table([@timestamp, Vendor.properties.appDisplayName, source.ip,
         Vendor.properties.location.countryOrRegion, Vendor.properties.status.errorCode], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: Cascading directory / app / credential / MFA changes by the target ---

#Vendor="microsoft" #event.module=m365
| Vendor.Workload = "AzureActiveDirectory"
| Vendor.UserId = /{{target_user}}/i
| in(field=Vendor.Operation, values=["Add member to role", "Add member to group",
    "Add eligible member to role", "Add application", "Add service principal",
    "Add service principal credentials", "Consent to application",
    "Add app role assignment to service principal", "Reset password (by admin)",
    "Update user", "Add owner to application", "Add owner to service principal",
    "User registered security info", "User deleted security info",
    "Admin registered security info"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query C: Exchange / SharePoint operations (inbox rules, eDiscovery, sharing) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_user}}/i
| in(field=Vendor.Operation, values=["New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "New-TransportRule", "Set-TransportRule", "UpdateInboxRules", "New-ComplianceSearch",
    "Start-ComplianceSearch", "New-ComplianceSearchAction", "SiteCollectionAdminAdded",
    "SharingPolicyChanged", "SiteCollectionCreated"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.Workload], limit=200)
| sort(@timestamp, order=desc, limit=200)
