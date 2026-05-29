// Data Exfiltration Stage 2 — Cloud application file access for {{target_upn}}.
// Bulk file access, external sharing, and mailbox-forwarding rules from the M365
//   unified audit log (#Vendor="microsoft" #event.module=m365 — verified).
//   Operations are in Vendor.Operation; file/site detail in Vendor.SourceFileName /
//   Vendor.SiteUrl; sharing target in Vendor.TargetUserOrGroupName (inspect rows).

// --- Sub-query A: Bulk file access (hourly) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_upn}}/i
| in(field=Vendor.Operation, values=["FileDownloaded", "FileSyncDownloadedFull",
    "FileAccessed", "FolderModified", "ListItemUpdated"])
| bucket(span=1h, function=[
    count(as=EventCount),
    count(field=Vendor.SourceFileName, distinct=true, as=UniqueFiles),
    count(field=Vendor.SiteUrl, distinct=true, as=UniqueSites),
    collect([Vendor.Operation], limit=10)
  ])
| sort(EventCount, order=desc, limit=200)


// --- Sub-query B: External sharing events ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_upn}}/i
| Vendor.Operation = /SharingSet|AddedToGroup|AnonymousLinkCreated|CompanyLinkCreated|SharingInvitationCreated|SecureLinkCreated/i
| table([@timestamp, Vendor.Operation, Vendor.SourceFileName, Vendor.SiteUrl], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query C: Mailbox-forwarding / inbox rules (exfil via mail) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_upn}}/i
| in(field=Vendor.Operation, values=["Set-Mailbox", "New-InboxRule", "Set-InboxRule",
    "UpdateInboxRules", "New-TransportRule"])
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP], limit=200)
| sort(@timestamp, order=desc, limit=200)
