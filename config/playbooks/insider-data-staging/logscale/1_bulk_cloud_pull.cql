// Insider / Data Staging Stage 1 — Bulk SharePoint / OneDrive pull.
// Source: M365 unified audit log (verified m365 module).
#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_upn}}/i
| in(field=Vendor.Operation, values=["FileDownloaded", "FileSyncDownloadedFull", "FileAccessed"])
| bucket(span=1h, function=[
    count(as=EventCount),
    count(field=Vendor.SourceFileName, distinct=true, as=UniqueFiles),
    count(field=Vendor.SiteUrl, distinct=true, as=UniqueSites),
    collect([Vendor.Operation], limit=10)
  ])
| EventCount >= 50
| sort(EventCount, order=desc, limit=200)
