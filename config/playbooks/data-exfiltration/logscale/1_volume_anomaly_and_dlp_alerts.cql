// Data Exfiltration Stage 1 — Volume anomaly and DLP alerts for {{target_upn}}.
// Sub-query A: DLP / exfiltration detections. ⚠ DLP alerting is client-dependent in
//   NG-SIEM. This uses Defender advanced-hunting AlertInfo (windows-defender-365);
//   where the client runs Netskope DLP instead, swap to:
//     #Vendor="netskope" #event.module=sse | Vendor.alert_type=/dlp/i
//   (Vendor.dlp_incident_id / Vendor.dlp_rule_count carry the DLP detail).
//   Sub-table discriminator is Vendor.Workload (e.g. "AlertInfo") — see phishing Stage 0 header.
// Sub-query B: daily file-operation volume from the M365 unified audit log
//   (#event.module=m365 — verified).

// --- Sub-query A: DLP / exfiltration alerts ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "AlertInfo"
| Vendor.properties.Title = /DLP|data loss|exfiltration|mass download|unusual volume|sensitive|information protection/i
| @rawstring = /{{target_upn}}/i
| table([@timestamp, Vendor.properties.Title, Vendor.properties.Severity,
         Vendor.properties.Category], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: Daily file-operation volume (downloads / uploads / copies) ---

#Vendor="microsoft" #event.module=m365
| Vendor.UserId = /{{target_upn}}/i
| in(field=Vendor.Operation, values=["FileDownloaded", "FileUploaded",
    "FileSyncDownloadedFull", "FileModifiedExtended", "FileCopied"])
| bucket(span=1d, function=[
    count(as=TotalOps),
    count(field=Vendor.SourceFileName, distinct=true, as=UniqueFiles),
    collect([Vendor.Operation], limit=10),
    collect([Vendor.SiteUrl], limit=20)
  ])
| sort(@timestamp, order=desc, limit=200)
