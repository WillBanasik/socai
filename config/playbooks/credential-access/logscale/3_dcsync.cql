// Credential Access Stage 3 — DCSync / directory replication abuse.
// Windows 4662 carrying the DS-Replication-Get-Changes control-access-right GUIDs,
//   requested by a NON-DC account, is the DCSync tell.
// ⚠ The replication GUID lives in the event Properties — matched here against
//   @rawstring. Confirm the discrete field (e.g. windows.EventData.Properties) on the
//   client repo and tighten the match if needed.
#Vendor="microsoft" #event.module=windows EventCode=4662
| @rawstring = /1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2/i
| windows.EventData.SubjectUserName != /\$$/
| table([@timestamp, host.hostname, windows.EventData.SubjectUserName,
         windows.EventData.ObjectName, windows.EventData.AccessMask], limit=200)
| sort(@timestamp, order=asc, limit=200)
