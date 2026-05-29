// Phishing Stage 4 — Attachment endpoint execution.
// Goal: was the attachment ({{sha256}}) written to disk and/or executed on an
//   endpoint, within ~2h of email delivery.
// Primary source: CrowdStrike Falcon endpoint telemetry (#event_simpleName=...),
//   the NG-SIEM equivalent of Sentinel DeviceFileEvents / DeviceProcessEvents.
//   Falcon carries the file hash in SHA256HashData.
// Alternative when Falcon endpoint is not deployed: Defender advanced-hunting
//   DeviceFileEvents / DeviceProcessEvents via #event.dataset="windows-defender-365.event"
//   (filter Vendor.properties.SHA256 = "{{sha256}}").
// CQL is join-free: correlate A and B on ComputerName + SHA256HashData within ~2h
//   of the delivery time from Stage 1/3.

// --- Sub-query A: File written to disk with the attachment hash ---

#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| SHA256HashData = "{{sha256}}"
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Process execution of the attachment hash ---

#event_simpleName=ProcessRollup2
| SHA256HashData = "{{sha256}}"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine,
         ParentBaseFileName, ParentCommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
