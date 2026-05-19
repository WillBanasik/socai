// --- Sub-query A: Credential dumping tools (per host) ---
// Replace HOST_NAME with each host to investigate.

#event_simpleName=ProcessRollup2
| ComputerName = /HOST_NAME/i
| FileName = /^(mimikatz\.exe|procdump\.exe|procdump64\.exe|nanodump\.exe|pypykatz)$/i OR CommandLine = /lsass.*MiniDump|lsass.*procdump|comsvcs.*lsass|sekurlsa|logonpasswords|SAM.*hive|SECURITY.*hive/i
| table([@timestamp, ComputerName, FileName, CommandLine, UserName,
         ParentBaseFileName, SHA256HashData])
| sort(@timestamp, order=desc)


// --- Sub-query B: LSASS access events (per host) ---
// CrowdStrike tracks LSASS access through specific detections.

#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| ComputerName = /HOST_NAME/i
| DetectName = /credential|LSASS|pass.the.hash|kerberoast|golden.ticket|DCSync|lateral.movement|mimikatz|brute.force/i
| table([@timestamp, ComputerName, DetectName, DetectDescription,
         Severity, FileName, CommandLine, Tactic, Technique])
| sort(@timestamp, order=desc)


// --- UNAVAILABLE: MDI Kerberos anomaly detection ---
// Source: IdentityLogonEvents (Microsoft Defender for Identity)
// Not available in LogScale. Check Microsoft Defender for Identity portal
// for Kerberos protocol anomalies (overpass-the-hash, pass-the-ticket,
// golden ticket, silver ticket, encryption downgrade).
