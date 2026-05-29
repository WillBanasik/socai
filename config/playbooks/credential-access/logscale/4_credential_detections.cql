// Credential Access Stage 4 — Credential-theft detections.
// Source: Falcon detection summary events filtered to credential-access tradecraft.
#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| DetectName = /credential|lsass|pass.the.hash|kerberoast|golden ticket|silver ticket|dcsync|mimikatz|ntds|credential dumping/i
| table([@timestamp, ComputerName, UserName, DetectName, DetectDescription,
         Severity, Tactic, Technique, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc, limit=200)
