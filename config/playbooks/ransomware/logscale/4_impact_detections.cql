// Ransomware Stage 4 — Encryption tooling & impact detections.
// Source: Falcon detection summary events. ⚠ DetectName/DetectDescription/Tactic/
//   Technique are standard Falcon detection fields — confirm against the client repo
//   if empty (some sensors populate Objective/Scenario instead).
#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| ComputerName = /{{device_name}}/i
| table([@timestamp, ComputerName, DetectName, DetectDescription, Severity,
         Tactic, Technique, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc, limit=200)
