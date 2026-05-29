// Defence Evasion Stage 4 — Defense-evasion detections.
#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| DetectName = /tamper|defender|antivirus|log clear|evasion|uninstall|exclusion|disable/i OR Tactic = /Defense Evasion/i
| table([@timestamp, ComputerName, UserName, DetectName, DetectDescription,
         Severity, Tactic, Technique, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc, limit=200)
