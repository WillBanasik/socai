// Defence Evasion Stage 1 — Security-log clearing.

// --- Sub-query A: Windows security log cleared (1102) / log file cleared (104) ---

#Vendor="microsoft" #event.module=windows
| in(field=EventCode, values=["1102", "104"])
| host.hostname = /{{device_name}}/i
| table([@timestamp, host.hostname, EventCode, windows.EventData.SubjectUserName], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: wevtutil cl / Clear-EventLog via process telemetry ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(wevtutil|powershell|pwsh)\.exe$/i
| CommandLine = /\bcl\b|clear-log|Clear-EventLog|Remove-EventLog/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)
