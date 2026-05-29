// Persistence Stage 1 — Scheduled tasks.

// --- Sub-query A: schtasks / Register-ScheduledTask via process telemetry ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(schtasks|at)\.exe$/i OR CommandLine = /Register-ScheduledTask|New-ScheduledTask/i
| CommandLine = /\/create|Register-ScheduledTask|New-ScheduledTask/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Scheduled-task creation via Windows event (4698) ---

#Vendor="microsoft" #event.module=windows EventCode=4698
| host.hostname = /{{device_name}}/i
| table([@timestamp, host.hostname, windows.EventData.SubjectUserName,
         windows.EventData.TaskName], limit=200)
| sort(@timestamp, order=asc, limit=200)
