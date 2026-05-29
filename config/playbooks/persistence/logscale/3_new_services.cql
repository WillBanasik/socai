// Persistence Stage 3 — New services.

// --- Sub-query A: Service install via Windows event (7045) ---

#Vendor="microsoft" #event.module=windows EventCode=7045
| host.hostname = /{{device_name}}/i
| table([@timestamp, host.hostname, windows.EventData.ServiceName,
         windows.EventData.ImagePath, windows.EventData.ServiceType,
         windows.EventData.StartType], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: sc.exe / New-Service via process telemetry ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(sc|powershell|pwsh)\.exe$/i
| CommandLine = /\bcreate\b|New-Service|Set-Service/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)
