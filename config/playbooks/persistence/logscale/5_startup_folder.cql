// Persistence Stage 5 — Startup-folder writes.
#event_simpleName=/^(NewExecutableWritten|NewScriptWritten|GenericFileWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /\\Start Menu\\Programs\\Startup\\/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
