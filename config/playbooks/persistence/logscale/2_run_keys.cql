// Persistence Stage 2 — Run keys / autostart (ASEP).
// ⚠ Falcon's registry-autostart event is AsepValueUpdate, not yet seen in this repo's
//   onboarded clients — confirm via discovery before relying on Sub-query A:
//     * | groupBy(@event_simpleName, function=count())   (look for Asep*/Reg* events)
//   Sub-query B is the reliable fallback: reg.exe / PowerShell writes to autostart keys.

// --- Sub-query A: Registry autostart writes (Falcon AsepValueUpdate — confirm fields) ---

#event_simpleName=AsepValueUpdate
| ComputerName = /{{device_name}}/i
| table([@timestamp, ComputerName, RegObjectName, RegValueName, RegStringValue], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: reg.exe / PowerShell writes to autostart keys (fallback) ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(reg|powershell|pwsh)\.exe$/i
| CommandLine = /CurrentVersion\\Run|RunOnce|Winlogon|Image File Execution Options|Policies\\Explorer\\Run|Windows\\Load/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)
