// Insider / Data Staging Stage 2 — Local staging / archiving.

// --- Sub-query A: Archive tooling via process telemetry ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(rar|winrar|7z|7za|zip|tar|makecab|powershell|pwsh)\.exe$/i
| CommandLine = /\ba\b|-hp|Compress-Archive|-mx|\s-r\s|makecab|\.rar|\.7z|\.zip/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Archive files written to disk ---

#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /\.(rar|7z|zip|tar|gz|cab)$/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
