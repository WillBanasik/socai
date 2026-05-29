// Defence Evasion Stage 3 — Defensive-tool process kills.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(taskkill|ntsd|pskill|pskill64|powershell|pwsh)\.exe$/i
| CommandLine = /MsMpEng|MsSense|SenseIR|CSFalcon|cylancesvc|SentinelAgent|SentinelOne|sophos|carbonblack|cb\.exe|xagt|SecurityHealthService|windefend/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=desc, limit=200)
