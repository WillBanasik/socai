// Persistence Stage 4 — WMI event subscriptions.
// ⚠ Falcon WMI-subscription telemetry is not in this repo's vocabulary; this uses
//   ProcessRollup2 for wmic / PowerShell creating __EventFilter / EventConsumer /
//   FilterToConsumerBinding objects.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(wmic|powershell|pwsh)\.exe$/i
| CommandLine = /__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding|Register-WmiEvent|Set-WmiInstance/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=asc, limit=200)
