// Ransomware Stage 1 — Shadow-copy & recovery tampering (MITRE T1490).
// Source: CrowdStrike Falcon ProcessRollup2 — CommandLine analysis of the recovery-
//   inhibition LOLBins is the reliable cross-platform signal.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(vssadmin|wbadmin|bcdedit|wmic|cipher|diskshadow|powershell|pwsh)\.exe$/i
| CommandLine = /delete shadows|delete catalog|resize shadowstorage|shadowcopy delete|win32_shadowcopy|recoveryenabled no|bootstatuspolicy ignoreallfailures|wbadmin delete|deletecatalog|\/purge/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine,
         ParentBaseFileName, ParentCommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
