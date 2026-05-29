// Credential Access Stage 1 — LSASS access / credential dumping.
// ⚠ Falcon has no in-repo process-access/handle event, so this detects the dumping
//   TOOLING and behaviour via ProcessRollup2 CommandLine. Pair with Stage 4 detections
//   (CrowdStrike's CredentialDumping detections fire on the actual lsass handle).
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| FileName = /^(procdump|procdump64|rundll32|taskmgr|nanodump|sqldumper|werfault)\.exe$/i OR CommandLine = /lsass|comsvcs\.dll.{0,20}minidump|minidump|sekurlsa|mimikatz/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine,
         ParentBaseFileName, ParentCommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
