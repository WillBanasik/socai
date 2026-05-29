// Defence Evasion Stage 2 — EDR / AV disablement & tamper.
// ⚠ Falcon sensor tamper/uninstall surfaces as DetectionSummaryEvent (Stage 4);
//   behavioural attempts are caught here via ProcessRollup2 command-line analysis.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| CommandLine = /Set-MpPreference.{0,40}-Disable|DisableRealtimeMonitoring|DisableBehaviorMonitoring|Add-MpPreference.{0,20}-ExclusionPath|sc.{0,5}(stop|config).{0,25}(windefend|sense|csagent)|fltMC.{0,10}unload|net stop.{0,25}(windefend|sense|csfalcon|sophos|cylance|sentinel)/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
| sort(@timestamp, order=desc, limit=200)
