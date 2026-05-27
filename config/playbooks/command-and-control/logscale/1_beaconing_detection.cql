// Beaconing detection - repeated outbound callbacks from LOLBins to a single
// remote IP. NetworkConnectIP4 carries no byte counts; this surfaces high-
// repetition destinations and their rough cadence (Span / Connections). For
// true interval-jitter analysis, export the per-connection timestamps for a
// candidate RemoteAddressIP4 and inspect the spacing directly.
#event_simpleName=NetworkConnectIP4
| ComputerName = /{{device_name}}/i
| RemoteAddressIP4 != /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/
| FileName = /^(powershell\.exe|pwsh\.exe|rundll32\.exe|mshta\.exe|wscript\.exe|cscript\.exe|certutil\.exe|regsvr32\.exe|bitsadmin\.exe|msbuild\.exe|installutil\.exe|msiexec\.exe)$/i
| groupBy([ComputerName, FileName, RemoteAddressIP4, RemotePort],
          function=[count(as=Connections), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| SpanSec := (LastSeen - FirstSeen) / 1000
| AvgIntervalSec := SpanSec / Connections
| Connections >= 6
| sort(Connections, order=desc)
