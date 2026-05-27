// LOLBin C2 callbacks - LOLBins calling out to non-Microsoft destinations on
// non-standard ports, with parent-process context.
#event_simpleName=NetworkConnectIP4
| ComputerName = /{{device_name}}/i
| RemoteAddressIP4 != /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/
| FileName = /^(powershell\.exe|pwsh\.exe|rundll32\.exe|mshta\.exe|wscript\.exe|cscript\.exe|certutil\.exe|regsvr32\.exe|bitsadmin\.exe|msbuild\.exe|installutil\.exe|msiexec\.exe)$/i
| !in(RemotePort, values=["80", "443", "53", "123", "389", "636"])
| groupBy([ComputerName, FileName, ParentBaseFileName, RemoteAddressIP4, RemotePort],
          function=[count(as=Connections), collect([CommandLine], limit=3)])
| sort(Connections, order=desc)
