// Data Exfiltration Stage 3 — Network exfiltration indicators.
// Goal: external data-transfer destinations and copies to removable/cloud paths.
// Source: CrowdStrike Falcon endpoint telemetry (the NG-SIEM equivalent of Sentinel
//   DeviceNetworkEvents / DeviceFileEvents). Identify the user's device(s) first
//   (e.g. via account-compromise Stage 3/4 UserLogon), then scope these by
//   ComputerName. RFC1918 destinations are excluded via regex below.

// --- Sub-query A: Outbound connections to external hosts on common exfil ports ---

#event_simpleName=NetworkConnectIP4
| in(field=RemotePort, values=[443, 80, 22, 21, 445])
| RemoteAddressIP4 != /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)/
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=[
    count(as=ConnectionCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(ConnectionCount, order=desc, limit=200)


// --- Sub-query B: File operations to removable / cloud-sync paths ---

#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| TargetFileName = /usb|removable|external|onedrive|dropbox|google drive|googledrive/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=desc, limit=200)
