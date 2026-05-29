// Insider / Data Staging Stage 4 — Mass print / cloud egress.
// ⚠ Falcon has no print-job telemetry in this repo's vocabulary — the print portion is
//   Defender-only. This covers personal-cloud egress via DNS + network connections.

// --- Sub-query A: DNS lookups to personal file-sharing services ---

#event_simpleName=DnsRequest
| ComputerName = /{{device_name}}/i
| DomainName = /dropbox|wetransfer|mega\.nz|drive\.google|sendspace|anonfiles|gofile|mediafire|pastebin/i
| groupBy([ComputerName, DomainName], function=[
    count(as=Lookups),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(Lookups, order=desc, limit=200)


// --- Sub-query B: Outbound connections from the host (correlate with A) ---

#event_simpleName=NetworkConnectIP4
| ComputerName = /{{device_name}}/i
| RemoteAddressIP4 != /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)/
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=[
    count(as=ConnCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(ConnCount, order=desc, limit=200)
