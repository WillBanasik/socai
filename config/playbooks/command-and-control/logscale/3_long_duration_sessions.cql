// Long-duration, low-volume sessions - implant keep-alive. NetworkConnectIP4
// has no byte counts; approximate with a long first->last span and a low
// connection count to a single external destination (slow check-ins).
#event_simpleName=NetworkConnectIP4
| ComputerName = /{{device_name}}/i
| RemoteAddressIP4 != /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/
| groupBy([ComputerName, RemoteAddressIP4],
          function=[count(as=Connections), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| SpanHours := (LastSeen - FirstSeen) / 3600000
| ConnectionsPerHour := Connections / (SpanHours + 0.01)
| SpanHours >= 1 AND Connections >= 2 AND Connections <= 60 AND ConnectionsPerHour <= 12
| sort(SpanHours, order=desc)
