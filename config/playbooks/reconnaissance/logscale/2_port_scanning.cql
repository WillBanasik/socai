// Port / service scanning - a single external source touching many hosts/ports.
// Inbound connections on the Falcon endpoint sensor are logged as
// NetworkReceiveAcceptIP4; NetworkConnectIP4 is included for environments that
// only surface the outbound side of the handshake.
#event_simpleName=/^(NetworkReceiveAcceptIP4|NetworkConnectIP4)$/
| RemoteAddressIP4 != /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/
| groupBy([RemoteAddressIP4],
          function=[count(as=Connections),
                    count(field=ComputerName, distinct=true, as=DistinctHosts),
                    count(field=LocalPort, distinct=true, as=DistinctPorts),
                    collect([LocalPort], limit=50)])
| DistinctPorts >= 10 OR DistinctHosts >= 5
| sort(DistinctPorts, order=desc)
