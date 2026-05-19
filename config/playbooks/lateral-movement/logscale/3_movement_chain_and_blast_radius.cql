// --- Sub-query A: Second-hop outbound connections (per destination host) ---
// Replace FIRST_HOP_HOST with each destination from Stage 1.

#event_simpleName=NetworkConnectIP4
| ComputerName = /FIRST_HOP_HOST/i
| in(RemotePort, values=["3389", "445", "135", "5985", "5986", "22"])
| RemoteAddressIP4 != "127.0.0.1"
| Protocol := case {
    RemotePort = "3389" | "RDP";
    RemotePort = "445"  | "SMB";
    RemotePort = "135"  | "WMI/DCOM";
    RemotePort = "5985" | "WinRM";
    RemotePort = "5986" | "WinRM";
    RemotePort = "22"   | "SSH";
    * | RemotePort;
  }
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort, Protocol,
         FileName, CommandLine, UserName])
| sort(@timestamp, order=asc)


// --- Sub-query B: Logons on second-hop hosts from first-hop hosts ---
// Replace FIRST_HOP_IP with the IP of each first-hop destination.

#event_simpleName=UserLogon
| RemoteAddressIP4 = "FIRST_HOP_IP"
| in(LogonType, values=["3", "10"])
| table([@timestamp, ComputerName, UserName, LogonType, LogonDomain,
         RemoteAddressIP4, AuthenticationPackage])
| sort(@timestamp, order=asc)
| head(50)
