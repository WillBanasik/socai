// --- Sub-query A: Outbound connections on lateral movement ports ---
// Ports: 3389=RDP, 445=SMB, 135=WMI/DCOM, 5985/5986=WinRM, 22=SSH, 23=Telnet

#event_simpleName=NetworkConnectIP4
| ComputerName = /{{source_host}}/i
| in(RemotePort, values=["3389", "445", "135", "5985", "5986", "22", "23"])
| RemoteAddressIP4 != "127.0.0.1"
| Protocol := case {
    RemotePort = "3389" | "RDP";
    RemotePort = "445"  | "SMB";
    RemotePort = "135"  | "WMI/DCOM";
    RemotePort = "5985" | "WinRM";
    RemotePort = "5986" | "WinRM";
    RemotePort = "22"   | "SSH";
    RemotePort = "23"   | "Telnet";
    * | RemotePort;
  }
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort, Protocol,
         FileName, CommandLine, UserName])
| sort(@timestamp, order=asc)


// --- Sub-query B: Lateral movement tool execution ---
// PsExec, WMI, WinRM, SSH, and remote task scheduling tools.

#event_simpleName=ProcessRollup2
| ComputerName = /{{source_host}}/i
| FileName = /^(psexec\.exe|psexec64\.exe|paexec\.exe|wmic\.exe|winrs\.exe|mstsc\.exe|ssh\.exe|plink\.exe|putty\.exe)$/i OR CommandLine = /Invoke-Command|Enter-PSSession|New-PSSession|wmic.*\/node|Invoke-WmiMethod|schtasks.*\/create.*\/s/i
| table([@timestamp, ComputerName, FileName, CommandLine, UserName,
         ParentBaseFileName, SHA256HashData])
| sort(@timestamp, order=desc)


// --- Sub-query C: Remote logons originating from the source host ---
// Look for UserLogon events where the remote IP matches the source host.
// NOTE: You need the source host's IP address for this query. Replace SOURCE_IP.

#event_simpleName=UserLogon
| RemoteAddressIP4 = "SOURCE_IP"
| in(LogonType, values=["3", "10"])
| table([@timestamp, ComputerName, UserName, LogonType, LogonDomain,
         RemoteAddressIP4, AuthenticationPackage])
| sort(@timestamp, order=asc)
| head(50)
