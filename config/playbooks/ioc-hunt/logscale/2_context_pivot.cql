// --- Sub-query A: All process activity on the hit host ---

#event_simpleName=ProcessRollup2
| ComputerName = /{{hit_host}}/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine,
         SHA256HashData, ParentBaseFileName, TargetProcessId])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query B: Network connections from the hit host ---

#event_simpleName=NetworkConnectIP4
| ComputerName = /{{hit_host}}/i
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort,
         FileName, CommandLine, LocalAddressIP4])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query C: DNS requests from the hit host ---

#event_simpleName=DnsRequest
| ComputerName = /{{hit_host}}/i
| table([@timestamp, ComputerName, DomainName, IP4Records, FileName])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query D: File writes on the hit host ---

#event_simpleName=/^(NewExecutableWritten|NewScriptWritten|GenericFileWritten)$/
| ComputerName = /{{hit_host}}/i
| table([@timestamp, ComputerName, TargetFileName, FilePath,
         SHA256HashData, FileName, CommandLine, UserName])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query E: Azure AD sign-ins from the hit IP ---
// Only run if the Stage 1 hit was an IP-based IOC against Azure sign-in logs.

#event.dataset="azure.signinlogs"
| source.ip = "{{hit_ip}}"
| table([@timestamp, Vendor.properties.userPrincipalName, source.ip,
         Vendor.properties.appDisplayName, Vendor.properties.status.errorCode,
         Vendor.properties.riskLevelDuringSignIn, Vendor.properties.isInteractive,
         Vendor.properties.deviceDetail.displayName])
| sort(@timestamp, order=desc)
| head(50)
