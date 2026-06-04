// --- Sub-query A: IP — CrowdStrike Falcon network connections ---
// Replace IP_LIST values with the suspect IPs.

#event_simpleName=NetworkConnectIP4
| in(RemoteAddressIP4, values=[{{iocs_ip}}])
| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort,
         FileName, CommandLine, UserName, LocalAddressIP4])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query B: IP — CrowdStrike Falcon DNS resolution ---
// Check if any suspect IPs appeared in DNS A-record responses.

#event_simpleName=DnsRequest
| in(IP4Records, values=[{{iocs_ip}}])
| table([@timestamp, ComputerName, DomainName, IP4Records,
         FileName, ContextProcessId])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query C: IP — Entra ID sign-in logs ---
// Check if any suspect IPs were used for authentication.

#event.module=entraid #event.dataset="entraid.signin"
| in(source.ip, values=[{{iocs_ip}}])
| table([@timestamp, Vendor.properties.userPrincipalName, source.ip,
         Vendor.properties.appDisplayName, Vendor.properties.status.errorCode,
         Vendor.properties.riskLevelDuringSignIn,
         Vendor.properties.location.city, Vendor.properties.location.countryOrRegion])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query D: IP — Fortinet FortiGate firewall ---
// Check if suspect IPs appear in firewall traffic. Adjust tags for other vendors.

#Vendor="fortinet" #event.module=fortinet
| in(source.ip, values=[{{iocs_ip}}]) OR in(destination.ip, values=[{{iocs_ip}}])
| table([@timestamp, source.ip, destination.ip, destination.port,
         event.action, network.direction, observer.name,
         source.geo.country_name, Vendor.app])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query E: Domain — CrowdStrike Falcon DNS requests ---
// Replace DOMAIN_LIST values with the suspect domains.

#event_simpleName=DnsRequest
| in(DomainName, values=[{{iocs_domain}}])
| table([@timestamp, ComputerName, DomainName, IP4Records,
         FileName, ContextProcessId, UserName])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query F: Hash — CrowdStrike Falcon file/process events ---
// Replace HASH_LIST values with the suspect SHA256 hashes.

#event_simpleName=/^(ProcessRollup2|NewExecutableWritten|SyntheticProcessRollup2)$/
| in(SHA256HashData, values=[{{iocs_hash}}])
| table([@timestamp, ComputerName, FileName, CommandLine, FilePath,
         SHA256HashData, ParentBaseFileName, UserName])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query G: CrowdStrike detections mentioning IOCs ---

#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| SHA256HashData = "{{iocs_hash}}" OR CommandLine = /{{iocs_domain}}/i OR CommandLine = /{{iocs_ip}}/i
| table([@timestamp, ComputerName, DetectName, DetectDescription,
         Severity, FileName, CommandLine, SHA256HashData,
         Tactic, Technique])
| sort(@timestamp, order=desc)
| head(50)
