// ---
// name: IOC Hunt
// description: >
//   Fast IOC presence sweep across LogScale data sources. Stage 1 runs
//   targeted queries against CrowdStrike Falcon (network, DNS, process),
//   Azure AD sign-in logs, and firewall logs to determine whether any of
//   the supplied IOCs have been seen. Stage 2 is a conditional context
//   pivot around hits. Time scope is controlled by the LogScale search
//   time picker.
// parameters:
//   - name: iocs_ip
//     type: string
//     description: Comma-separated suspicious IP addresses
//   - name: iocs_domain
//     type: string
//     description: Comma-separated suspicious domains
//   - name: iocs_hash
//     type: string
//     description: Comma-separated suspicious SHA256 hashes
//   - name: hit_host
//     type: string
//     description: ComputerName from Stage 1 hit (used in Stage 2)
//   - name: hit_ip
//     type: string
//     description: RemoteAddressIP4 or source.ip from Stage 1 hit (used in Stage 2)
// stages:
//   - stage: 1
//     name: IOC presence sweep
//     description: Targeted queries per IOC type across available LogScale data sources
//     run: always
//   - stage: 2
//     name: Context pivot
//     description: Pull surrounding activity from the host or source where Stage 1 found hits
//     run: when Stage 1 returns hits
// data_sources:
//   - CrowdStrike Falcon (NetworkConnectIP4, DnsRequest, ProcessRollup2, NewExecutableWritten)
//   - Azure AD Sign-In Logs (azure.signinlogs)
//   - Fortinet FortiGate (firewall traffic)
//   - UNAVAILABLE: SecurityAlert (Sentinel — CrowdStrike detections used instead)
//   - UNAVAILABLE: CommonSecurityLog (replaced by vendor-specific firewall queries)
// ---


// ============================================================================
// STAGE 1 — IOC presence sweep
// ============================================================================
// Parameters: iocs_ip, iocs_domain, iocs_hash
// Run: ALWAYS — run each sub-query for the relevant IOC types.
// Returns: one or more hits per IOC with source context.

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


// --- Sub-query C: IP — Azure AD sign-in logs ---
// Check if any suspect IPs were used for authentication.

#event.dataset="azure.signinlogs"
| in(source.ip, values=[{{iocs_ip}}])
| table([@timestamp, Vendor.properties.userPrincipalName, source.ip,
         Vendor.properties.appDisplayName, Vendor.properties.status.errorCode,
         Vendor.properties.riskLevelDuringSignIn,
         Vendor.properties.location.city, Vendor.properties.location.countryOrRegion])
| sort(@timestamp, order=desc)
| head(50)


// --- Sub-query D: IP — Fortinet FortiGate firewall ---
// Check if suspect IPs appear in firewall traffic. Adjust tags for other vendors.

#Vendor="fortinet" #event.module=fortigate
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


// ============================================================================
// STAGE 2 — Context pivot
// ============================================================================
// Parameters: hit_host (ComputerName from Stage 1), hit_ip (optional)
// Run: when Stage 1 returns hits. Pulls surrounding activity for the affected host.
// Purpose: understand what else happened on the same host around the time of the IOC hit.
// NOTE: Set the LogScale time picker to a 1-hour window around the hit timestamp.

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
