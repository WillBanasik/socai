// ---
// name: Lateral Movement Investigation
// description: >
//   Multi-stage lateral movement investigation using CrowdStrike Falcon
//   sensor telemetry. Stage 1 identifies RDP, SMB, WMI, PsExec, WinRM,
//   and SSH connections from the compromised host. Stage 2 checks for
//   credential access tools on source and destination hosts. Stage 3
//   traces secondary hops to map the full blast radius.
//   Time scope is controlled by the LogScale search time picker.
// parameters:
//   - name: source_host
//     type: string
//     description: Initially compromised hostname (ComputerName)
//   - name: source_user
//     type: string
//     description: Compromised user account (optional)
//   - name: destination_hosts
//     type: string
//     description: Comma-separated destination hosts from Stage 1 (used in Stages 2-3)
// stages:
//   - stage: 1
//     name: Lateral movement connections
//     description: RDP, SMB, WMI, PsExec, WinRM, and SSH connections from the source host
//     run: always
//   - stage: 2
//     name: Credential access on movement path
//     description: LSASS access, credential dumping tools, and CrowdStrike detections on source and destination hosts
//     run: when Stage 1 identifies lateral connections
//   - stage: 3
//     name: Movement chain and blast radius
//     description: Multi-hop movement tracing to map the full blast radius from first-hop destinations
//     run: when Stage 2 confirms credential access or Stage 1 shows multiple destinations
// definitions:
//   - term: Lateral Movement
//     definition: Techniques where an adversary moves from one system to another within the network, typically using legitimate remote access protocols (RDP, SMB, WMI) with stolen or escalated credentials.
//   - term: Blast Radius
//     definition: The total set of systems and accounts accessed by the adversary from the initial point of compromise, including all intermediate hops.
// data_sources:
//   - CrowdStrike Falcon (NetworkConnectIP4, ProcessRollup2, UserLogon, DetectionSummaryEvent)
//   - UNAVAILABLE: IdentityLogonEvents (MDI — Kerberos anomaly detection not available)
//   - UNAVAILABLE: SecurityAlert (Sentinel — CrowdStrike detections used instead)
// ---


// ============================================================================
// STAGE 1 — Lateral movement connections
// ============================================================================
// Parameters: source_host, source_user (optional)
// Run: ALWAYS — identify all lateral movement from the source host.
// Returns: outbound connections on lateral movement ports and lateral tool execution.

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


// ============================================================================
// STAGE 2 — Credential access on movement path
// ============================================================================
// Parameters: source_host, destination_hosts (comma-separated from Stage 1)
// Run: when Stage 1 identifies lateral connections.
// Purpose: detect credential theft techniques on source and destination hosts.
// NOTE: Run sub-query A once per host (source + each destination).

// --- Sub-query A: Credential dumping tools (per host) ---
// Replace HOST_NAME with each host to investigate.

#event_simpleName=ProcessRollup2
| ComputerName = /HOST_NAME/i
| FileName = /^(mimikatz\.exe|procdump\.exe|procdump64\.exe|nanodump\.exe|pypykatz)$/i OR CommandLine = /lsass.*MiniDump|lsass.*procdump|comsvcs.*lsass|sekurlsa|logonpasswords|SAM.*hive|SECURITY.*hive/i
| table([@timestamp, ComputerName, FileName, CommandLine, UserName,
         ParentBaseFileName, SHA256HashData])
| sort(@timestamp, order=desc)


// --- Sub-query B: LSASS access events (per host) ---
// CrowdStrike tracks LSASS access through specific detections.

#event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/
| ComputerName = /HOST_NAME/i
| DetectName = /credential|LSASS|pass.the.hash|kerberoast|golden.ticket|DCSync|lateral.movement|mimikatz|brute.force/i
| table([@timestamp, ComputerName, DetectName, DetectDescription,
         Severity, FileName, CommandLine, Tactic, Technique])
| sort(@timestamp, order=desc)


// --- UNAVAILABLE: MDI Kerberos anomaly detection ---
// Source: IdentityLogonEvents (Microsoft Defender for Identity)
// Not available in LogScale. Check Microsoft Defender for Identity portal
// for Kerberos protocol anomalies (overpass-the-hash, pass-the-ticket,
// golden ticket, silver ticket, encryption downgrade).


// ============================================================================
// STAGE 3 — Movement chain and blast radius
// ============================================================================
// Parameters: destination_hosts (from Stage 1)
// Run: when Stage 2 confirms credential access or Stage 1 shows multiple destinations.
// Purpose: trace secondary hops from first-hop destinations.
// NOTE: Run sub-query A once per first-hop destination host.

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
