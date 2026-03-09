# MDR Incident Report
### Suspicious CPL Execution via Internal OneDrive Share — User `cpithoi` on Host `FRACFGVS03T3` | Florian Mages' OneDrive as Delivery Vector

---

## 1. Executive Summary

On 9 March 2026 at 14:34 UTC, user `camille.pithois@heidelbergmaterials.com` (username `cpithoi`) on host `FRACFGVS03T3` downloaded three `.cpl` (Control Panel) files from the OneDrive of internal user `florian.mages@heidelbergmaterials.com` and executed at least one. The execution triggered a CrowdStrike Falcon detection for **System Binary Proxy Execution (T1218.002)** as `rundll32.exe` loaded the CPL via `Shell32.dll,Control_RunDLL`. The detection was not blocked (PatternDisposition: 0). The process ran to completion with exit code 0.

The CPL files were located in Mages' OneDrive folder `2026 - Acculturation IA/` alongside legitimate training documents. Mages sent two Teams messages containing links at 14:08–14:09 UTC; the user browsed Mages' OneDrive file listing at 14:33:13 UTC and began downloading files at 14:34:49 UTC.

No upload event for the CPL files was found in the available audit data. **It has not been determined whether Mages' account or endpoint is compromised, or whether the CPL files are malicious.** The CPL file hashes were not captured by MDE. Further investigation is required — specifically into Mages' account, device, and the CPL files themselves.

A KnowBe4 phishing simulation email (campaign 418614541) was also delivered to the user at 10:09 UTC on the same day. Investigation confirmed this email is **unrelated** to the CPL file downloads — CrowdStrike DNS telemetry and MDE network events during the download window show exclusively Microsoft 365 infrastructure and zero connections to KnowBe4 domains.

---

## 2. Low-Level Technical Narrative

### Delivery — OneDrive File Share via Teams

At 08:09:14 UTC, `florian.mages@heidelbergmaterials.com` sent an email to `cpithoi` with subject "E-learning Copilot : script + Captivate". The email contained Teams meeting links and a SharePoint conference page URL. No OneDrive file share link was present in this email (confirmed via `EmailUrlInfo` for NetworkMessageId `a8dba2d6-1390-4614-7d1e-08de7db32473`).

At 14:08:59 and 14:09:49 UTC, Mages sent two Teams messages containing links (`OfficeActivity` — `MessageCreatedHasLink`). The content of these messages was not available in the audit data. At 14:33:13 UTC — approximately 24 minutes later — the user accessed Mages' OneDrive file listing:

| Time (UTC) | Operation | File / Object | Source |
|---|---|---|---|
| 14:33:13 | FileAccessed | `All.aspx` (folder listing) | `OfficeActivity` |
| 14:34:49 | **FileDownloaded** | **`~Formation IA.cpl`** | `OfficeActivity` |
| 14:35:05 | **FileDownloaded** | **`~Sans titre1.cpl`** | `OfficeActivity` |
| 14:35:16 | FileAccessed | `One Pager use case IA.docx` | `OfficeActivity` |
| 14:35:23 | FilePreviewed | `One Pager use case IA.docx` | `OfficeActivity` |
| 14:35:40 | **FileDownloaded** | **`~Formation IA.cpl`** (second download) | `OfficeActivity` |

All file activity was from the same OneDrive path:

```
https://hcgroupnet-my.sharepoint.com/personal/florian_mages_heidelbergmaterials_com/
  Documents/Documents/2026 - Acculturation IA/
```

The folder contained both CPL files and at least one legitimate document (`One Pager use case IA.docx`), which the user accessed and previewed in the same session. The CPL file names use French-language labels: "Formation IA" (AI Training) and "Sans titre" (Untitled).

All downloads were from ClientIP `170.85.0.177`, the known external IP for host `FRACFGVS03T3`.

### Download — MDE File Events

MDE `DeviceFileEvents` recorded the corresponding file creation on the endpoint:

| Time (UTC) | Action | File | Path |
|---|---|---|---|
| 14:34:50 | FileCreated / FileRenamed | `_Formation IA.cpl` | `C:\Users\cpithoi\Downloads\` |
| 14:35:05 | FileCreated / FileRenamed | `_Sans titre1.cpl` | `C:\Users\cpithoi\Downloads\` |
| 14:35:40 | FileCreated / FileRenamed | `_Formation IA (1).cpl` | `C:\Users\cpithoi\Downloads\` |

MDE did not capture SHA256 hashes or `FileOriginUrl` for any of the CPL downloads. A legitimate PDF (`AttestationDeDroits_2026-03-09.pdf`) downloaded from `assure.ameli.fr` earlier the same day had full hash and origin metadata, confirming the gap is specific to the CPL file type.

The initiating process for all downloads was `msedge.exe`. The Edge quarantine utility subprocess (`quarantine.mojom.Quarantine`) processed each file, indicating the browser's standard download pipeline handled them. Browser language was set to French (`--lang=fr`).

### Network Telemetry — Download Window

CrowdStrike `DnsRequest` events and MDE `DeviceNetworkEvents` for host `FRACFGVS03T3` during the download window (14:34:00–14:36:00 UTC) were reviewed in full. **Every DNS resolution and network connection was to Microsoft 365 infrastructure:**

| Domain | Service |
|---|---|
| `substrate.office.com` | SharePoint / OneDrive API |
| `dataservice.protection.outlook.com` | Outlook / Defender scanning |
| `webshell.suite.office.com` | Office web shell |
| `graph.microsoft.com` | Microsoft Graph API |
| `spo.nel.measure.office.net` | SharePoint Online measurement |
| `res-1.cdn.office.net` / `res.cdn.office.net` | Office CDN |
| `clients.config.office.net` | Office configuration |
| `login.microsoftonline.com` | Azure AD authentication |
| `loki.delve.office.com` | Delve |
| `editor.svc.cloud.microsoft` | Microsoft Editor |
| Various `fa000000XXX.resources.office.net` | Office add-in resources |

**Zero DNS resolutions or connections to any non-Microsoft domain were observed.** No connections to `kb4.io`, `knowbe4.com`, or any other external infrastructure occurred during the download window. One connection to IP `172.211.159.152` (Azure) from a unique process ID was identified as `smartscreen.exe` (SHA256: `8c1223d98490f70326aa68f96b03618d9a522822e951f487c183828c58f52500`), spawned by `svchost.exe` at 14:34:47 UTC to perform a file reputation check on the downloaded CPL.

### Execution

The user opened at least one CPL file. Opening a `.cpl` file invokes the Windows Control Panel handler, which spawns `rundll32.exe` to load the file as a DLL:

**Process Tree:**
```
msedge.exe
  > msedge.exe
    > control.exe (SHA256: af2eacc5a433d5581a784a350451215b5a0fa958af93e76ce78ec07782caa067)
      > rundll32.exe (PID 8140, SHA256: f94fab1ee2ed77229edb12abd95b00f25f08b92f9bcfc872ce5cb06b52fbb5f9)
```

**Command Line:**
```
"C:\WINDOWS\system32\rundll32.exe" Shell32.dll,Control_RunDLL "C:\Users\cpithoi\Downloads\_Formation IA.cpl"
```

| Field | Value |
|---|---|
| TargetProcessId | 650106292949 |
| TreeId | 193273955766 |
| ProcessStartTime | 1773066893.276 (~14:34:53 UTC) |
| ExitCode | 0 |
| ImageSubsystem | 2 (GUI) |
| IntegrityLevel | 8192 (Medium) |
| UserIsAdmin | 0 |
| PatternDisposition | 0 (Detect only — not blocked) |

CrowdStrike tagged the `ProcessRollup2` event with **Tactic: Defence Evasion** and **Technique: System Binary Proxy Execution (T1218.002)**. Detection PatternId `10186`, TemplateId `41`.

Twenty `ClassifiedModuleLoad` events were recorded. All loaded DLLs were legitimate Windows system libraries (ntdll, kernel32, KernelBase, combase, shell32, user32, gdi32, ole32, msvcrt, ucrtbase, rpcrt4, shlwapi, imm32, msctf, uxtheme, apphelp, SHCore, WinTypes, bcryptprimitives, imagehlp, kernel.appcore, win32u, msvcp_win, gdi32full, umppc20403). No anomalous or unsigned third-party modules were observed.

The process executed and terminated normally (ExitCode 0) within approximately 3 seconds.

### User Context

| Field | Value |
|---|---|
| UserName | cpithoi |
| UserPrincipal | camille.pithois@heidelbergmaterials.com |
| UserSid | S-1-12-1-190501076-1248857303-1915422350-2915853989 |
| LogonDomain | GROUPHC |
| AuthenticationPackage | CloudAP (Azure AD) |
| LogonType | 2 (Interactive) |
| RemoteAccount | 1 |
| SessionId | 1 |

### Unrelated KnowBe4 Phishing Simulation

A KnowBe4 phishing simulation was delivered to the same user at 10:09:44 UTC on 9 March 2026:

| Field | Value |
|---|---|
| Sender | `assistance@heidelbergmaterals.com` (typosquat — missing "i") |
| Subject | L'un de vos appareils n'est pas conforme |
| InternetMessageId | `<18dd7903b.10ffe12b6@psm.knowbe4.com>` |
| Authentication | SPF: pass, DKIM: pass, DMARC: none, CompAuth: fail |
| Body URLs | Three links to `https.www.secure.kb4.io` (campaign ID `418614541`) |

This email was initially assessed as the delivery vector for the CPL files based on temporal proximity. This attribution was subsequently disproven by CrowdStrike DNS and MDE network telemetry, which showed zero connections to KnowBe4 infrastructure during the download window. The KnowBe4 simulation and the CPL execution are two independent events. Whether the user interacted with the KnowBe4 email is not determinable from the data reviewed.

---

## 3. Evidence Correlation

| Pivot Point | Value | Links |
|---|---|---|
| OneDrive Source | `florian_mages_heidelbergmaterials_com/.../2026 - Acculturation IA/` | OfficeActivity (FileDownloaded) → DeviceFileEvents (FileCreated) → CrowdStrike ProcessRollup2 (CommandLine) |
| File Name | `~Formation IA.cpl` (OneDrive) = `_Formation IA.cpl` (local) | OfficeActivity SourceFileName → DeviceFileEvents FileName (tilde replaced by underscore on download) |
| Host | `FRACFGVS03T3` | DeviceFileEvents, DeviceNetworkEvents, CrowdStrike telemetry (ComputerName) |
| User Identity | `cpithoi` / `camille.pithois@heidelbergmaterials.com` / `S-1-12-1-190501076-...` | OfficeActivity (UserId) → CrowdStrike UserIdentity (UserPrincipal, UserSid) |
| ClientIP / ExternalIP | `170.85.0.177` | OfficeActivity (ClientIP) → CrowdStrike (aip) |
| Process Chain | `msedge.exe` → `control.exe` → `rundll32.exe` | CrowdStrike ProcessAncestryInformation |
| CrowdStrike Agent | `5a0c40b16b3544fe955e626efff60e92` | Ties all CrowdStrike events to single endpoint |
| Teams Delivery | Mages `MessageCreatedHasLink` at 14:08–14:09 → user browsed OneDrive at 14:33 | OfficeActivity (Teams) → OfficeActivity (SharePoint) |
| DNS Confirmation | Zero non-Microsoft DNS during download window | CrowdStrike DnsRequest — rules out external delivery |

---

## 4. Key IOCs

| Type | Value | Context |
|---|---|---|
| File | `~Formation IA.cpl` | Downloaded from Mages' OneDrive. Written to disk as `_Formation IA.cpl`. **Hash unknown** — not captured by MDE. |
| File | `~Sans titre1.cpl` | Downloaded from Mages' OneDrive. Written to disk as `_Sans titre1.cpl`. **Hash unknown**. |
| OneDrive Path | `/personal/florian_mages_heidelbergmaterials_com/Documents/Documents/2026 - Acculturation IA/` | Folder containing CPL files alongside legitimate documents. |
| Account | `florian.mages@heidelbergmaterials.com` | OneDrive owner. Sent Teams messages with links at 14:08–14:09 UTC. Account/endpoint compromise status unknown. |

> **Note:** The rundll32.exe and control.exe hashes in Section 2 are legitimate Microsoft binaries. The `heidelbergmaterals.com` domain (KnowBe4 simulation) is unrelated to the CPL delivery and is not treated as an IOC for this incident.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detail |
|---|---|---|---|
| Initial Access | Trusted Relationship / Valid Accounts | T1199 / T1078 | CPL files hosted in internal user's OneDrive, shared via Teams |
| Execution | User Execution: Malicious File | T1204.002 | User downloaded and opened CPL file |
| Defence Evasion | System Binary Proxy Execution: Control Panel | T1218.002 | CPL executed via `rundll32.exe Shell32.dll,Control_RunDLL` |

---

## 6. Plain-Language Security Risk Explanation

A user downloaded and executed Control Panel files (`.cpl`) from a colleague's OneDrive folder that appeared to contain legitimate AI training materials. CPL files are DLLs that execute arbitrary code through `rundll32.exe` when opened — a technique that bypasses basic file-type awareness and leverages a trusted Windows binary for execution.

The files were hosted in the OneDrive of `florian.mages@heidelbergmaterials.com`, in a folder named `2026 - Acculturation IA/` alongside at least one genuine document (`One Pager use case IA.docx`). The user browsed this folder and downloaded both the CPL files and the legitimate document in the same session. The delivery appears to have been facilitated by Teams messages sent by Mages shortly before.

CrowdStrike detected the execution but did not block it (detect-only disposition). The process ran to completion with exit code 0. The CPL file hashes were not captured by any available telemetry source, so the files have not been assessed for malicious content.

The key unresolved question is how the CPL files came to be in Mages' OneDrive. Either his account was compromised and an attacker planted them among legitimate content, or his endpoint is compromised and the files were synced to OneDrive via the desktop client. In either scenario, any user with access to the shared folder is at risk of downloading and executing the CPL files.

---

## 7. What Was NOT Observed

The following activity was **not** observed within the available evidence:

- **No outbound network connections** from the `rundll32.exe` process were present in the CrowdStrike telemetry reviewed
- **No persistence mechanisms** were established (no registry modifications, scheduled tasks, or service creation)
- **No lateral movement** was detected
- **No credential access or privilege escalation** was observed
- **No anomalous or unsigned module loads** — all DLLs loaded by `rundll32.exe` were legitimate Windows system libraries
- **No upload event** for the CPL files was found in `OfficeActivity` for Mages' account within the queried timeframe (1–10 March 2026)
- **No connection to KnowBe4 infrastructure** was observed during the download window — the phishing simulation email is confirmed unrelated

> **Important caveat:** The CrowdStrike event export reviewed covered process, module load, user identity, process ancestry, and DNS events. MDE telemetry covered file events and network events. The `OfficeActivity` upload search may be limited by audit log retention or the upload method (OneDrive sync client events may not appear in this table). The absence of post-exploitation indicators does not confirm the CPL files are benign — the file hashes are unknown and the files have not been analysed.

---

## 8. Recommendations

**Immediate — the following actions require client execution:**

1. **Recover the CPL files from Mages' OneDrive** (`2026 - Acculturation IA/` folder) and from `cpithoi`'s Downloads folder (`C:\Users\cpithoi\Downloads\`). Obtain SHA256 hashes and submit for analysis (sandbox detonation, AV scanning, manual reverse engineering). Until the files are assessed, **treat as potentially malicious**.

2. **Restrict access to Mages' OneDrive folder** `2026 - Acculturation IA/` immediately. Any user who accessed this folder may have downloaded the CPL files. Audit the SharePoint access logs for this folder to identify other affected users.

3. **Investigate Florian Mages' account and endpoint.** Determine:
   - When the CPL files were uploaded (widen `OfficeActivity` audit search beyond 10 days, check OneDrive sync logs on his device)
   - From what IP/device the upload occurred
   - Whether his account shows signs of compromise (anomalous sign-ins, impossible travel, MFA changes)
   - Whether his endpoint shows signs of compromise (CrowdStrike detections, suspicious process activity)
   - Identify his device name via `DeviceInfo` or Entra ID and review its telemetry

4. **Contain host `FRACFGVS03T3`** if the CPL files are confirmed malicious. The payload executed successfully (ExitCode 0) and CrowdStrike did not block it.

**Short-term:**

5. **Review CrowdStrike prevention policy** for the host group containing `FRACFGVS03T3`. PatternDisposition `0` (detect only) for T1218.002 means CPL-based execution from user-writable paths is not blocked. Consider enabling prevention for CPL execution from Downloads, Desktop, Temp, and AppData.

6. **Investigate the MDE telemetry gap.** SHA256 hashes and `FileOriginUrl` were not captured for the CPL downloads. Determine whether this is a known limitation for this file type or a configuration issue, and assess compensating controls (e.g. `DeviceImageLoadEvents` custom detection rules for non-System32 DLLs loaded by `rundll32.exe`).

7. **Check whether the Teams messages from Mages at 14:08–14:09 were sent by Mages or by a threat actor with access to his account.** Review the Teams audit for message content if available, and cross-reference with Mages' sign-in activity at that time.

---

**Classification: Suspicious — Pending Investigation**
**Confidence Level: Medium**

The CPL files were delivered through a legitimate internal OneDrive share. It has not been determined whether the files are malicious. The origin of the CPL files in Mages' OneDrive is unknown — no upload event was found in the available audit data. Until the CPL file hashes are obtained and assessed, and Mages' account and endpoint are investigated, this incident cannot be closed. The execution was not blocked by CrowdStrike.
