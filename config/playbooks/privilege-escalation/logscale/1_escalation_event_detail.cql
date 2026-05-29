// Privilege Escalation Stage 1 — Escalation event detail.
// Covers cloud (Entra/AAD directory audit), on-prem AD (Windows security events),
//   and related detections — the three unioned sources of the Sentinel original.
// Params: {{actor_upn}} (who performed it), {{target_user}}, {{target_group}}
//   (__NONE__ when not applicable — the regex simply won't match).

// --- Sub-query A: Entra/AAD role & group changes (M365 unified audit log) ---
// AzureActiveDirectory operations flow through the verified m365 module.

#Vendor="microsoft" #event.module=m365
| Vendor.Workload = "AzureActiveDirectory"
| in(field=Vendor.Operation, values=["Add member to role", "Add member to group",
    "Add eligible member to role", "Add eligible member (permanent)",
    "Add member to role in PIM requested (permanent)", "Add member to role outside of PIM",
    "User activated eligible role", "Remove member from role", "Remove member from group"])
| Vendor.UserId = /{{actor_upn}}/i OR @rawstring = /{{target_user}}/i OR @rawstring = /{{target_group}}/i
| table([@timestamp, Vendor.Operation, Vendor.UserId, Vendor.ClientIP, Vendor.ResultStatus], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query B: On-prem AD group-membership changes (Windows security events) ---
// 4728 = added to global group, 4732 = domain-local, 4756 = universal
//   (4727/4731/4755 = group created/changed). SubjectUserName = actor, TargetUserName
//   = group, MemberName/MemberSid = the added principal (⚠ MemberName not in the
//   discovered sample — verify against the client repo if empty).

#Vendor="microsoft" #event.module=windows
| in(field=EventCode, values=["4728", "4732", "4756", "4727", "4731", "4755"])
| windows.EventData.SubjectUserName = /{{actor_upn}}/i OR windows.EventData.TargetUserName = /{{target_user}}/i OR windows.EventData.TargetUserName = /{{target_group}}/i
| table([@timestamp, EventCode, host.hostname, windows.EventData.SubjectUserName,
         windows.EventData.TargetUserName, windows.EventData.MemberName,
         windows.EventData.MemberSid], limit=200)
| sort(@timestamp, order=desc, limit=200)


// --- Sub-query C: Related detections (Defender AlertInfo) ---
// Sub-table discriminator is Vendor.Workload="AlertInfo" (see phishing Stage 0 header).
// Falcon alternative: #event_simpleName=/^(DetectionSummaryEvent|SensorDetectionSummary)$/

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "AlertInfo"
| @rawstring = /{{actor_upn}}/i OR @rawstring = /{{target_user}}/i
| table([@timestamp, Vendor.properties.Title, Vendor.properties.Severity,
         Vendor.properties.Category], limit=200)
| sort(@timestamp, order=desc, limit=200)
