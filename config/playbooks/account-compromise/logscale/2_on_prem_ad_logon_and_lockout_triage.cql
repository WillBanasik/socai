// --- Sub-query A: Logon events summary (4624, 4625, 4771, 4776, 4768, 4769) ---

#Vendor="microsoft" #event.module=windows
| in(EventCode, values=["4624", "4625", "4771", "4776", "4768", "4769"])
| user.name = /{{username}}/i
| groupBy([windows.EventData.IpAddress, EventCode], function=[
    count(as=Count),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen),
    collect([host.hostname], limit=5)
  ])
| sort(Count, order=desc)


// --- Sub-query B: Failed logon detail (4625 — wrong password, locked out, etc.) ---

#Vendor="microsoft" #event.module=windows EventCode=4625
| user.name = /{{username}}/i
| table([@timestamp, host.hostname, user.name,
         windows.EventData.IpAddress, windows.EventData.SubStatus,
         windows.EventData.LogonType, windows.EventData.FailureReason])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query C: Account lockout events (4740) ---

#Vendor="microsoft" #event.module=windows EventCode=4740
| user.name = /{{username}}/i
| table([@timestamp, host.hostname, user.name,
         windows.EventData.TargetDomainName])
| sort(@timestamp, order=desc)
| head(100)


// --- Sub-query D: Kerberos pre-auth failures (4771) with status decode ---

#Vendor="microsoft" #event.module=windows EventCode=4771
| user.name = /{{username}}/i
| StatusDecode := case {
    windows.EventData.Status = "0x6"  | "Unknown principal";
    windows.EventData.Status = "0x12" | "Account locked/disabled/expired";
    windows.EventData.Status = "0x17" | "Password expired";
    windows.EventData.Status = "0x18" | "Wrong password";
    windows.EventData.Status = "0x25" | "Clock skew";
    * | windows.EventData.Status;
  }
| groupBy([windows.EventData.IpAddress, StatusDecode], function=[
    count(as=Count),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(Count, order=desc)
