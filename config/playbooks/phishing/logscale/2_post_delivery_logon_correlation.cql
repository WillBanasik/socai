// Phishing Stage 2 — Post-delivery logon correlation.
// Goal (from the Sentinel original): for recipients of *delivered* phishing mail,
//   find an endpoint logon within ~30 minutes of delivery (possible compromise).
// Email side: Defender advanced-hunting EmailEvents (windows-defender-365).
// Logon side: Falcon endpoint logons (#event_simpleName=UserLogon) — the NG-SIEM
//   equivalent of Sentinel IdentityLogonEvents.
// CQL is join-free: run A, then run B filtered to the account(s) of interest and
//   correlate on AccountName + a 0–30 min window after the email DeliveryTime.

// --- Sub-query A: Delivered recipients (with derived AccountName) ---

#Vendor="microsoft" #event.dataset="windows-defender-365.event"
| Vendor.Workload = "EmailEvents"
| in(field=Vendor.properties.NetworkMessageId, values=[{{target_ids}}])
| Vendor.properties.DeliveryAction = "Delivered"
| regex("^(?<AccountName>[^@]+)@", field=Vendor.properties.RecipientEmailAddress)
| table([@timestamp, Vendor.properties.RecipientEmailAddress, AccountName,
         Vendor.properties.Subject, Vendor.properties.NetworkMessageId], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Endpoint logons for the recipient account(s) ---
// Replace the AccountName regex below with the account(s) surfaced by Sub-query A,
// then look for LogonTime within 0–30 min AFTER the matching email DeliveryTime.

#event_simpleName=UserLogon
| UserName = /__RECIPIENT_ACCOUNT__/i
| table([@timestamp, UserName, ComputerName, LogonType, UserSid], limit=200)
| sort(@timestamp, order=asc, limit=200)
