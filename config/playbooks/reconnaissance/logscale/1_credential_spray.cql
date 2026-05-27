// Credential stuffing / password spray - failed Azure AD sign-ins (forwarded
// via the M365 connector as azure.signinlogs) clustered by source IP.
//   many distinct users, few attempts each = password spray
//   high attempt volume from one source = credential stuffing / brute force
#event.dataset="azure.signinlogs"
| Vendor.properties.status.errorCode != 0
| groupBy([source.ip],
          function=[count(as=FailedAttempts),
                    countDistinct(Vendor.properties.userPrincipalName, as=DistinctUsers),
                    collect([Vendor.properties.userPrincipalName], limit=50)])
| AttemptsPerUser := FailedAttempts / DistinctUsers
| DistinctUsers >= 5 OR FailedAttempts >= 25
| sort(DistinctUsers, order=desc)
