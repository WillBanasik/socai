// Credential stuffing / password spray - failed Entra ID sign-ins (dedicated
// entraid connector, dataset entraid.signin) clustered by source IP.
//   many distinct users, few attempts each = password spray
//   high attempt volume from one source = credential stuffing / brute force
#event.module=entraid #event.dataset="entraid.signin"
| Vendor.properties.status.errorCode != 0
| groupBy([source.ip],
          function=[count(as=FailedAttempts),
                    countDistinct(Vendor.properties.userPrincipalName, as=DistinctUsers),
                    collect([Vendor.properties.userPrincipalName], limit=50)])
| AttemptsPerUser := FailedAttempts / DistinctUsers
| DistinctUsers >= 5 OR FailedAttempts >= 25
| sort(DistinctUsers, order=desc)
