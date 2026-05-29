// DNS tunnelling - high query volume and long subdomains under a single parent
// domain. Falcon DnsRequest carries DomainName (the queried FQDN). Long, high-
// cardinality subdomain labels under one registrable parent = tunnelling.
#event_simpleName=DnsRequest
| ComputerName = /{{device_name}}/i
| regex("^(?<sub>[^.]+)\\.(?<parent>.+)$", field=DomainName)
| SubLen := length("sub")
| groupBy([ComputerName, parent],
          function=[count(as=QueryCount), count(field=DomainName, distinct=true, as=DistinctSubdomains), max("SubLen", as=MaxSubLen)])
| DistinctSubdomains >= 50 OR MaxSubLen >= 40
| sort(DistinctSubdomains, order=desc)
