# CrowdStrike LogScale (Humio) Query Language Reference

Quick reference for query generation in `tools/generate_queries.py` and `tools/security_arch_review.py`.

Source: https://library.humio.com/data-analysis/syntax.html

## Filter Operators

```
field = "value"          // exact match (case-sensitive)
field != "value"         // not equal
field = *value*          // wildcard contains
field = prefix*          // starts with
field = *suffix          // ends with
field = *                // field exists
field != *               // field does not exist
field = ""               // field exists with empty value
field < 400              // numeric less-than
field <= 400             // numeric less-than-or-equal
field >= 400             // numeric greater-than-or-equal
field > 400              // numeric greater-than
field = /regex/          // regex match on specific field
field = /regex/i         // case-insensitive regex
/regex/                  // regex across all fields + @rawstring
```

## Logical Operators

```
foo bar                  // implicit AND
foo AND bar              // explicit AND
foo OR bar               // OR
NOT foo                  // negation
!foo                     // negation (prefix)
(foo OR bar) AND baz     // grouping
```

**Precedence (high to low):** NOT > AND > OR
**Note:** OR binds tighter than AND — opposite of most languages. Use parentheses.

## String Matching

```
field = "exact"          // case-sensitive exact
like(field, pattern="*foo*", ignoreCase=true)  // like with case option
```

Wildcards use `*` only (no `?`). Available in `=`, `like`, `in()`.

## Assignment & Eval

```
foo := a + b                          // field assignment
foo := if(cond, then="x", else="y")   // conditional assignment
eval(foo = a + b)                     // eval syntax
```

## Key Functions

### in() — multi-value filter
```
in(field, values=["val1", "val2", "val3"])
in(field, values=["4*"])                          // wildcard in values
in(field, ignoreCase=true, values=["error"])
!in(field, values=["val1", "val2"])               // negation
```

### match() — lookup table join
```
match(file="lookup.csv", field=srcField, column=csvColumn)
match(file, field=f, column=c, strict=false)      // left-join (all events pass)
match(file, field=ip, column=cidr, mode=cidr)     // CIDR matching
!match("known.csv", field=src_ip)                 // set difference
```
Modes: `string` (default), `glob`, `cidr`. Max glob rows: 20,000.

### groupBy() — aggregation
```
groupBy(field)                                    // default: count
groupBy(field, function=[count(as=cnt)])
groupBy([field1, field2], function=count())        // multi-field
groupBy(field, function=[], limit=max)             // unique values only
groupBy(field, function=[count(), avg(x)])         // multiple aggregates
```
Default limit: 20,000 groups. Max: 1,000,000 or `max`.

### Aggregate Functions
```
count(as=cnt)            avg(field, as=a)
sum(field)               min(field)
max(field)               percentile(field, percentiles=[95,99])
stdDev(field)            range(field)
stats(function=[...])    top(field, limit=10)
collect(field)           selectLast(field)
```

### Filter Functions
```
in(field, values=[...])
cidr(field, subnet="10.0.0.0/8")
regex("pattern", field=f)
test(expr)
wildcard(field, pattern="*foo*")
sample(rate=0.1)
```

### String Functions
```
concat([f1, f2], as=out)
replace(field, regex="old", with="new")
lower(field, as=out)     upper(field, as=out)
splitString(field, by=",", as=out)
length(field, as=len)
format(format="%s:%s", field=[a,b], as=out)
```

### Time Functions
```
formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, as=ts)
parseTimestamp("yyyy-MM-dd", field=dateStr, as=@timestamp)
now()
time:hour()  time:dayOfWeek()  time:month()  time:year()
```

### Transformation
```
select([field1, field2])           // keep only these fields
rename(old, as=new)
drop([field1, field2])             // remove fields
sort(@timestamp, order=asc)
sort(field, order=desc, limit=100)
head(10)                           // first N events
tail(10)                           // last N events
table([f1, f2, f3])               // display as table widget
```

### Network / Security
```
cidr(field, subnet="10.0.0.0/8")
asn(field, as=asn)
ipLocation(field)
communityId()
ioc:lookup(field, type="ip")
```

## CrowdStrike Falcon Sensor Fields

Common event_simpleName values and their key fields:

| event_simpleName | Key Fields |
|-----------------|------------|
| ProcessRollup2 | FileName, CommandLine, SHA256HashData, ParentBaseFileName, UserName, ImageFileName |
| DnsRequest | DomainName, IP4Records, ContextProcessId |
| NetworkConnectIP4 | RemoteAddressIP4, RemotePort, LocalAddressIP4, LocalPort, Protocol |
| UserLogon | UserName, LogonType, LogonDomain, RemoteAddressIP4 |
| FileWrittenWithEntropyHigh | TargetFileName, SourceFileName |
| NewExecutableWritten | TargetFileName, SHA256HashData |
| AsepValueUpdate | RegObjectName, RegValueName |
| ScheduledTaskRegistered | TaskName, TaskExecCommand |
| SensitiveWmiQuery | QueryString |
| InjectedThread | TargetImageFileName, InjectingImageFileName |

LogonType values: 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 10=RDP, 11=CachedInteractive, 12=CachedRemoteInteractive

## Syntax Pitfalls

1. **OR vs AND precedence** — OR binds tighter. `a AND b OR c` = `a AND (b OR c)`. Always use parens.
2. **Free-text search only before first aggregate** — `foo | groupBy(x) | bar` — `bar` won't work as free text.
3. **Regex is /slashes/ not quotes** — `field = /pattern/` not `field =~ "pattern"`.
4. **No =~ operator** — use `field = /regex/` or `regex("pattern", field=f)`.
5. **Field names are unquoted** — `ComputerName` not `"ComputerName"` (unless they contain special chars).
6. **Array params use square brackets** — `values=["a","b"]`, `field=[f1,f2]`.
7. **String values use double quotes** — `field = "value"` not `field = 'value'`.
