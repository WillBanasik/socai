# CrowdStrike LogScale (Humio) Query Language Reference

Authoritative syntax reference for all LogScale query generation.
**All agents generating LogScale queries MUST consult this file** for correct syntax.

**Companion resources (MCP):**
- `socai://ngsiem-rules` — detection rule authoring conventions, anti-patterns, log source tags
- `socai://ngsiem-columns` — field schema per connector (ECS + vendor fields)
- `socai://cql-grammar` — complete function grammar (194 functions, all signatures)

Source: https://library.humio.com/data-analysis/syntax.html

---

## Comments

```
// single-line comment (end of line)
/* multi-line
   block comment */
```

---

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

**Free-text search:** `foo` searches @rawstring and all extracted fields with
implicit wildcards (`*foo*`). Multi-word: `"foo bar"`. Escaped quotes:
`"msg:\"welcome\""`. Free-text only works **before the first aggregate** in a
pipeline.

**Spaces** around operators are optional: `user="value"` is valid.

**Ambiguity trap:** `foo < 42 + 3` is parsed as `(foo < 42) AND "*+*" AND "*3*"`
because `+` and `3` become free-text terms. Use parentheses.

---

## Logical Operators

```
foo bar                  // implicit AND
foo AND bar              // explicit AND
foo OR bar               // OR
NOT foo                  // negation
!foo                     // negation (prefix)
(foo OR bar) AND baz     // grouping
```

**Precedence (high → low):** NOT > OR > AND

**CRITICAL: OR binds tighter than AND** — opposite of most languages.
`a AND b OR c` = `a AND (b OR c)`. Always use parentheses.

**AND/OR do NOT work with functions.** You cannot write:
`regex(/disconnect/) AND !in(field=...)`. Use pipe stages instead:
```
| regex(/disconnect/)
| !in(field, values=[...])
```

**Negating filter functions:**
```
| !cidr(ip, subnet="127.0.0.0/16")
| !in(field, values=["a", "b", "c"])
| !regex("pattern")
| !match("file.csv", field=src_ip)
| !join(query={...}, field=x, key=x)      // anti-join (set difference)
```

---

## Pipe Operator

The `|` constructs pipelines — each stage passes results to the next:
```
#event_simpleName = ProcessRollup2
| FileName = "cmd.exe"
| groupBy(ComputerName, function=count())
| sort(_count, order=desc)
```

Place **tag filters first** (`#event_simpleName`, `#type`, `#repo`) to reduce
data scanned.

---

## Special / Metadata Fields

| Field | Purpose |
|-------|---------|
| `@rawstring` | Raw log line text |
| `@timestamp` | Event timestamp (epoch ms) |
| `@ingesttimestamp` | Ingestion timestamp |
| `@id` | Event unique ID |
| `@timezone` | Timezone |
| `#type` | Event/parser type (tag field) |
| `#repo` | Repository name (tag field) |
| `#event_simpleName` | CrowdStrike Falcon event type (tag field) |

Tag fields (`#field`) are indexed — filter on them first for performance.

### Tag Field Syntax Rules

Tag fields (`#field`) have **different syntax rules** from regular fields:

1. **Single value:** `#event_simpleName=ProcessRollup2` (quotes optional for simple values)
2. **Multi-value — use regex alternation (NOT `in()`):**
   ```
   #event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|DnsRequest)$/
   ```
3. **Wildcard:** `#event_simpleName=Process*` (prefix matching)
4. **Negation:** `#event_simpleName!=ProcessRollup2`
5. **Regex:** `#event_simpleName=/^Network/` (starts with "Network")

**CRITICAL:** `in()` does NOT work on tag fields. These are all INVALID:
```
#event_simpleName IN (ProcessRollup2, DnsRequest)           // INVALID
in(#event_simpleName, values=["ProcessRollup2", "DnsRequest"])  // INVALID
| in(#event_simpleName, values=["ProcessRollup2"])          // INVALID
```

The correct multi-value pattern is always regex alternation:
```
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/
```

---

## Field Assignment

### `:=` operator (shorthand for eval)
```
foo := a + b
bar := a / b
success := if(status >= 500, then=0, else=1)
```

### `eval()` function
```
eval(foo = a + b)
eval(bar = a / b)
```

### `as` parameter on functions
```
count(as=cnt)
concat([a, b], as=combined)
format(format="%s:%s", field=[a,b], as=out)
```

Default aggregate output fields are prefixed with underscore (e.g. `_count`).

### `=~` field operator (apply function to specific field)
```
ip_addr =~ cidr(subnet="10.0.0.0/8")     // equivalent to cidr(subnet="10.0.0.0/8", field=ip_addr)
fieldName =~ join(...)                     // shorthand for join with field
```

### Regex extraction (named capture groups)
```
regex("disk_free=(?<space>[0-9]+)")
| space < 1000
```

Or inline on @rawstring:
```
@rawstring=/user=(?<username>\S+)/
```

Use `repeat=true` for multiple matches:
```
regex("value[^=]*=(?<val>\\S+)", repeat=true)
```

---

## Expressions

All values are strings at runtime, interpreted contextually.

### Arithmetic
```
+  -  *  /  %
```
`"2" + "2"` = `4` (numeric context). Type mismatch → null.

### Comparison (inside eval/test/if)
```
==  !=  <  <=  >  >=
```

### Boolean
```
!   // negation (prefix)
```
No `&&` or `||` operators in expressions — use `if()` nesting or `case{}`.

### Conditional
```
if(condition, then=onTrue, else=onFalse)
success := if(status >= 500, then=0, else=1)
```

---

## Conditional Evaluation

### case {} — multi-branch
```
case {
  src="client-side" | type := "client" ;
  src="frontend-server" | ip != 192.168.1.1 | type := "frontend" ;
  * | type := "server"
}
```
- Clauses separated by `;`
- `*` = default catch-all
- Events not matching any clause are **dropped** unless `*` exists

### match {} — switch on a single field
```
logtype match {
  "accesslog" => time := response_time ;
  /server_\d+/ => time := server_time * 1000 ;
  * => time := 0
}
```
Matchers: string literals, `/regex/`, `in(values=[...])`, `*` (catch-all),
`"*"` / `**` (field existence check).

---

## String Matching

```
field = "exact"                                         // case-sensitive
like(field, pattern="*foo*", ignoreCase=true)            // like with case option
wildcard(field, pattern="*foo*", ignoreCase=true)        // wildcard filter
```

Wildcards use `*` only (no `?`). Available in `=`, `like`, `in()`.

---

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

### join() — cross-query correlation
```
join(query={subquery}, field=[matchField], key=[subqueryField],
     mode=inner, include=[extraFields], limit=100000, max=1,
     start=2h, end=now, repo=otherRepo)
```
- `mode=inner` (default): only matching events pass
- `mode=left`: all primary events pass; non-matches get empty included fields
- `!join(...)`: anti-join (set difference) — cannot use `include` with negation
- `start`/`end`: subquery time range relative to main query
- `repo`/`view`: run subquery against a different repository
- `max`: allow multiple matches per key (default 1)
- **Limit:** 200,000 max rows in subquery
- **Not recommended for live queries** (two-pass architecture)

### selfJoin() — correlate events within same dataset
```
selfJoin(field, where=[{condition1}, {condition2}],
         collect=[fields], limit=20000, prefilter=false, postfilter=false)
```
Example — find emails matching both sender and recipient conditions:
```
selfJoin(email_id,
  where=[{from=*peter*}, {to=*anders*}],
  collect=[from, to])
```
- Uses bloom filter — probabilistic (small false-positive rate)
- Not live-compatible (two data passes)

---

## Aggregate Functions
```
count(as=cnt)                        avg(field, as=a)
sum(field)                           min(field)
max(field)                           percentile(field, percentiles=[95,99])
stdDev(field)                        range(field)
stats(function=[...])                top(field, limit=10)
collect(field)                       selectLast(field)
selectFirst(field)                   variance(field)
```

---

## Filter Functions
```
in(field, values=[...])
cidr(field, subnet="10.0.0.0/8")
regex("pattern", field=f)
test(expr)                           // boolean expression filter
wildcard(field, pattern="*foo*")
sample(rate=0.1)
```

---

## String Functions
```
concat([f1, f2], as=out)
replace(field, regex="old", with="new")
lower(field, as=out)                 upper(field, as=out)
splitString(field, by=",", as=out)
length(field, as=len)
format(format="%s:%s", field=[a,b], as=out)
```

---

## Time Functions
```
formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, as=ts)
parseTimestamp("yyyy-MM-dd", field=dateStr, as=@timestamp)
now()
time:hour()  time:dayOfWeek()  time:month()  time:year()
```

---

## Transformation Functions
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

---

## Network / Security Functions
```
cidr(field, subnet="10.0.0.0/8")
asn(field, as=asn)
ipLocation(field)
communityId()
ioc:lookup(field, type="ip")
```

---

## Array & Object Syntax

### Array access
```
username[]                // entire array
username[0]               // first element (0-indexed)
username[1]               // second element
```

### Nested object access (dot notation)
```
users[0].username         // property of first array element
users[0].user.name        // nested object within array element
foo[0][0]                 // multi-dimensional array
```

### Backtick escaping for special field names
```
user.`e-mail`[]           // field name containing hyphen
```

### objectArray:eval() for iteration
```
objectArray:eval("in[]", asArray="out[]", function={...})
```
Inside the function: `in.key`, `in.others[0].foo`, `in[0][1]`.

---

## Regular Expressions

**Engine:** JitRex (similar to Perl/JavaScript/re2 syntax).

### Usage patterns
```
/pattern/                 // search @rawstring + all fields
field = /pattern/         // search specific field
field = /pattern/i        // case-insensitive
regex("pattern", field=f) // function form
```

### Named capture groups (field extraction)
```
/user with id (?<id>\S+) logged in/
regex("disk_free=(?<space>[0-9]+)")
```

### Supported features
- Character classes: `[abc]`, `[^abc]`
- Quantifiers: `*`, `+`, `?`, `{n,m}`
- Anchors: `^`, `$`
- Alternation: `|`
- Grouping: `()`
- Flags: `i` (case-insensitive), multiline

### Key rules
- **Use `/slashes/` not quotes** for regex in field filters
- **No `=~` operator for regex** — use `field = /regex/` or `regex()` function
- Field-specific regex is much faster than all-field `/regex/`

---

## CrowdStrike Falcon Sensor Fields

Common `#event_simpleName` values and their key fields:

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

LogonType values: 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock,
10=RDP, 11=CachedInteractive, 12=CachedRemoteInteractive

---

## Syntax Pitfalls (MUST READ)

1. **OR vs AND precedence** — OR binds tighter. `a AND b OR c` = `a AND (b OR c)`. Always use parens.
2. **Free-text search only before first aggregate** — `foo | groupBy(x) | bar` — `bar` won't work as free text.
3. **Regex is /slashes/ not quotes** — `field = /pattern/` not `field =~ "pattern"`.
4. **No =~ operator for regex** — use `field = /regex/` or `regex("pattern", field=f)`.
5. **Field names are unquoted** — `ComputerName` not `"ComputerName"` (unless special chars, then use backticks).
6. **Array params use square brackets** — `values=["a","b"]`, `field=[f1,f2]`.
7. **String values use double quotes** — `field = "value"` not `field = 'value'`.
8. **AND/OR don't work with functions** — use pipe stages: `| func1() | func2()`.
9. **Tag fields start with #** — `#event_simpleName`, `#type`, `#repo`. Filter on these first for performance.
10. **No `=~` comparison operator** — use `field = /regex/` for regex, `=~` only applies functions to fields.
11. **case/match drop unmatched events** — always include a `*` default clause unless you want filtering behaviour.
12. **join() is two-pass** — not reliable for live queries; use for historical searches.
13. **`!join()` cannot use `include`** — anti-joins only filter, they don't enrich.
14. **`in()` is a pipeline function, not a filter** — `#event_simpleName IN (A, B)` is INVALID. Use regex alternation: `#event_simpleName=/^(A|B)$/`.
15. **Tag fields use different multi-value syntax** — `#field` does not support `in()` or `IN`. Use `#field=/^(Val1|Val2)$/` for multi-value matching on tag fields.
16. **`table()` uses array syntax** — `table([f1, f2, f3])` not `table(f1, f2, f3)`. The argument is a single array.
17. **`in()` placement** — `in()` cannot appear in filter expressions (before the first `|`). It must be a pipeline step: `| in(field, values=[...])`.
18. **Tag values are conventionally unquoted** — `#event_simpleName=ProcessRollup2` not `#event_simpleName="ProcessRollup2"`.
