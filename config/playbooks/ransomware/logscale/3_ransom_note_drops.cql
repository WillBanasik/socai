// Ransomware Stage 3 — Ransom-note drops.
// Source: Falcon file-write events; ransom-note filename patterns.
#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /readme|recover|restore|decrypt|how.?to.?(decrypt|recover)|unlock|_help_|ransom/i
| groupBy([ComputerName, TargetFileName], function=[
    count(as=NoteCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(NoteCount, order=desc, limit=200)
