// Ransomware Stage 2 — Mass file modification / extension burst.
// ⚠ Platform asymmetry: Defender DeviceFileEvents gives a clean rename/extension
//   burst. Falcon has no equivalent rename-rate event in this repo's vocabulary, so
//   this approximates impact via file-WRITE volume per device. A high NewFileCount in
//   a short window from one host is the signal — confirm with the Stage 4 detection.
#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| ComputerName = /{{device_name}}/i
| groupBy([ComputerName], function=[
    count(as=NewFileCount),
    collect([TargetFileName], limit=40),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| NewFileCount >= 200
| sort(NewFileCount, order=desc, limit=200)
