// Insider / Data Staging Stage 3 — Removable-media writes.

// --- Sub-query A: Removable-media / USB device connections ---
// ⚠ Confirm Falcon USB device fields (DeviceManufacturer/Product/SerialNumber) against
//   the client repo; some sensors use DeviceInstanceId / ProductName variants.

#event_simpleName=/^(RemovableMediaConnected|USBDeviceConnected)$/
| ComputerName = /{{device_name}}/i
| table([@timestamp, ComputerName, DeviceManufacturer, DeviceProduct, DeviceSerialNumber], limit=200)
| sort(@timestamp, order=asc, limit=200)


// --- Sub-query B: Files written to removable paths ---

#event_simpleName=/^(NewExecutableWritten|GenericFileWritten|NewScriptWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /removable|\\Device\\Harddisk[1-9]/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
