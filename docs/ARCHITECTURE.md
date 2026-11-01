# Architecture — MyPC LAN & Print Doctor v1.0

## Layers

| Project | Responsibility |
|---------|----------------|
| Abstractions | Interfaces, models, input validation |
| Core | DecisionEngine, CompareEngine, DiagnosticOrchestrator |
| Network/Firewall/Smb/Printing/ShaPrint | Domain diagnostic services |
| Repair | Backup → Apply → Verify → Rollback journal |
| Reports | Evidence ZIP exporter |
| Platform | Windows PowerShell/.NET inspectors + test fakes |
| MyPC.LanPrintDoctor | WPF UI (VI/EN) |

## Safety invariants

- Scan path never mutates Windows configuration.
- Repair requires explicit confirmation + admin when needed.
- No SMB1 enable, no firewall disable, no insecure guest, no blanket NIC reset.
- Host/IP inputs validated before process arguments (ArgumentList, escaped PowerShell literals).

## Decision IDs (selected)

- `LAN-001` unreachable (ICMP+TCP fail) — do not blame firewall alone
- `LAN-002` ICMP blocked suspected (ICMP fail + TCP pass)
- `LAN-003` off-subnet
- `SMB-001` TCP 445 failure
- `PRN-001` Spooler stopped
- `SHA-001` ShaPrint endpoint unavailable
- `CMP-001` common multi-client outage
