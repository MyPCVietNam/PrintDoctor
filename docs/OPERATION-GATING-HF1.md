# Operation gating — v1.2.2-HF1

FIELD_READY remains **false**. CI / simulation PASS ≠ physical restoration.

| Operation | Implemented | Preconditions | Target machine | Backup | Apply tested | Local verify | Rollback | Isolated Win mutation | UI |
|-----------|-------------|---------------|----------------|--------|--------------|--------------|----------|----------------------|----|
| NET-PROFILE-PRIVATE | Yes | Admin; non-Domain; exact InterfaceIndex | Local | Journal snapshot | UNIT | UNIT | Limited (profile restore) | NOT_RUN | Enabled |
| FW-OWNED-ICMP4 | Yes | Admin; Private; LocalSubnet/CIDR; consent | LocalServer | Rule query JSON | UNIT+fault | UNIT | Delete-only if created-in-tx | NOT_RUN | Enabled |
| FW-OWNED-SMB445 | Yes | Same owned-firewall gates | LocalServer | Rule query JSON | UNIT+fault | UNIT | Same | NOT_RUN | Enabled |
| FW-OWNED-SHA48631 | Yes | Same; listener preferred | LocalServer | Rule query JSON | UNIT+fault | UNIT | Same | NOT_RUN | Enabled |
| FW-OWNED-SHA48633 | Yes | Same; UDP discovery | LocalServer | Rule query JSON | UNIT | UNIT | Same | NOT_RUN | Enabled |
| FW-FILE-PRINT-SHARE | Yes | Admin; Private profile | LocalAny | Toggle snapshot | UNIT | UNIT | Best-effort | NOT_RUN | Enabled |
| SVC-LANMANSERVER-START | Yes | Admin; service exists | LocalAny | Service state | UNIT | UNIT | No stop-on-rollback | NOT_RUN | Enabled |
| SVC-LANMANWORKSTATION-START | Yes | Admin | LocalAny | Service state | UNIT | UNIT | No stop-on-rollback | NOT_RUN | Enabled |
| SVC-SPOOLER-START | Yes | Admin | LocalAny | Service state | UNIT | UNIT | No stop-on-rollback | NOT_RUN | Enabled |
| SHA-START-PROCESS | Yes* | Admin; ProgramFiles trust; no foreign PID; not already running | LocalServer | Pre-state JSON | UNIT trust | ProcessRunning only (≠ IPPS) | Unsupported (no kill) | NOT_RUN | Enabled if trust OK; else BLOCKED with manual start |

\*Executable trust requires canonical Program Files install path + metadata/hash when available. Filename “ShaPrint” alone is insufficient. If trust fails → operation blocked with manual-start instruction.

## Prohibited (never enabled)
SMB1 enable · signing disable · insecure guest · unrestricted firewall Any/0.0.0.0/0 · Point and Print weaken · foreign process kill · credential/cert delete

## Disabled / NOT_IMPLEMENTED
NET-MS-SERVER-BINDING · PRN-RESTORE-MAPPING

## Evidence separation
`LOCAL_CONFIG_VERIFIED` ≠ `END_TO_END_RESTORED` ≠ `PHYSICAL_PRINT_CONFIRMED`
