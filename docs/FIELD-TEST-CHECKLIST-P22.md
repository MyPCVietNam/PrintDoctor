# Field test checklist — MyPC PrintDoctor v1.2.2-RC3

**FIELD_READY: false** until physical validation signs below.

## Enabled repairs (consent + admin)
- `NET-PROFILE-PRIVATE` — exact NIC selection
- `FW-OWNED-ICMP4` / `FW-OWNED-SMB445` / `FW-OWNED-SHA48631` / `FW-OWNED-SHA48633`
- `FW-FILE-PRINT-SHARE`
- `SVC-SPOOLER-START` / `SVC-LANMANSERVER-START` / `SVC-LANMANWORKSTATION-START`
- `SHA-START-PROCESS` — verified executable only

## Disabled / NOT_IMPLEMENTED
- `NET-MS-SERVER-BINDING` — adapter binding mutation
- `PRN-RESTORE-MAPPING` — UNC mapping restore
- SMB1 enable, signing disable, guest logon, firewall off, RPC dynamic open, PnP weaken — **never**

## Minimal office cycle
1. **Server:** Role=Server → SCAN → Export `SERVER-BEFORE.zip`
2. **Client:** Role=Client → enter server IPv4 → SCAN → Export `CLIENT-BEFORE.zip`
3. **Compare:** Import both → review root cause + evidence
4. **Repair:** Select ONE eligible repair → confirm → Apply → expect `LOCAL_CONFIG_VERIFIED — WAITING_FOR_CLIENT_VERIFICATION`
5. Re-SCAN client → Export AFTER → optional test page + **physical** confirmation
6. Repeat for remaining clients only after one client works

## Sign-off (leave blank until run)
| Gate | Result | Operator | Date (Asia/Saigon) |
|------|--------|----------|--------------------|
| WIN10_LAB | NOT_RUN | | |
| WIN11_LAB | NOT_RUN | | |
| PHYSICAL_LAN | NOT_RUN | | |
| PHYSICAL_PRINT | NOT_RUN | | |
