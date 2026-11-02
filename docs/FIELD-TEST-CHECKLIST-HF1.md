# Field test checklist — MyPC PrintDoctor v1.2.2-HF1

**FIELD_READY: false** until physical Win10 server + Win10/11 client validation.

## Two-PC then remaining clients (office)

### Server (Windows 10 22H2)
1. Role = **Server** → read-only **SCAN**
2. Export **SERVER-BEFORE.zip**
3. Do **not** apply repairs yet

### First client (Windows 10/11)
4. Role = **Client** → enter server IPv4 → read-only **SCAN**
5. Export **CLIENT-BEFORE.zip**
6. **Compare** server + client reports
7. Review best-supported cause (do not speculate)
8. If evidence points to **switch / VLAN / routing / IP-conflict** → stop Windows repairs; escalate infra
9. Otherwise offer **exactly one** eligible repair → explicit selection + consent
10. Save transaction + snapshot (journal under ProgramData)
11. Apply → expect **LOCAL_CONFIG_VERIFIED** only (not FIXED)
12. Re-test client connectivity → Export **AFTER** reports → ask for **physical print** confirmation

### Remaining three clients
Only after the first client path is restored + physically confirmed (or clearly blocked), repeat client SCAN/Compare for PC2–PC4. Prefer client-specific faults over re-applying server repairs.

## Evidence labels (keep distinct)
| Label | Meaning |
|-------|---------|
| LOCAL_CONFIG_VERIFIED | Local mutation verified on this machine |
| END_TO_END_RESTORED | Client path probes pass after repair |
| PHYSICAL_PRINT_CONFIRMED | Operator saw a real page |

## Sign-off (blank until run)
| Gate | Result | Operator | Date (Asia/Saigon) |
|------|--------|----------|--------------------|
| WIN10_SERVER_22H2 | NOT_RUN | | |
| WIN10_11_CLIENT | NOT_RUN | | |
| PHYSICAL_LAN | NOT_RUN | | |
| PHYSICAL_PRINT | NOT_RUN | | |
| REMAINING_3_CLIENTS | NOT_RUN | | |
