# Field Test Checklist — MyPC PrintDoctor v1.2.0-RC1

**FIELD_VALIDATION_PENDING** until completed on office Windows 10/11.

## Prep
- [ ] Install RELEASE ZIP on Server Win10 22H2
- [ ] Install RELEASE ZIP on one failing Client (Win10 or Win11)
- [ ] Note server IPv4 / MAC before changes

## Procedure
1. [ ] Scan **Server** → save BEFORE ZIP
2. [ ] Scan **Client** with exact server IP → save BEFORE ZIP
3. [ ] Compare Reports
4. [ ] Review NGUYÊN NHÂN / RC-CASE-A|B|C — do **not** apply multiple repairs
5. [ ] Apply **one** repair on the **correct** machine only
6. [ ] Save transaction + AFTER ZIP
7. [ ] Re-probe from client
8. [ ] Try Windows Sharing **or** ShaPrint (not both blindly)
9. [ ] Print test page → record JOB_ACCEPTED / PHYSICAL_PRINT_CONFIRMED separately
10. [ ] Scan remaining clients
11. [ ] Reboot + recheck next day (recurrence)

## Hard rules
- No batch repair before baseline
- No fake PASS on UNKNOWN probes
- INFRASTRUCTURE_ACTION_REQUIRED → switch/VLAN/cable — not firewall spam
- Rollback only transaction-owned changes
