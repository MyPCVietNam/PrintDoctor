# Field Test Checklist — v1.2.1-RC2 (2026-11-02)

**FIELD_VALIDATION_PENDING** until completed.

## Server Win10 22H2
1. Read-only scan → BEFORE ZIP  
2. Confirm IP/MAC/gateway/profile/listeners/Spooler/ShaPrint  

## Client Win10/11
1. Enter exact server IPv4  
2. ICMP + TCP 445/135/48631 → BEFORE ZIP  
3. Compare Reports  

## Repair
1. Select **one** repair from list (no auto-first)  
2. Review preview / security impact / rollback  
3. Backup → Apply → Verify local  
4. Client re-probe → AFTER ZIP  
5. Test page with physical confirmation  

Hard rules: no batch repairs; no firewall spam on INFRASTRUCTURE_INVESTIGATION_RECOMMENDED; never open TCP 48632 to LAN.
