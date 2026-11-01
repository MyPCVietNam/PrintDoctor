# Problem / Cause / Test / Repair Matrix

| Symptom | Hypotheses | Detect | Safe repair |
|---------|------------|--------|-------------|
| All clients cannot ping server, IP unchanged | Firewall ICMP; NIC; subnet; AP isolation; server down | LAN-001/002/003/004, CMP-001 | Scoped ICMP rule; profile Private; else infra guidance |
| Printer sharing stopped | Spooler; LanmanServer; Public profile; sharing toggles | PRN-001, SMB-002/005, FW-001 | Start services; enable scoped sharing rules |
| ShaPrint works 1–2 days then fails | Process exit; port bind; firewall; IP change; route | SHA-001/002/003 | No auto-uninstall; restart guidance + endpoint verify |
| UNC fails, TCP 445 open | Auth/permissions/signing | SMB-004 | Do not disable signing / enable guest |
| DNS fail, IP works | Name resolution | DNS probe | Fix DNS; not treat as offline |
