# KNOWN-LIMITATIONS — v1.2.2-HF1

- **FIELD_READY=false** — office physical Win10 22H2 server + Win10/11 client run not completed.
- `SHA-START-PROCESS` is implemented but **trust-gated**: Program Files canonical path + metadata/hash when available; filename alone is insufficient. Trust failure → blocked with manual-start instruction. Process start ≠ IPPS operational.
- End-to-end print success requires user-confirmed **PHYSICAL_PRINT_CONFIRMED**; `LOCAL_CONFIG_VERIFIED` ≠ `END_TO_END_RESTORED` ≠ FIXED.
- Infrastructure conclusions use investigation-recommended unless witness evidence confirms (power/sleep, WFP drop, packet-arrival remain BLOCKED without models).
- Windows CI ≠ Windows 10/11 desktop compatibility proof.
- Pktmon/WFP advanced capture and recurrence monitoring are read-only / deferred.
- Prohibited forever: SMB1 enable, signing disable, insecure guest, unrestricted firewall, Point and Print weaken.
