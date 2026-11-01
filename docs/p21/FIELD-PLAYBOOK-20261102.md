# MYPC PRINTDOCTOR - Minimal Office Test Playbook (02 Nov 2026)

## Office setup
1 Windows 10 22H2 server with printer; 4 clients (Windows 10 22H2 / Windows 11 25H2 / 26H2). All four clients currently cannot ping the server IP; ShaPrint worked about 1-2 days and then stopped; actual server IP is reported unchanged.

## Two-device first pass (READ-ONLY)
1. Keep the existing printer and ShaPrint installed. Do not reset network or disable firewall.
2. On SERVER: unzip this kit and launch `windows/01-Server-ReadOnly.cmd`. Keep the produced report ZIP.
3. On ONE failing CLIENT: launch `windows/02-Client-ReadOnly.cmd`. Enter the numeric server IPv4 when prompted. Keep ZIP.
4. Check client `Quick-Results.txt` and server `Snapshot.json` together. Never infer host offline from ping alone.

## Decision table
- Server NIC down: inspect server cable, switch port, adapter and machine power. No firewall repair.
- Server gateway unreachable: verify physical LAN and gateway. No mass reset.
- Server NIC up, gateway good, client ping & all 3 TCP ports fail: verify route/ARP/MAC, and if necessary capture server-side WFP/pktmon for packet arrival. Without WFP evidence, root cause remains UNKNOWN.
- Ping fails but TCP 445 or 48631 works: host is reachable; classify ICMP separately from print function.
- TCP 445 fails but server has no 445 listener / LanmanServer is stopped: investigate service and ms_server binding before firewall.
- TCP 445 works but UNC fails with access denied: secure authentication/permission issue; no SMB1/guest/signing downgrade.
- TCP 445 works but RPC print fails: check TCP 135 and actual RPC endpoint; do not automatically open entire dynamic range.
- TCP 48631 fails and ShaPrint process is stopped: verify app/startup; open no port without a correct listener and user consent.
- TCP 48631 succeeds but IPPS fails: inspect ShaPrint TLS/trust/network channel, not simple connectivity.
- USB printer disconnected, printer offline or spooler stopped: correct physical/local printing before rebuilding remote share.
- Firewall WFP evidence confirms a blocked target: P2 may preview ONE scoped Private/LocalSubnet owner rule after safety gate; verify from client.

## Minimum use of Repair button
- Only use the NEW P2 EXE repair features when Windows API contract gate is PASS, the repair has a valid pre-mutation snapshot, and the user is standing at the target machine with a rollback path.
- If uncertain or if a global policy/third-party security product is in control, DO NOT APPLY automatically.
- After ONE change: re-run the same client probes and an intentionally selected test print. Distinguish TCP, IPPS, spooler accept and physical paper.
- If network recovers on one client, only then run quick checks on the remaining three.
- Keep pre/post ZIPs private; they contain computer names/IPs/MACs and printer names.

## Avoid
- Do not turn off Windows Firewall, enable SMB1, insecure guest, disable SMB signing, or use RpcAuthnLevelPrivacyEnabled=0.
- Do not clear print queues, remove drivers, restart every network service, or reset the TCP/IP stack by default.
- Do not run simultaneous repairs across all five PCs.

## For recurring failures
Capture an additional server deep read-only report after reboot or when the issue recurs; compare network category, link, firewall effective policy, services and ShaPrint process/listener before changing them.

## Honest status
The Python scenario simulation is synthetic and independent. PowerShell field collector and Windows API contract scripts have NOT been executed on the user's Windows PCs; they must be tested on Windows by Cursor/field operator. Physical print remains unverified until a paper output is confirmed.
