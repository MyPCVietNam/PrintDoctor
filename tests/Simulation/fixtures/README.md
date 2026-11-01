# MyPC PrintDoctor - Pre-field Scenario Simulation Kit

Date: 2026-11-01. Purpose: reduce uncontrolled trial-and-error for 2026-11-02 office testing.

The kit provides:
- 48 SYNTHETIC single-device failure fixtures plus 12 five-machine office topologies and an independent offline oracle.
- 28 synthetic repair state-machine failure-injection tests (NOT the actual RepairExecutor).
- A read-only Windows Server/Client collector with small focused probes.
- Read-only Windows cmdlet compatibility gate checking actual parameter metadata.
- A Cursor prompt to connect the fixtures to REAL P2 .NET tests.
- A two-device-first field playbook; Windows-lab and paper-print gates remain NOT_RUN.

## Offline reference simulation (developer/Cursor computer)

`python3 simulation/run_simulations.py`

`python3 simulation/repair_transaction_tests.py`

Output is `reports/SIMULATION-RESULTS.json`. The simulation tests its own independent oracle, NOT the P2 application. It is useful only if Cursor maps fixtures into the actual code and runs that code separately.

## Real Windows read-only validation (tomorrow)

On print server: `windows/01-Server-ReadOnly.cmd`

On ONE client: `windows/02-Client-ReadOnly.cmd` (prompts for numeric server IPv4).

Only if needed: `windows/03-Server-DeepReadOnly.cmd` (includes selected events).

Actual NetSecurity cmdlet discovery: `windows/04-Windows-API-Check.cmd`.

These scripts do not change firewall, SMB, network settings, printers, or services. They save ZIP/JSON evidence under Windows user TEMP. Sharing reports discloses network identity data.

## Limits

No physical Windows runtime was available during kit creation. The `.ps1` files have been statically inspected but NOT executed under PowerShell 5.1. No production PrintDoctor EXE code or GitHub PR was changed by this kit. Offline scenario PASS is NOT evidence that any Windows repair works.

Read SOURCES.md, FIELD-PLAYBOOK-20261102.md, and CURSOR-P2-SIMULATION-PROMPT.md before using.
