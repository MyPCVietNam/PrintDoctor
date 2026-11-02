# PowerShell firewall safe-scope fixtures (HF2 / P2)

These assertions are enforced by `Hf2WindowsPowerShellFixtureTests` via a recording process runner.
**CI must never mutate production firewall rules.** Live mutation requires `LPD_ALLOW_FIREWALL_MUTATION=1` (manual lab only).

## ICMP / FPS enable script must

1. Call `Set-NetFirewallRule -Name … -RemoteAddress LocalSubnet` **before** `Enable-NetFirewallRule`.
2. **Never** use `Set-NetFirewallAddressFilter -AssociatedNetFirewallRule` (invalid on Set-*). Prefer Get→pipe or `Set-NetFirewallRule -RemoteAddress`.
3. Re-read address filter (`Get-NetFirewallAddressFilter -AssociatedNetFirewallRule`) and throw `REMOTE_NOT_SET` if not LocalSubnet.
4. Refuse Profile containing Public/Domain (`PROFILE_NOT_SET` / `BAD_PROFILE`).
5. Never use `Enable-NetFirewallRule -Group`.
6. Never wrap address-filter set in empty `catch { }`.
7. Skip / throw on GPO (`GPO_MANAGED`).

## Owned PrintDoctor rules (P2-02)

1. `New-NetFirewallRule … -Enabled False` with full scope first.
2. Re-read Profile/RemoteAddress before Enable.
3. Rollback deletes only `MyPC.PrintDoctor.*` rules.
4. Never open TCP 48632 to LAN; never RemoteAddress=Any.

## FPS enable script must

1. Iterate approved rule ids only (`FPS-SMB-In-TCP`, `FPS-NBSession-In-TCP`, `FPS-RPCSS-In-TCP`, `FPS-SpoolSvc-In-TCP`).
2. Scope Profile=Private + RemoteAddress=LocalSubnet before each Enable.
3. Emit `CHANGED:` list of actually mutated rule names.

## Restore scripts must

1. Set Profile/Direction/Action and RemoteAddress before Enable/Disable.
2. Throw `REMOTE_RESTORE_FAIL` when re-read RemoteAddress mismatches backup.
