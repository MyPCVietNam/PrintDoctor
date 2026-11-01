# PowerShell firewall safe-scope fixtures (HF2)

These assertions are enforced by `Hf2WindowsPowerShellFixtureTests` via a recording process runner.
**CI must never mutate production firewall rules.** Live mutation requires `LPD_ALLOW_FIREWALL_MUTATION=1` (manual lab only).

## ICMP enable script must

1. Call `Set-NetFirewallAddressFilter` … `-RemoteAddress LocalSubnet` **before** `Enable-NetFirewallRule`.
2. Re-read address filter and throw `REMOTE_NOT_SET` if not LocalSubnet.
3. Refuse Profile containing Public/Domain (`PROFILE_NOT_SET` / `BAD_PROFILE`).
4. Never use `Enable-NetFirewallRule -Group`.
5. Never wrap address-filter set in empty `catch { }`.
6. Skip / throw on GPO (`GPO_MANAGED`).

## FPS enable script must

1. Iterate approved rule ids only (`FPS-SMB-In-TCP`, `FPS-NBSession-In-TCP`, `FPS-RPCSS-In-TCP`, `FPS-SpoolSvc-In-TCP`).
2. Scope Profile=Private + RemoteAddress=LocalSubnet before each Enable.
3. Emit `CHANGED:` list of actually mutated rule names.

## Restore scripts must

1. Set Profile/Direction/Action and RemoteAddress before Enable/Disable.
2. Throw `REMOTE_RESTORE_FAIL` when re-read RemoteAddress mismatches backup.
