using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

/// <summary>
/// Creates PrintDoctor-owned firewall rules (Disabled → verify exact scope → Enable).
/// P22-001: Transaction-bound create/recover — never rely solely on an in-memory create flag.
/// P22-002: Strict MatchesDesired — NULL≠VALID, Any≠port/ICMP, compound scopes rejected.
/// </summary>
public sealed class OwnedFirewallRuleRepair : IRepairOperation, ITransactionBoundRepair
{
    public const string RulePrefix = "MyPC.PrintDoctor.";

    private readonly IProcessRunner _runner;
    private readonly IElevationService _elevation;
    private readonly OwnedFirewallSpec _spec;
    private string? _backupJson;
    private string? _transactionId;
    private string? _createdFingerprint;
    private bool _createdInThisTransaction;
    private FirewallRulePresence _beforePresence = FirewallRulePresence.Unknown;

    public OwnedFirewallRuleRepair(IProcessRunner runner, IElevationService elevation, OwnedFirewallSpec spec)
    {
        _runner = runner;
        _elevation = elevation;
        _spec = spec;
    }

    public string OperationId => "FW-OWNED-" + _spec.ShortId;
    public string Title => _spec.Title;
    public bool IsImplemented => true;
    public bool SupportsRollback => true;
    public RepairOwnerRole OwnerRole => _spec.OwnerRole;
    public RepairTargetMachine TargetMachine => RepairTargetMachine.Local;
    public bool CreatedInThisTransaction => _createdInThisTransaction;
    public string? BoundTransactionId => _transactionId;
    public FirewallRulePresence BeforePresence => _beforePresence;

    public void BindTransaction(string transactionId)
    {
        if (string.IsNullOrWhiteSpace(transactionId))
            throw new ArgumentException("TransactionId required.", nameof(transactionId));
        _transactionId = transactionId;
    }

    public Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
    {
        if (!_elevation.IsAdministrator())
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Administrator required." });
        if (string.IsNullOrWhiteSpace(_spec.RuleName) || !_spec.RuleName.StartsWith(RulePrefix, StringComparison.Ordinal))
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Rule must use MyPC.PrintDoctor.* prefix." });
        if (!_spec.Profile.Equals("Private", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Owned rules are Private-only." });
        if (!FirewallRemoteAddress.IsSafeLanScope(_spec.RemoteAddress))
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "RemoteAddress must be LocalSubnet or confirmed LAN CIDR — not Any/0.0.0.0/0/SPECIFIC_CIDR." });
        return Task.FromResult(new RepairPrerequisiteResult { CanProceed = true, RequiresAdmin = true });
    }

    public Task CollectEvidenceAsync(CancellationToken ct = default) => Task.CompletedTask;

    public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPreview
        {
            OperationId = OperationId,
            Title = Title,
            Description = $"Create owned rule {_spec.RuleName} Disabled → verify exact scope → Enable. Profile=Private Remote={_spec.RemoteAddress}.",
            Changes = new[]
            {
                $"New-NetFirewallRule -Name {_spec.RuleName} (Enabled=False) if absent",
                $"Exact scope Protocol={_spec.Protocol} Port/ICMP={_spec.LocalPortOrIcmp} Remote={_spec.RemoteAddress}",
                "Enable only after re-read confirms exact fields; rollback deletes only this transaction's create"
            },
            Risks = new[] { "Adds inbound allow on Private/LocalSubnet for the specified protocol only" },
            Reversible = true
        });

    public async Task<RepairBackup> BackupAsync(CancellationToken ct = default)
    {
        var (presence, snap, raw) = await QueryRuleAsync(ct);
        _beforePresence = presence;
        if (presence == FirewallRulePresence.Unknown)
            throw new InvalidOperationException("BACKUP_FAILED: firewall query returned UNKNOWN — refusing to treat as absence.");
        if (string.IsNullOrWhiteSpace(raw))
            throw new InvalidOperationException("BACKUP_FAILED: empty payload — refusing to treat as valid absence.");

        _backupJson = raw;
        return new RepairBackup
        {
            BackupId = $"bak-{OperationId}-{Guid.NewGuid():N}",
            Path = "journal",
            CreatedAt = DateTimeOffset.UtcNow,
            PayloadJson = _backupJson
        };
    }

    public async Task ApplyAsync(CancellationToken ct = default)
    {
        // Prefer executor-bound TransactionId; only mint for direct unit-test calls.
        _transactionId ??= Guid.NewGuid().ToString("N");
        _createdInThisTransaction = false;
        _createdFingerprint = BuildFingerprint(_transactionId);

        var (presence, existing, _) = await QueryRuleAsync(ct);
        _beforePresence = presence;
        if (presence == FirewallRulePresence.Unknown)
            throw new RepairBlockedException($"UNKNOWN_BEFORE_STATE:{_spec.RuleName} — firewall query failed; mutation blocked.");

        if (presence == FirewallRulePresence.Present && existing is not null)
        {
            if (MatchesDesired(existing, requireEnabled: true))
                throw new RepairNoChangeException($"ALREADY_CONFIGURED:{_spec.RuleName}");
            throw new RepairBlockedException(
                $"RULE_CONFLICT:{_spec.RuleName} — preexisting rule present with different scope/provenance; " +
                "refusing overwrite/delete. Use a dedicated consent repair after explicit snapshot.");
        }

        // Step 4a — create Disabled with full intended scope + provenance Description.
        var createResult = await RunCreateDisabledAsync(ct);
        if (!createResult.Ok)
        {
            await RecoverAfterPossibleCreateAsync(ct, createResult.Error);
            throw new InvalidOperationException(createResult.Error ?? "Owned firewall create failed.");
        }

        // Re-query after create — confirm provenance before Enable.
        var (afterCreatePresence, afterCreate, _) = await QueryRuleAsync(ct);
        if (afterCreatePresence == FirewallRulePresence.Unknown)
        {
            await RecoverAfterPossibleCreateAsync(ct, "POST_CREATE_QUERY_UNKNOWN");
            throw new InvalidOperationException("UNCERTAIN_STATE: created rule cannot be re-read.");
        }

        if (afterCreatePresence != FirewallRulePresence.Present || afterCreate is null)
        {
            // Create claimed success but rule absent — do not Enable; nothing to roll back.
            throw new InvalidOperationException("CREATE_NOT_VISIBLE: New-NetFirewallRule reported success but rule is absent.");
        }

        if (!HasOurProvenance(afterCreate))
        {
            // Foreign/preexisting appeared — never Enable or delete.
            throw new RepairBlockedException($"RULE_CONFLICT:{_spec.RuleName} — rule present without this transaction provenance.");
        }

        _createdInThisTransaction = true;

        if (!MatchesDesired(afterCreate, requireEnabled: false))
        {
            // Scope wrong after create — attempt safe rollback of our rule.
            throw new InvalidOperationException("SCOPE_VERIFY_FAIL: created rule does not match desired exact scope.");
        }

        if (afterCreate.Enabled == true)
            throw new InvalidOperationException("CREATED_ENABLED_TOO_EARLY");

        // Step 4b — Enable only after exact scope validation.
        var enableResult = await RunEnableAsync(ct);
        if (!enableResult.Ok)
        {
            // Rule exists with our provenance — rollback path must delete it.
            _createdInThisTransaction = true;
            throw new InvalidOperationException(enableResult.Error ?? "Enable-NetFirewallRule failed.");
        }

        var (finalPresence, finalSnap, _) = await QueryRuleAsync(ct);
        if (finalPresence != FirewallRulePresence.Present || finalSnap is null || !MatchesDesired(finalSnap, requireEnabled: true))
        {
            _createdInThisTransaction = true;
            throw new InvalidOperationException("POST_ENABLE_VERIFY_FAIL: rule missing or scope/enabled mismatch.");
        }
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        var (presence, snap, _) = await QueryRuleAsync(ct);
        if (presence != FirewallRulePresence.Present || snap is null) return false;
        return MatchesDesired(snap, requireEnabled: true);
    }

    public async Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
    {
        // Determine ownership from live re-query + provenance — not only the in-memory flag.
        var (presence, live, _) = await QueryRuleAsync(ct);
        if (presence == FirewallRulePresence.Unknown)
        {
            return new RollbackResult
            {
                Attempted = true,
                Succeeded = false,
                Verified = false,
                Partial = true,
                Message = "UNCERTAIN_STATE: cannot re-query firewall during rollback."
            };
        }

        if (presence == FirewallRulePresence.Absent)
        {
            return new RollbackResult
            {
                Attempted = false,
                Succeeded = true,
                Verified = true,
                Message = "ROLLBACK_VERIFIED: rule already absent — nothing to delete."
            };
        }

        var beforeWasAbsent = _beforePresence == FirewallRulePresence.Absent
                              || (backup.PayloadJson is not null && backup.PayloadJson.Contains("\"exists\":false", StringComparison.OrdinalIgnoreCase));

        // Never delete a preexisting rule.
        if (!beforeWasAbsent && !_createdInThisTransaction && !HasOurProvenance(live!))
        {
            return new RollbackResult
            {
                Attempted = false,
                Succeeded = true,
                Verified = true,
                Message = "NO_DELETE_PREEXISTING: Apply did not create a rule in this transaction — refusing Remove-NetFirewallRule."
            };
        }

        if (!HasOurProvenance(live!) && !_createdInThisTransaction)
        {
            return new RollbackResult
            {
                Attempted = true,
                Succeeded = false,
                Verified = false,
                Partial = true,
                Message = "UNCERTAIN_STATE: ownership cannot be confirmed — refusing delete."
            };
        }

        if (live!.Name is null || !live.Name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return new RollbackResult
            {
                Attempted = true,
                Succeeded = false,
                Verified = false,
                Message = "REFUSE_DELETE_NON_OWNED"
            };
        }

        var name = Escape(_spec.RuleName);
        var fp = Escape(_createdFingerprint ?? BuildFingerprint(_transactionId ?? ""));
        var script = $@"
$ErrorActionPreference = 'Stop'
$r = Get-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue
if (-not $r) {{ 'OK:GONE'; exit 0 }}
if ($r.Name -notlike 'MyPC.PrintDoctor.*') {{ throw 'REFUSE_DELETE_NON_OWNED' }}
$desc = [string]$r.Description
if ($desc -notlike '*{fp}*' -and $desc -notlike '*tx:{Escape(_transactionId ?? "")}*') {{
  throw 'PROVENANCE_MISMATCH:' + $desc
}}
Remove-NetFirewallRule -Name '{name}' -ErrorAction Stop
'OK:REMOVED'
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        var raw = (result.StdOut ?? "").Trim();
        var removeOk = result.ExitCode == 0 && raw.Contains("OK:", StringComparison.Ordinal);

        // Step 6 — verify cleanup independently.
        var (afterPresence, afterSnap, _) = await QueryRuleAsync(ct);
        if (afterPresence == FirewallRulePresence.Unknown)
        {
            return new RollbackResult
            {
                Attempted = true,
                Succeeded = removeOk,
                Verified = false,
                Partial = true,
                Message = "UNCERTAIN_STATE: rollback command ran but post-rollback query is UNKNOWN."
            };
        }

        if (afterPresence == FirewallRulePresence.Present)
        {
            return new RollbackResult
            {
                Attempted = true,
                Succeeded = false,
                Verified = false,
                Partial = true,
                Message = "PARTIAL_ROLLBACK: Remove reported " + (removeOk ? "OK" : "FAIL") + " but rule still PRESENT."
            };
        }

        if (!removeOk && afterPresence == FirewallRulePresence.Absent)
        {
            // Race: gone despite command noise — treat as verified absent.
            return new RollbackResult
            {
                Attempted = true,
                Succeeded = true,
                Verified = true,
                Message = "ROLLBACK_VERIFIED: rule absent after rollback."
            };
        }

        return new RollbackResult
        {
            Attempted = true,
            Succeeded = removeOk,
            Verified = afterPresence == FirewallRulePresence.Absent,
            Message = afterPresence == FirewallRulePresence.Absent
                ? "ROLLBACK_VERIFIED: transaction-created owned rule removed; preexisting state preserved."
                : (result.StdErr ?? raw ?? "rollback failed")
        };
    }

    private async Task RecoverAfterPossibleCreateAsync(CancellationToken ct, string? error)
    {
        var (presence, snap, _) = await QueryRuleAsync(ct);
        if (presence == FirewallRulePresence.Unknown)
        {
            // Cannot confirm — leave flag false so Rollback refuses blind delete, surface UNCERTAIN.
            _createdInThisTransaction = false;
            throw new InvalidOperationException(
                "UNCERTAIN_STATE: PowerShell failed after possible create and re-query is UNKNOWN. " + (error ?? ""));
        }

        if (presence == FirewallRulePresence.Present && snap is not null && HasOurProvenance(snap))
        {
            _createdInThisTransaction = true;
            return; // caller throws; executor Rollback will delete our rule
        }

        if (presence == FirewallRulePresence.Present && snap is not null && !HasOurProvenance(snap))
        {
            _createdInThisTransaction = false;
            throw new RepairBlockedException(
                $"RULE_CONFLICT:{_spec.RuleName} — rule present without this transaction provenance after failed create.");
        }

        // Absent — create never landed.
        _createdInThisTransaction = false;
    }

    private async Task<(bool Ok, string? Error)> RunCreateDisabledAsync(CancellationToken ct)
    {
        var proto = Escape(_spec.Protocol);
        var remote = Escape(_spec.RemoteAddress);
        var name = Escape(_spec.RuleName);
        var display = Escape(_spec.DisplayName);
        var fingerprint = Escape(_createdFingerprint!);
        var portArg = string.IsNullOrWhiteSpace(_spec.LocalPortOrIcmp)
            ? ""
            : (_spec.Protocol.Contains("ICMP", StringComparison.OrdinalIgnoreCase)
                ? $"-IcmpType {_spec.LocalPortOrIcmp}"
                : $"-LocalPort {_spec.LocalPortOrIcmp}");

        // Create only — Enable is a separate call so partial failure can be recovered.
        var script = $@"
$ErrorActionPreference = 'Stop'
$name = '{name}'
if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {{ throw 'RULE_EXISTS:' + $name }}
New-NetFirewallRule -Name $name -DisplayName '{display}' -Direction Inbound -Action Allow -Enabled False -Profile Private -Protocol {proto} {portArg} -RemoteAddress {remote} -Description '{fingerprint}' -ErrorAction Stop | Out-Null
$r = Get-NetFirewallRule -Name $name -ErrorAction Stop
$port = $r | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object -First 1
$addr = $r | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object -First 1
if ($r.Enabled -eq $true -or [string]$r.Enabled -eq 'True') {{ throw 'CREATED_ENABLED_TOO_EARLY' }}
$remoteActual = [string]$addr.RemoteAddress
if ($remoteActual -ne '{remote}') {{ throw 'BAD_REMOTE_EXACT:' + $remoteActual }}
'CREATED:' + $name + '|FINGERPRINT:{fingerprint}'
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        var raw = (result.StdOut ?? "").Trim();
        var err = (result.StdErr ?? "").Trim();
        if (raw.Contains("RULE_EXISTS:", StringComparison.Ordinal) || err.Contains("RULE_EXISTS:", StringComparison.Ordinal))
            throw new RepairBlockedException("RULE_EXISTS: preexisting rule — no delete on rollback.");
        if (result.ExitCode != 0 || !raw.Contains("CREATED:", StringComparison.Ordinal))
            return (false, string.IsNullOrWhiteSpace(raw) ? (string.IsNullOrWhiteSpace(err) ? "Owned firewall create failed (no output)." : err) : raw);
        return (true, null);
    }

    private async Task<(bool Ok, string? Error)> RunEnableAsync(CancellationToken ct)
    {
        var name = Escape(_spec.RuleName);
        var script = $@"
$ErrorActionPreference = 'Stop'
$name = '{name}'
Enable-NetFirewallRule -Name $name -ErrorAction Stop
$v = Get-NetFirewallRule -Name $name -ErrorAction Stop
if (-not ($v.Enabled -eq $true -or [string]$v.Enabled -eq 'True')) {{ throw 'NOT_ENABLED' }}
'ENABLED:' + $name
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        var raw = (result.StdOut ?? "").Trim();
        if (result.ExitCode != 0 || !raw.Contains("ENABLED:", StringComparison.Ordinal))
            return (false, string.IsNullOrWhiteSpace(raw) ? (result.StdErr ?? "Enable failed.") : raw);
        return (true, null);
    }

    private async Task<(FirewallRulePresence Presence, OwnedRuleSnapshot? Snap, string? Raw)> QueryRuleAsync(CancellationToken ct)
    {
        var script = $@"
$ErrorActionPreference = 'Stop'
$r = Get-NetFirewallRule -Name '{Escape(_spec.RuleName)}' -ErrorAction SilentlyContinue
if (-not $r) {{ '{{""exists"":false}}'; exit 0 }}
$port = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Select-Object -First 1
$addr = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | Select-Object -First 1
[pscustomobject]@{{
  exists = $true
  Name = [string]$r.Name
  Enabled = $(if ($r.Enabled -eq $true -or [string]$r.Enabled -eq 'True') {{ $true }} elseif ($r.Enabled -eq $false -or [string]$r.Enabled -eq 'False') {{ $false }} else {{ $null }})
  Direction = [string]$r.Direction
  Action = [string]$r.Action
  Profile = [string]$r.Profile
  Protocol = $(if ($port) {{ [string]$port.Protocol }} else {{ $null }})
  LocalPort = $(if ($port) {{ [string]$port.LocalPort }} else {{ $null }})
  RemotePort = $(if ($port) {{ [string]$port.RemotePort }} else {{ $null }})
  IcmpType = $(if ($port) {{ [string]$port.IcmpType }} else {{ $null }})
  LocalAddress = $(if ($addr) {{ [string]$addr.LocalAddress }} else {{ $null }})
  RemoteAddress = $(if ($addr) {{ [string]$addr.RemoteAddress }} else {{ $null }})
  PolicyStore = [string]$r.PolicyStore
  Description = [string]$r.Description
  Program = $null
  Service = $null
}} | ConvertTo-Json -Compress
";
        ProcessResult result;
        try
        {
            result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        }
        catch (Exception)
        {
            return (FirewallRulePresence.Unknown, null, null);
        }

        if (result.ExitCode != 0)
            return (FirewallRulePresence.Unknown, null, result.StdOut);
        if (string.IsNullOrWhiteSpace(result.StdOut) || result.StdOut.Trim().Equals("null", StringComparison.OrdinalIgnoreCase))
            return (FirewallRulePresence.Unknown, null, result.StdOut);

        try
        {
            var raw = result.StdOut.Trim();
            using var doc = JsonDocument.Parse(raw);
            var el = doc.RootElement;
            var exists = el.TryGetProperty("exists", out var exEl) &&
                         (exEl.ValueKind == JsonValueKind.True ||
                          (exEl.ValueKind == JsonValueKind.String && exEl.GetString() is "True" or "true"));
            if (!exists)
                return (FirewallRulePresence.Absent, new OwnedRuleSnapshot { Exists = false }, raw);

            bool? enabled = null;
            if (el.TryGetProperty("Enabled", out var en))
            {
                if (en.ValueKind == JsonValueKind.True) enabled = true;
                else if (en.ValueKind == JsonValueKind.False) enabled = false;
                else if (en.ValueKind == JsonValueKind.String)
                    enabled = en.GetString() is "True" or "true" ? true : en.GetString() is "False" or "false" ? false : null;
            }

            var snap = new OwnedRuleSnapshot
            {
                Exists = true,
                Name = GetStr(el, "Name"),
                Enabled = enabled,
                Direction = GetStr(el, "Direction"),
                Action = GetStr(el, "Action"),
                Profile = GetStr(el, "Profile"),
                Protocol = GetStr(el, "Protocol"),
                LocalPort = GetStr(el, "LocalPort"),
                RemotePort = GetStr(el, "RemotePort"),
                IcmpType = GetStr(el, "IcmpType"),
                LocalAddress = GetStr(el, "LocalAddress"),
                RemoteAddress = GetStr(el, "RemoteAddress"),
                PolicyStore = GetStr(el, "PolicyStore"),
                Description = GetStr(el, "Description"),
                Program = GetStr(el, "Program"),
                Service = GetStr(el, "Service")
            };
            return (FirewallRulePresence.Present, snap, raw);
        }
        catch (JsonException)
        {
            return (FirewallRulePresence.Unknown, null, result.StdOut);
        }
    }

    /// <summary>Strict equality — NULL ≠ VALID; Any ≠ expected port/ICMP; compound profiles rejected.</summary>
    public bool MatchesDesired(OwnedRuleSnapshot s, bool requireEnabled)
    {
        if (!string.Equals(s.Name, _spec.RuleName, StringComparison.OrdinalIgnoreCase)) return false;

        if (requireEnabled && s.Enabled != true) return false;

        // Direction / Action — null is NOT valid.
        if (string.IsNullOrWhiteSpace(s.Direction) || !IsInbound(s.Direction)) return false;
        if (string.IsNullOrWhiteSpace(s.Action) || !IsAllow(s.Action)) return false;

        if (!FirewallRemoteAddress.ProfileIsPrivateOnly(s.Profile)) return false;
        if (!FirewallRemoteAddress.ExactMatch(s.RemoteAddress, _spec.RemoteAddress)) return false;

        if (string.IsNullOrWhiteSpace(s.Protocol)) return false;
        if (!string.IsNullOrWhiteSpace(_spec.Protocol) &&
            !ProtocolEquals(s.Protocol, _spec.Protocol))
            return false;

        if (!string.IsNullOrWhiteSpace(_spec.LocalPortOrIcmp))
        {
            if (_spec.Protocol.Contains("ICMP", StringComparison.OrdinalIgnoreCase))
            {
                // ICMPv4 Echo Request Type 8 — Any/null never match expected type.
                if (string.IsNullOrWhiteSpace(s.IcmpType)) return false;
                if (s.IcmpType.Equals("Any", StringComparison.OrdinalIgnoreCase)) return false;
                if (!IcmpTypeMatches(s.IcmpType, _spec.LocalPortOrIcmp)) return false;
            }
            else
            {
                if (string.IsNullOrWhiteSpace(s.LocalPort)) return false;
                if (s.LocalPort.Equals("Any", StringComparison.OrdinalIgnoreCase)) return false;
                if (!LocalPortMatches(s.LocalPort, _spec.LocalPortOrIcmp)) return false;
            }
        }

        if (s.PolicyStore is not null &&
            (s.PolicyStore.Contains("GP", StringComparison.OrdinalIgnoreCase) ||
             s.PolicyStore.Contains("GroupPolicy", StringComparison.OrdinalIgnoreCase)))
            return false;

        return true;
    }

    private bool HasOurProvenance(OwnedRuleSnapshot s)
    {
        if (string.IsNullOrWhiteSpace(s.Description)) return false;
        if (!string.IsNullOrWhiteSpace(_createdFingerprint) &&
            s.Description.Contains(_createdFingerprint, StringComparison.Ordinal))
            return true;
        if (!string.IsNullOrWhiteSpace(_transactionId) &&
            s.Description.Contains("tx:" + _transactionId, StringComparison.Ordinal))
            return true;
        return false;
    }

    private string BuildFingerprint(string tx)
        => $"tx:{tx}|op:{OperationId}|name:{_spec.RuleName}|remote:{_spec.RemoteAddress}";

    private static bool IsInbound(string d)
        => d.Equals("Inbound", StringComparison.OrdinalIgnoreCase)
           || d.Equals("In", StringComparison.OrdinalIgnoreCase)
           || d.Equals("1", StringComparison.Ordinal); // NetSecurity enum sometimes numeric

    private static bool IsAllow(string a)
        => a.Equals("Allow", StringComparison.OrdinalIgnoreCase)
           || a.Equals("2", StringComparison.Ordinal);

    private static bool ProtocolEquals(string actual, string expected)
    {
        if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)) return true;
        // Windows may report "TCP" vs "6" — accept only well-known synonyms, never substring Any.
        if (expected.Equals("TCP", StringComparison.OrdinalIgnoreCase) && actual is "6" or "TCP") return true;
        if (expected.Equals("UDP", StringComparison.OrdinalIgnoreCase) && actual is "17" or "UDP") return true;
        if (expected.Contains("ICMP", StringComparison.OrdinalIgnoreCase)
            && actual.Contains("ICMP", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static bool LocalPortMatches(string actual, string expected)
    {
        var parts = actual.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length == 1 && parts[0].Equals(expected, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IcmpTypeMatches(string actual, string expected)
    {
        // Windows may return "8", "Echo Request", or "8:0"
        if (actual.Equals(expected, StringComparison.OrdinalIgnoreCase)) return true;
        var parts = actual.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var p in parts)
        {
            var code = p.Split(':')[0];
            if (code.Equals(expected, StringComparison.OrdinalIgnoreCase)) return true;
            if (expected == "8" && p.Contains("Echo", StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    private static string? GetStr(JsonElement el, string name)
        => el.TryGetProperty(name, out var p) && p.ValueKind != JsonValueKind.Null ? p.ToString() : null;

    private static string Escape(string s) => s.Replace("'", "''");

    public sealed class OwnedRuleSnapshot
    {
        public bool Exists { get; init; }
        public string? Name { get; init; }
        public bool? Enabled { get; init; }
        public string? Direction { get; init; }
        public string? Action { get; init; }
        public string? Profile { get; init; }
        public string? Protocol { get; init; }
        public string? LocalPort { get; init; }
        public string? RemotePort { get; init; }
        public string? IcmpType { get; init; }
        public string? LocalAddress { get; init; }
        public string? RemoteAddress { get; init; }
        public string? PolicyStore { get; init; }
        public string? Description { get; init; }
        public string? Program { get; init; }
        public string? Service { get; init; }
    }
}

public enum FirewallRulePresence
{
    Present,
    Absent,
    Unknown
}

/// <summary>Exact RemoteAddress / Profile / CIDR helpers — no loose regex, no placeholder tokens.</summary>
public static class FirewallRemoteAddress
{
    public static bool IsSafeLanScope(string? remote)
    {
        if (string.IsNullOrWhiteSpace(remote)) return false;
        if (remote.Equals("Any", StringComparison.OrdinalIgnoreCase)) return false;
        if (remote.Equals("SPECIFIC_CIDR", StringComparison.OrdinalIgnoreCase)) return false;
        if (remote.Contains("0.0.0.0/0", StringComparison.OrdinalIgnoreCase)) return false;
        if (remote.Contains("::/0", StringComparison.OrdinalIgnoreCase)) return false;
        if (remote.Equals("LocalSubnet", StringComparison.OrdinalIgnoreCase)) return true;

        var parts = Split(remote);
        if (parts.Count == 0) return false;
        if (parts.Any(p => p.Equals("Any", StringComparison.OrdinalIgnoreCase))) return false;
        if (parts.Any(p => p.Equals("SPECIFIC_CIDR", StringComparison.OrdinalIgnoreCase))) return false;

        foreach (var p in parts)
        {
            if (p.Equals("LocalSubnet", StringComparison.OrdinalIgnoreCase)) continue;
            if (!TryValidateCidr(p, out _)) return false;
        }

        return true;
    }

    public static bool TryValidateCidr(string token, out string? reason)
    {
        reason = null;
        if (string.IsNullOrWhiteSpace(token))
        {
            reason = "empty";
            return false;
        }

        var slash = token.IndexOf('/');
        if (slash <= 0 || slash == token.Length - 1)
        {
            reason = "missing_prefix";
            return false;
        }

        var ipPart = token[..slash];
        var prefixPart = token[(slash + 1)..];
        if (!IPAddress.TryParse(ipPart, out var ip))
        {
            reason = "bad_ip";
            return false;
        }

        if (!int.TryParse(prefixPart, out var prefix) || prefix < 0)
        {
            reason = "bad_prefix";
            return false;
        }

        var max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix > max)
        {
            reason = "prefix_out_of_range";
            return false;
        }

        // Reject default routes / world-open scopes.
        if (prefix == 0)
        {
            reason = "prefix_zero";
            return false;
        }

        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
        {
            reason = "any_network";
            return false;
        }

        return true;
    }

    public static bool ExactMatch(string? actual, string expected)
    {
        var a = Split(actual);
        var e = Split(expected);
        if (a.Count != e.Count) return false;
        return a.SetEquals(e);
    }

    public static bool ProfileIsPrivateOnly(string? profile)
    {
        if (string.IsNullOrWhiteSpace(profile)) return false;
        if (profile.Contains("Public", StringComparison.OrdinalIgnoreCase)) return false;
        if (profile.Contains("Domain", StringComparison.OrdinalIgnoreCase)) return false;
        if (profile.Contains(',', StringComparison.Ordinal)) return false; // Private,Public etc.
        return profile.Equals("Private", StringComparison.OrdinalIgnoreCase)
               || profile.Equals("2", StringComparison.Ordinal); // NetSecurity Private enum
    }

    private static HashSet<string> Split(string? s)
        => new(
            (s ?? "").Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            StringComparer.OrdinalIgnoreCase);
}

public sealed class OwnedFirewallSpec
{
    public required string ShortId { get; init; }
    public required string RuleName { get; init; }
    public required string DisplayName { get; init; }
    public required string Title { get; init; }
    public required string Protocol { get; init; }
    public string? LocalPortOrIcmp { get; init; }
    public string RemoteAddress { get; init; } = "LocalSubnet";
    public string Profile { get; init; } = "Private";
    public RepairOwnerRole OwnerRole { get; init; } = RepairOwnerRole.LocalServer;

    public static OwnedFirewallSpec IcmpEchoPrivateLocalSubnet() => new()
    {
        ShortId = "ICMP4",
        RuleName = "MyPC.PrintDoctor.ICMPv4.Private",
        DisplayName = "MyPC PrintDoctor ICMPv4 Echo (Private/LocalSubnet)",
        Title = "Add owned ICMPv4 Echo allow (Private/LocalSubnet)",
        Protocol = "ICMPv4",
        LocalPortOrIcmp = "8",
        OwnerRole = RepairOwnerRole.LocalServer
    };

    public static OwnedFirewallSpec Smb445PrivateLocalSubnet() => new()
    {
        ShortId = "SMB445",
        RuleName = "MyPC.PrintDoctor.SMB445.Private",
        DisplayName = "MyPC PrintDoctor SMB 445 (Private/LocalSubnet)",
        Title = "Add owned SMB TCP/445 allow (Private/LocalSubnet)",
        Protocol = "TCP",
        LocalPortOrIcmp = "445",
        OwnerRole = RepairOwnerRole.LocalServer
    };

    public static OwnedFirewallSpec ShaPrint48631() => new()
    {
        ShortId = "SHA48631",
        RuleName = "MyPC.PrintDoctor.ShaPrint48631.Private",
        DisplayName = "MyPC PrintDoctor ShaPrint IPPS 48631",
        Title = "Add owned ShaPrint TCP/48631 allow (Private/LocalSubnet)",
        Protocol = "TCP",
        LocalPortOrIcmp = "48631",
        OwnerRole = RepairOwnerRole.LocalServer
    };

    public static OwnedFirewallSpec ShaPrint48633Udp() => new()
    {
        ShortId = "SHA48633",
        RuleName = "MyPC.PrintDoctor.ShaPrint48633.Private",
        DisplayName = "MyPC PrintDoctor ShaPrint Discovery UDP 48633",
        Title = "Add owned ShaPrint UDP/48633 discovery allow (Private/LocalSubnet)",
        Protocol = "UDP",
        LocalPortOrIcmp = "48633",
        OwnerRole = RepairOwnerRole.LocalServer
    };
}
