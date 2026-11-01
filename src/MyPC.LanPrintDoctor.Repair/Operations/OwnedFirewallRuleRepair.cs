using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

/// <summary>
/// Creates PrintDoctor-owned firewall rules (Disabled → verify exact scope → Enable).
/// P21-001: Rollback deletes ONLY rules created in this transaction (provenance), never preexisting.
/// P21-002: Verify uses exact field equality — LocalSubnet,Any ≠ LocalSubnet.
/// </summary>
public sealed class OwnedFirewallRuleRepair : IRepairOperation
{
    public const string RulePrefix = "MyPC.PrintDoctor.";

    private readonly IProcessRunner _runner;
    private readonly IElevationService _elevation;
    private readonly OwnedFirewallSpec _spec;
    private string? _backupJson;
    private string? _transactionId;
    private string? _createdFingerprint;
    private bool _createdInThisTransaction;
    private bool _preexistingPresent;

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

    public Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
    {
        if (!_elevation.IsAdministrator())
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Administrator required." });
        if (string.IsNullOrWhiteSpace(_spec.RuleName) || !_spec.RuleName.StartsWith(RulePrefix, StringComparison.Ordinal))
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Rule must use MyPC.PrintDoctor.* prefix." });
        if (!_spec.Profile.Equals("Private", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Owned rules are Private-only." });
        if (!FirewallRemoteAddress.IsSafeLanScope(_spec.RemoteAddress))
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "RemoteAddress must be LocalSubnet or confirmed LAN CIDR — not Any/0.0.0.0/0." });
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
        var script = $@"
$ErrorActionPreference = 'Stop'
$r = Get-NetFirewallRule -Name '{Escape(_spec.RuleName)}' -ErrorAction SilentlyContinue
if (-not $r) {{ '{{""exists"":false}}'; exit 0 }}
$port = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Select-Object -First 1
$addr = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | Select-Object -First 1
[pscustomobject]@{{
  exists = $true
  Name = [string]$r.Name
  Enabled = $(if ($null -eq $r.Enabled) {{ $null }} elseif ($r.Enabled -is [bool]) {{ [bool]$r.Enabled }} else {{ [string]$r.Enabled }})
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
  DisplayName = [string]$r.DisplayName
}} | ConvertTo-Json -Compress
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0)
            throw new InvalidOperationException("BACKUP_FAILED: " + (result.StdErr ?? result.StdOut ?? "Get-NetFirewallRule failed"));
        var raw = (result.StdOut ?? "").Trim();
        if (string.IsNullOrWhiteSpace(raw) || raw.Equals("null", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("BACKUP_FAILED: empty or literal null payload — refusing to treat as valid absence.");
        try
        {
            using var doc = JsonDocument.Parse(raw);
            _preexistingPresent = doc.RootElement.TryGetProperty("exists", out var ex) &&
                                  (ex.ValueKind == JsonValueKind.True ||
                                   (ex.ValueKind == JsonValueKind.String && ex.GetString() is "True" or "true"));
        }
        catch (JsonException jx)
        {
            throw new InvalidOperationException("BACKUP_FAILED: invalid JSON — " + jx.Message);
        }

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
        _transactionId ??= Guid.NewGuid().ToString("N");
        _createdInThisTransaction = false;
        _createdFingerprint = null;

        // Evaluate preexisting from backup / live read — never RULE_EXISTS → destructive rollback.
        var existing = await ReadRuleSnapshotAsync(ct);
        if (existing is { Exists: true })
        {
            if (MatchesDesired(existing))
                throw new RepairNoChangeException($"ALREADY_CONFIGURED:{_spec.RuleName}");
            throw new RepairBlockedException(
                $"RULE_EXISTS_MISMATCH:{_spec.RuleName} — preexisting rule present with different scope/provenance; " +
                "refusing overwrite/delete. Use a dedicated consent repair after explicit snapshot.");
        }

        var proto = Escape(_spec.Protocol);
        var remote = Escape(_spec.RemoteAddress);
        var name = Escape(_spec.RuleName);
        var display = Escape(_spec.DisplayName);
        var fingerprint = $"tx:{_transactionId}|op:{OperationId}|name:{_spec.RuleName}|remote:{_spec.RemoteAddress}";
        var portArg = string.IsNullOrWhiteSpace(_spec.LocalPortOrIcmp)
            ? ""
            : (_spec.Protocol.Contains("ICMP", StringComparison.OrdinalIgnoreCase)
                ? $"-IcmpType {_spec.LocalPortOrIcmp}"
                : $"-LocalPort {_spec.LocalPortOrIcmp}");

        var script = $@"
$ErrorActionPreference = 'Stop'
$name = '{name}'
if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {{ throw 'RULE_EXISTS:' + $name }}
New-NetFirewallRule -Name $name -DisplayName '{display}' -Direction Inbound -Action Allow -Enabled False -Profile Private -Protocol {proto} {portArg} -RemoteAddress {remote} -Description '{Escape(fingerprint)}' -ErrorAction Stop | Out-Null
$r = Get-NetFirewallRule -Name $name -ErrorAction Stop
$port = $r | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object -First 1
$addr = $r | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object -First 1
if ($r.Enabled -eq $true -or [string]$r.Enabled -eq 'True') {{ throw 'CREATED_ENABLED_TOO_EARLY' }}
if ([string]$r.Profile -ne 'Private' -and [string]$r.Profile -notmatch '^Private$') {{
  if ([string]$r.Profile -match 'Public|Domain' -or [string]$r.Profile -notmatch 'Private') {{ throw 'BAD_PROFILE:' + $r.Profile }}
}}
$remoteActual = [string]$addr.RemoteAddress
if ($remoteActual -ne '{remote}') {{ throw 'BAD_REMOTE_EXACT:' + $remoteActual }}
Enable-NetFirewallRule -Name $name -ErrorAction Stop
$v = Get-NetFirewallRule -Name $name -ErrorAction Stop
if (-not ($v.Enabled -eq $true -or [string]$v.Enabled -eq 'True')) {{ throw 'NOT_ENABLED' }}
'CHANGED:' + $name + '|FINGERPRINT:{Escape(fingerprint)}'
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        var raw = (result.StdOut ?? "").Trim();
        if (result.ExitCode != 0 || !raw.Contains("CHANGED:", StringComparison.Ordinal))
        {
            // Never mark created — rollback must not delete preexisting.
            if (raw.Contains("RULE_EXISTS:", StringComparison.Ordinal) || (result.StdErr ?? "").Contains("RULE_EXISTS:", StringComparison.Ordinal))
                throw new RepairBlockedException("RULE_EXISTS: preexisting rule — no delete on rollback.");
            throw new InvalidOperationException(raw.Length > 0 ? raw : (result.StdErr ?? "Owned firewall rule apply failed."));
        }

        _createdInThisTransaction = true;
        _createdFingerprint = fingerprint;
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        var snap = await ReadRuleSnapshotAsync(ct);
        return snap is { Exists: true } && MatchesDesired(snap) && snap.Enabled == true;
    }

    public async Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
    {
        // CRITICAL P21-001: never delete unless this transaction created the rule.
        if (!_createdInThisTransaction || string.IsNullOrWhiteSpace(_createdFingerprint))
        {
            return new RollbackResult
            {
                Attempted = false,
                Succeeded = true,
                Verified = true,
                Message = "NO_DELETE_PREEXISTING: Apply did not create a rule in this transaction — refusing Remove-NetFirewallRule."
            };
        }

        var name = Escape(_spec.RuleName);
        var fp = Escape(_createdFingerprint);
        var script = $@"
$ErrorActionPreference = 'Stop'
$r = Get-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue
if (-not $r) {{ 'OK:GONE'; exit 0 }}
if ($r.Name -notlike 'MyPC.PrintDoctor.*') {{ throw 'REFUSE_DELETE_NON_OWNED' }}
$desc = [string]$r.Description
if ($desc -notlike '*{fp}*' -and $desc -notlike '*tx:*') {{
  # Fingerprint missing / foreign rewrite after create → conflict, do not delete.
  throw 'PROVENANCE_MISMATCH:' + $desc
}}
if ($desc -notlike '*{fp}*') {{ throw 'PROVENANCE_MISMATCH:' + $desc }}
Remove-NetFirewallRule -Name '{name}' -ErrorAction Stop
'OK:REMOVED'
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        var raw = (result.StdOut ?? "").Trim();
        var ok = result.ExitCode == 0 && raw.Contains("OK:", StringComparison.Ordinal);
        return new RollbackResult
        {
            Attempted = true,
            Succeeded = ok,
            Verified = ok,
            Message = ok ? "Transaction-created owned rule removed." : (result.StdErr ?? raw ?? "rollback failed")
        };
    }

    private async Task<OwnedRuleSnapshot?> ReadRuleSnapshotAsync(CancellationToken ct)
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
}} | ConvertTo-Json -Compress
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return null;
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut.Trim());
            var el = doc.RootElement;
            var exists = el.TryGetProperty("exists", out var ex) &&
                         (ex.ValueKind == JsonValueKind.True ||
                          (ex.ValueKind == JsonValueKind.String && ex.GetString() is "True" or "true"));
            if (!exists) return new OwnedRuleSnapshot { Exists = false };
            bool? enabled = null;
            if (el.TryGetProperty("Enabled", out var en))
            {
                if (en.ValueKind == JsonValueKind.True) enabled = true;
                else if (en.ValueKind == JsonValueKind.False) enabled = false;
                else if (en.ValueKind == JsonValueKind.String)
                    enabled = en.GetString() is "True" or "true" ? true : en.GetString() is "False" or "false" ? false : null;
            }

            return new OwnedRuleSnapshot
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
                Description = GetStr(el, "Description")
            };
        }
        catch
        {
            return null;
        }
    }

    private bool MatchesDesired(OwnedRuleSnapshot s)
    {
        if (!string.Equals(s.Name, _spec.RuleName, StringComparison.OrdinalIgnoreCase)) return false;
        if (s.Direction is not null && !s.Direction.Contains("In", StringComparison.OrdinalIgnoreCase)) return false;
        if (s.Action is not null && !s.Action.Contains("Allow", StringComparison.OrdinalIgnoreCase)) return false;
        if (!FirewallRemoteAddress.ProfileIsPrivateOnly(s.Profile)) return false;
        if (!FirewallRemoteAddress.ExactMatch(s.RemoteAddress, _spec.RemoteAddress)) return false;
        if (!string.IsNullOrWhiteSpace(_spec.Protocol) &&
            !string.Equals(s.Protocol, _spec.Protocol, StringComparison.OrdinalIgnoreCase) &&
            !(s.Protocol?.Contains(_spec.Protocol, StringComparison.OrdinalIgnoreCase) ?? false))
            return false;
        if (!string.IsNullOrWhiteSpace(_spec.LocalPortOrIcmp))
        {
            if (_spec.Protocol.Contains("ICMP", StringComparison.OrdinalIgnoreCase))
            {
                if (!(s.IcmpType?.Contains(_spec.LocalPortOrIcmp, StringComparison.OrdinalIgnoreCase) ?? false) &&
                    s.IcmpType is not null && s.IcmpType != "Any")
                    return false;
            }
            else if (!(s.LocalPort?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                         .Contains(_spec.LocalPortOrIcmp, StringComparer.OrdinalIgnoreCase) ?? false) &&
                     s.LocalPort is not null && !s.LocalPort.Equals("Any", StringComparison.OrdinalIgnoreCase))
            {
                // If LocalPort reported and doesn't include expected → fail
                if (!string.Equals(s.LocalPort, _spec.LocalPortOrIcmp, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
        }

        if (s.PolicyStore is not null &&
            (s.PolicyStore.Contains("GP", StringComparison.OrdinalIgnoreCase) ||
             s.PolicyStore.Contains("GroupPolicy", StringComparison.OrdinalIgnoreCase)))
            return false;
        return true;
    }

    private static string? GetStr(JsonElement el, string name)
        => el.TryGetProperty(name, out var p) && p.ValueKind != JsonValueKind.Null ? p.ToString() : null;

    private static string Escape(string s) => s.Replace("'", "''");

    private sealed class OwnedRuleSnapshot
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
    }
}

/// <summary>Exact RemoteAddress / Profile scope helpers — no loose regex.</summary>
public static class FirewallRemoteAddress
{
    public static bool IsSafeLanScope(string? remote)
    {
        if (string.IsNullOrWhiteSpace(remote)) return false;
        if (remote.Equals("Any", StringComparison.OrdinalIgnoreCase)) return false;
        if (remote.Contains("0.0.0.0/0", StringComparison.OrdinalIgnoreCase)) return false;
        if (remote.Contains("::/0", StringComparison.OrdinalIgnoreCase)) return false;
        // Simulation / advanced: explicit LocalSubnet or confirmed CIDR token (never Any).
        if (remote.Equals("LocalSubnet", StringComparison.OrdinalIgnoreCase)) return true;
        if (remote.Equals("SPECIFIC_CIDR", StringComparison.OrdinalIgnoreCase)) return true;
        if (remote.Contains('/')) return true; // CIDR notation
        var parts = Split(remote);
        if (parts.Count == 0) return false;
        if (parts.Any(p => p.Equals("Any", StringComparison.OrdinalIgnoreCase))) return false;
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
        return profile.Contains("Private", StringComparison.OrdinalIgnoreCase);
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
