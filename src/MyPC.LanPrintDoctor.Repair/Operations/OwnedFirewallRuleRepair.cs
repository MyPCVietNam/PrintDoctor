using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

/// <summary>
/// Creates PrintDoctor-owned firewall rules (Disabled → verify scope → Enable).
/// Never batch-enables system groups; never opens Public without explicit Private profile.
/// </summary>
public sealed class OwnedFirewallRuleRepair : IRepairOperation
{
    public const string RulePrefix = "MyPC.PrintDoctor.";

    private readonly IProcessRunner _runner;
    private readonly IElevationService _elevation;
    private readonly OwnedFirewallSpec _spec;
    private string? _backupJson;
    private string? _createdRuleName;

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

    public Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
    {
        if (!_elevation.IsAdministrator())
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Administrator required." });
        if (string.IsNullOrWhiteSpace(_spec.RuleName) || !_spec.RuleName.StartsWith(RulePrefix, StringComparison.Ordinal))
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Rule must use MyPC.PrintDoctor.* prefix." });
        if (!_spec.Profile.Equals("Private", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "Owned rules are Private-only." });
        if (string.IsNullOrWhiteSpace(_spec.RemoteAddress) || _spec.RemoteAddress.Equals("Any", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(new RepairPrerequisiteResult { CanProceed = false, RequiresAdmin = true, Reason = "RemoteAddress must be LocalSubnet or confirmed CIDR — not Any." });
        return Task.FromResult(new RepairPrerequisiteResult { CanProceed = true, RequiresAdmin = true });
    }

    public Task CollectEvidenceAsync(CancellationToken ct = default) => Task.CompletedTask;

    public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPreview
        {
            OperationId = OperationId,
            Title = Title,
            Description = $"Create owned rule {_spec.RuleName} Disabled → verify scope → Enable. Profile=Private Remote={_spec.RemoteAddress}.",
            Changes = new[]
            {
                $"New-NetFirewallRule -Name {_spec.RuleName} (Enabled=False)",
                $"Set scope Protocol={_spec.Protocol} Port/ICMP={_spec.LocalPortOrIcmp} Remote={_spec.RemoteAddress}",
                "Enable only after re-read confirms scope"
            },
            Risks = new[] { "Adds inbound allow on Private/LocalSubnet for the specified protocol only" },
            Reversible = true
        });

    public async Task<RepairBackup> BackupAsync(CancellationToken ct = default)
    {
        var script = $"Get-NetFirewallRule -Name '{Escape(_spec.RuleName)}' -ErrorAction SilentlyContinue | Select-Object Name,Enabled,Direction,Action,Profile,PolicyStore | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        _backupJson = string.IsNullOrWhiteSpace(result.StdOut) ? "null" : result.StdOut.Trim();
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
        // Create Disabled with full scope, re-read, then Enable — never Enabled with wide scope.
        var proto = Escape(_spec.Protocol);
        var remote = Escape(_spec.RemoteAddress);
        var name = Escape(_spec.RuleName);
        var display = Escape(_spec.DisplayName);
        var portArg = string.IsNullOrWhiteSpace(_spec.LocalPortOrIcmp)
            ? ""
            : (_spec.Protocol.Contains("ICMP", StringComparison.OrdinalIgnoreCase)
                ? $"-IcmpType {_spec.LocalPortOrIcmp}"
                : $"-LocalPort {_spec.LocalPortOrIcmp}");

        var script = $@"
$ErrorActionPreference = 'Stop'
$name = '{name}'
if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {{ throw 'RULE_EXISTS:' + $name }}
New-NetFirewallRule -Name $name -DisplayName '{display}' -Direction Inbound -Action Allow -Enabled False -Profile Private -Protocol {proto} {portArg} -RemoteAddress {remote} -ErrorAction Stop | Out-Null
$r = Get-NetFirewallRule -Name $name -ErrorAction Stop
$addr = Get-NetFirewallRule -Name $name | Get-NetFirewallAddressFilter -ErrorAction Stop
if ($r.Enabled -eq $true -or [string]$r.Enabled -eq 'True') {{ throw 'CREATED_ENABLED_TOO_EARLY' }}
if ([string]$r.Profile -notmatch 'Private' -or [string]$r.Profile -match 'Public|Domain') {{ throw 'BAD_PROFILE' }}
if ([string]$addr.RemoteAddress -notmatch '{remote}') {{ throw 'BAD_REMOTE:' + $addr.RemoteAddress }}
Enable-NetFirewallRule -Name $name -ErrorAction Stop
$v = Get-NetFirewallRule -Name $name -ErrorAction Stop
if (-not ($v.Enabled -eq $true -or [string]$v.Enabled -eq 'True')) {{ throw 'NOT_ENABLED' }}
'CHANGED:' + $name
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        var raw = (result.StdOut ?? "").Trim();
        if (result.ExitCode != 0 || !raw.Contains("CHANGED:", StringComparison.Ordinal))
            throw new InvalidOperationException(raw.Length > 0 ? raw : (result.StdErr ?? "Owned firewall rule apply failed."));
        _createdRuleName = _spec.RuleName;
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        var script = $@"
$ErrorActionPreference = 'Stop'
$r = Get-NetFirewallRule -Name '{Escape(_spec.RuleName)}' -ErrorAction Stop
$addr = Get-NetFirewallRule -Name '{Escape(_spec.RuleName)}' | Get-NetFirewallAddressFilter -ErrorAction Stop
$ok = ($r.Enabled -eq $true -or [string]$r.Enabled -eq 'True') -and ([string]$r.Profile -match 'Private') -and ([string]$r.Profile -notmatch 'Public|Domain') -and ([string]$addr.RemoteAddress -match '{Escape(_spec.RemoteAddress)}')
if ($ok) {{ 'PASS' }} else {{ 'FAIL:' + $r.Enabled + '/' + $r.Profile + '/' + $addr.RemoteAddress }}
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        return result.ExitCode == 0 && (result.StdOut ?? "").Contains("PASS", StringComparison.Ordinal);
    }

    public async Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
    {
        var name = Escape(_createdRuleName ?? _spec.RuleName);
        // Owned rules created by this transaction are removed (not system rules).
        var script = $@"
$ErrorActionPreference = 'Stop'
$r = Get-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue
if (-not $r) {{ 'OK:GONE'; exit 0 }}
if ($r.Name -notlike 'MyPC.PrintDoctor.*') {{ throw 'REFUSE_DELETE_NON_OWNED' }}
Remove-NetFirewallRule -Name '{name}' -ErrorAction Stop
'OK:REMOVED'
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        var ok = result.ExitCode == 0 && (result.StdOut ?? "").Contains("OK:", StringComparison.Ordinal);
        return new RollbackResult
        {
            Attempted = true,
            Succeeded = ok,
            Verified = ok,
            Message = ok ? "Owned rule removed." : (result.StdErr ?? result.StdOut ?? "rollback failed")
        };
    }

    private static string Escape(string s) => s.Replace("'", "''");
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

    /// <summary>UDP discovery only — never opens TCP 48632 (client loopback proxy) to LAN.</summary>
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
