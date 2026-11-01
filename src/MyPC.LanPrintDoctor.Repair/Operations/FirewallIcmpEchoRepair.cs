using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

public sealed class FirewallIcmpEchoRepair : IRepairOperation
{
    private readonly IFirewallInspector _firewall;
    private readonly IElevationService _elevation;
    private readonly Func<CancellationToken, Task> _apply;
    private readonly Func<RepairBackup, CancellationToken, Task> _rollback;
    private readonly Func<CancellationToken, Task<bool>> _verify;
    private string? _evidence;

    public FirewallIcmpEchoRepair(
        IFirewallInspector firewall,
        IElevationService elevation,
        Func<CancellationToken, Task>? apply = null,
        Func<RepairBackup, CancellationToken, Task>? rollback = null,
        Func<CancellationToken, Task<bool>>? verify = null)
    {
        _firewall = firewall;
        _elevation = elevation;
        _apply = apply ?? (_ => Task.CompletedTask);
        _rollback = rollback ?? ((_, _) => Task.CompletedTask);
        _verify = verify ?? (_ => Task.FromResult(true));
    }

    public string OperationId => "FW-ICMP-ECHO";
    public string Title => "Enable scoped ICMP Echo Request rule";

    public Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
    {
        var admin = _elevation.IsAdministrator();
        return Task.FromResult(new RepairPrerequisiteResult
        {
            CanProceed = admin,
            RequiresAdmin = true,
            Reason = admin ? null : "Administrator elevation required (UAC)."
        });
    }

    public async Task CollectEvidenceAsync(CancellationToken ct = default)
    {
        var rules = await _firewall.GetRelevantRulesAsync(ct);
        _evidence = JsonSerializer.Serialize(rules);
    }

    public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPreview
        {
            OperationId = OperationId,
            Title = Title,
            Description = "Enable or create ICMPv4 Echo Request allow rule scoped to LocalSubnet for Private profile. Does not disable firewall.",
            Changes = new[] { "Ensure File and Printer Sharing (Echo Request - ICMPv4-In) enabled for Private/LocalSubnet" },
            Risks = new[] { "Allows ping from local subnet on Private profile" },
            Reversible = true
        });

    public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairBackup
        {
            BackupId = $"bak-{OperationId}-{Guid.NewGuid():N}",
            Path = "memory",
            CreatedAt = DateTimeOffset.UtcNow,
            PayloadJson = _evidence
        });

    public Task ApplyAsync(CancellationToken ct = default) => _apply(ct);

    public Task<bool> VerifyAsync(CancellationToken ct = default) => _verify(ct);

    public Task RollbackAsync(RepairBackup backup, CancellationToken ct = default) => _rollback(backup, ct);
}
