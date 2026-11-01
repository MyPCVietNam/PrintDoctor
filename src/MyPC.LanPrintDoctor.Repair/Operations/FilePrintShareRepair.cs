using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

/// <summary>
/// Distinct from ICMP repair — enables File and Printer Sharing inbound group via language-independent group id.
/// </summary>
public sealed class FilePrintShareRepair : IRepairOperation
{
    private readonly IFirewallInspector _firewall;
    private readonly IElevationService _elevation;
    private string? _evidence;

    public FilePrintShareRepair(IFirewallInspector firewall, IElevationService elevation)
    {
        _firewall = firewall;
        _elevation = elevation;
    }

    public string OperationId => "FW-FILE-PRINT-SHARE";
    public string Title => "Enable File and Printer Sharing (Private)";
    public bool IsImplemented => true;
    public bool SupportsRollback => true;

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
            Description = "Enable File and Printer Sharing inbound rules for Private profile using FirewallAPI group id (works on VI/EN Windows). Does not enable SMB1 or disable signing.",
            Changes = new[]
            {
                "Enable-NetFirewallRule -Group '@FirewallAPI.dll,-28502' for Private",
                "Scope remains profile-bound; firewall stays on"
            },
            Risks = new[] { "Exposes SMB/printer sharing ports on Private profile" },
            Reversible = true
        });

    public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairBackup
        {
            BackupId = $"bak-{OperationId}-{Guid.NewGuid():N}",
            Path = "journal",
            CreatedAt = DateTimeOffset.UtcNow,
            PayloadJson = _evidence ?? "[]"
        });

    public async Task ApplyAsync(CancellationToken ct = default)
    {
        var ok = await _firewall.EnableFileAndPrinterSharingAsync(ct);
        if (!ok)
            throw new InvalidOperationException("Failed to enable File and Printer Sharing firewall group.");
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        var rules = await _firewall.GetRelevantRulesAsync(ct);
        return rules.Any(r =>
            r.Enabled &&
            r.Direction.Contains("In", StringComparison.OrdinalIgnoreCase) &&
            ((r.Grouping?.Contains("FirewallAPI.dll,-28502", StringComparison.OrdinalIgnoreCase) ?? false)
             || (r.Grouping?.Contains("File and Printer", StringComparison.OrdinalIgnoreCase) ?? false)
             || (r.Grouping?.Contains("Tệp và máy in", StringComparison.OrdinalIgnoreCase) ?? false)
             || (r.RuleId?.StartsWith("FPS-", StringComparison.OrdinalIgnoreCase) ?? false)));
    }

    public async Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
    {
        var restored = await _firewall.RestoreFileAndPrinterSharingFromBackupAsync(backup.PayloadJson ?? "[]", ct);
        return new RollbackResult
        {
            Attempted = true,
            Succeeded = restored,
            Verified = restored,
            Message = restored ? "Sharing firewall rules restored from backup." : "Sharing rollback not verified."
        };
    }
}
