using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

/// <summary>
/// Enables only named FPS inbound rules after Private+LocalSubnet — never Enable-NetFirewallRule -Group.
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
    public string Title => "Enable File and Printer Sharing (Private/LocalSubnet)";
    public bool IsImplemented => true;
    public bool SupportsRollback => true;
    public RepairOwnerRole OwnerRole => RepairOwnerRole.LocalAny;
    public RepairTargetMachine TargetMachine => RepairTargetMachine.Local;

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
            Description = "Enable approved FPS inbound rules by name (SMB/Spooler/NBSession) for Private+LocalSubnet only. Does NOT call Enable-NetFirewallRule -Group.",
            Changes = new[]
            {
                "Per-rule Set-NetFirewallRule -Profile Private before Enable",
                "RemoteAddress=LocalSubnet where supported",
                "Skip GPO-managed rules",
                "No Public/Domain enablement"
            },
            Risks = new[] { "Exposes SMB/printer sharing on Private/LocalSubnet" },
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
            throw new InvalidOperationException("Failed to enable scoped File and Printer Sharing rules.");
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        var rules = await _firewall.GetRelevantRulesAsync(ct);
        // At least one scoped FPS rule; and no newly enabled Public-only FPS rule claimed as success
        var scoped = rules.Where(FirewallRuleScope.IsScopedFilePrintShareRule).ToList();
        if (scoped.Count == 0) return false;
        // Fail verify if any enabled FPS inbound rule is Public without Private
        var badPublic = rules.Any(r =>
            r.Enabled
            && r.Direction.Contains("In", StringComparison.OrdinalIgnoreCase)
            && ((r.RuleId ?? "").StartsWith("FPS-", StringComparison.OrdinalIgnoreCase)
                || (r.Grouping?.Contains("FirewallAPI.dll,-28502") ?? false))
            && (r.Profiles?.Contains("Public", StringComparison.OrdinalIgnoreCase) ?? false)
            && !(r.Profiles?.Contains("Private", StringComparison.OrdinalIgnoreCase) ?? false));
        return !badPublic;
    }

    public async Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
    {
        var restored = await _firewall.RestoreFileAndPrinterSharingFromBackupAsync(backup.PayloadJson ?? "[]", ct);
        return new RollbackResult
        {
            Attempted = true,
            Succeeded = restored,
            Verified = restored,
            Message = restored
                ? "Sharing firewall rules restored and re-read matched backup."
                : "Sharing rollback not verified against backup."
        };
    }
}
