using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

/// <summary>
/// Local-server ICMP Echo repair: Private + LocalSubnet only. Never group-enable.
/// </summary>
public sealed class FirewallIcmpEchoRepair : IRepairOperation
{
    private readonly IFirewallInspector _firewall;
    private readonly IElevationService _elevation;
    private string? _evidence;

    public FirewallIcmpEchoRepair(IFirewallInspector firewall, IElevationService elevation)
    {
        _firewall = firewall;
        _elevation = elevation;
    }

    public string OperationId => "FW-ICMP-ECHO";
    public string Title => "Enable scoped ICMP Echo Request rule";
    public bool IsImplemented => true;
    public bool SupportsRollback => true;
    public RepairOwnerRole OwnerRole => RepairOwnerRole.LocalServer;
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
            Description = "Enable FPS-ICMP4-ERQ-In only after setting Profile=Private and RemoteAddress=LocalSubnet. Does not enable group-wide rules or Public/Domain.",
            Changes = new[]
            {
                "Target rule id FPS-ICMP4-ERQ-In",
                "Set Profile=Private BEFORE Enable",
                "Set RemoteAddress=LocalSubnet BEFORE Enable",
                "Direction=Inbound Action=Allow",
                "Skip if PolicyStore indicates GPO"
            },
            Risks = new[] { "Allows ICMP echo from local subnet on Private profile only" },
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
        var ok = await _firewall.EnableScopedIcmpEchoAsync(ct);
        if (!ok)
            throw new InvalidOperationException("Failed to enable scoped ICMP Echo firewall rule (PowerShell did not return OK / scope verify failed).");
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        var rules = await _firewall.GetRelevantRulesAsync(ct);
        // Strict: ALL scope conditions via FirewallRuleScope — not merely Enabled=true
        return rules.Any(FirewallRuleScope.IsScopedIcmpEcho);
    }

    public async Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
    {
        var restored = await _firewall.RestoreIcmpEchoFromBackupAsync(backup.PayloadJson ?? "[]", ct);
        // Restore method itself re-reads and compares; do not claim verified on PowerShell OK alone
        return new RollbackResult
        {
            Attempted = true,
            Succeeded = restored,
            Verified = restored,
            Message = restored
                ? "ICMP rule attributes restored and re-read matched backup."
                : "ICMP rollback could not be verified against backup snapshot."
        };
    }

    public static bool IsEnabledScopedIcmp(FirewallRuleInfo r) => FirewallRuleScope.IsScopedIcmpEcho(r);
}
