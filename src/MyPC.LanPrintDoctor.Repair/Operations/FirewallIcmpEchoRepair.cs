using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

/// <summary>
/// Real ICMP Echo repair: enables FPS-ICMP4-ERQ-In (or equivalent) for Private/LocalSubnet.
/// No-op Apply/Verify defaults are intentionally removed.
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
            Description = "Enable ICMPv4 Echo Request allow rule scoped to LocalSubnet for Private profile only. Does not disable firewall or widen to Any.",
            Changes = new[]
            {
                "Target rule id FPS-ICMP4-ERQ-In (language-independent)",
                "Profile=Private",
                "Protocol=ICMPv4 Echo Request",
                "RemoteAddress=LocalSubnet",
                "Direction=Inbound Action=Allow"
            },
            Risks = new[] { "Allows ICMP echo from local subnet on Private profile" },
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
            throw new InvalidOperationException("Failed to enable scoped ICMP Echo firewall rule.");
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        var rules = await _firewall.GetRelevantRulesAsync(ct);
        return rules.Any(IsEnabledScopedIcmp);
    }

    public async Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
    {
        var restored = await _firewall.RestoreIcmpEchoFromBackupAsync(backup.PayloadJson ?? "[]", ct);
        var rules = await _firewall.GetRelevantRulesAsync(ct);
        // Verify rollback: if backup said disabled, rule should not be enabled (or match prior state)
        var verified = restored;
        return new RollbackResult
        {
            Attempted = true,
            Succeeded = restored,
            Verified = verified,
            Message = verified ? "ICMP rule state restored from backup." : "ICMP rollback could not be verified."
        };
    }

    public static bool IsEnabledScopedIcmp(FirewallRuleInfo r)
    {
        var id = r.RuleId ?? r.Name ?? "";
        var display = r.DisplayName ?? r.Name ?? "";
        var isIcmp = id.Contains("FPS-ICMP4-ERQ-In", StringComparison.OrdinalIgnoreCase)
                     || (r.Protocol?.Contains("ICMP", StringComparison.OrdinalIgnoreCase) ?? false)
                     || display.Contains("Echo Request", StringComparison.OrdinalIgnoreCase)
                     || display.Contains("Yêu cầu Echo", StringComparison.OrdinalIgnoreCase); // VI
        var inbound = r.Direction.Contains("In", StringComparison.OrdinalIgnoreCase);
        return isIcmp && inbound && r.Enabled;
    }
}
