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
    private string? _evidence;
    private List<string> _changedRuleIds = new();

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
    public IReadOnlyList<string> LastChangedRuleIds => _changedRuleIds;

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
            Description = "Enable FPS-ICMP4-ERQ-In only after Profile=Private and RemoteAddress=LocalSubnet succeed. Enable is aborted if scope set fails.",
            Changes = new[]
            {
                "Set Profile=Private + RemoteAddress=LocalSubnet (Stop on failure)",
                "Enable only after scope re-read confirms LocalSubnet",
                "Changed-rule list recorded for Verify (not any matching rule)",
                "Skip GPO-managed rules"
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
        var result = await _firewall.EnableScopedIcmpEchoAsync(ct);
        // Always capture ids actually mutated — including mid-failure partial lists.
        _changedRuleIds = result.ChangedRuleIds.ToList();
        if (!result.Success)
            throw new InvalidOperationException(
                (result.Detail ?? "Scoped ICMP enable failed (Enable not applied without scope).")
                + ( _changedRuleIds.Count > 0 ? " PARTIAL_CHANGED:" + string.Join(',', _changedRuleIds) : ""));
        if (_changedRuleIds.Count == 0)
            throw new InvalidOperationException("No changed rule ids recorded — refusing success.");
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        if (_changedRuleIds.Count == 0) return false;
        var rules = await _firewall.GetRelevantRulesAsync(ct);
        // ALL changed rules must satisfy scoped ICMP — one bad ⇒ fail
        return FirewallRuleScope.AllChangedSatisfy(rules, _changedRuleIds, FirewallRuleScope.IsScopedIcmpEcho);
    }

    public async Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
    {
        // Only restore rules belonging to this transaction's changed-id list.
        var payload = FilterBackupToChanged(backup.PayloadJson ?? "[]", _changedRuleIds);
        if (_changedRuleIds.Count == 0)
        {
            return new RollbackResult
            {
                Attempted = false,
                Succeeded = false,
                Verified = false,
                Message = "No changed rule ids in transaction — refusing to touch unrelated firewall rules."
            };
        }

        var restored = await _firewall.RestoreIcmpEchoFromBackupAsync(payload, ct);
        return new RollbackResult
        {
            Attempted = true,
            Succeeded = restored.Succeeded,
            Verified = restored.Verified && !restored.Partial,
            Partial = restored.Partial,
            Message = restored.Message ?? (restored.Verified ? "verified" : "not verified")
        };
    }

    internal static string FilterBackupToChanged(string backupJson, IReadOnlyList<string> changedIds)
    {
        if (changedIds.Count == 0) return "[]";
        try
        {
            var all = JsonSerializer.Deserialize<List<FirewallRuleInfo>>(backupJson) ?? new();
            var filtered = all.Where(r =>
                changedIds.Any(id => string.Equals(id, r.RuleId ?? r.Name, StringComparison.OrdinalIgnoreCase))).ToList();
            return JsonSerializer.Serialize(filtered);
        }
        catch
        {
            return "[]";
        }
    }

    public static bool IsEnabledScopedIcmp(FirewallRuleInfo r) => FirewallRuleScope.IsScopedIcmpEcho(r);
}
