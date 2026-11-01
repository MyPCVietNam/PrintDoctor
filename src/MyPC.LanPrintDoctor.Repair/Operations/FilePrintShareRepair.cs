using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

public sealed class FilePrintShareRepair : IRepairOperation
{
    private readonly IFirewallInspector _firewall;
    private readonly IElevationService _elevation;
    private string? _evidence;
    private List<string> _changedRuleIds = new();

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
            Description = "Enable approved FPS rules by name only. RemoteAddress=LocalSubnet must succeed before Enable. Never Enable-NetFirewallRule -Group. Public rules untouched.",
            Changes = FirewallRuleScope.ApprovedFpsRuleIds.Select(id => $"Scope+Enable {id} (Private/LocalSubnet)").ToArray(),
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
        var result = await _firewall.EnableFileAndPrinterSharingAsync(ct);
        // Record every id mutated in this transaction — even when Apply fails mid-loop.
        _changedRuleIds = result.ChangedRuleIds.ToList();
        if (!result.Success)
            throw new InvalidOperationException(
                (result.Detail ?? "Scoped FPS enable failed.")
                + (_changedRuleIds.Count > 0 ? " PARTIAL_CHANGED:" + string.Join(',', _changedRuleIds) : ""));
        if (_changedRuleIds.Count == 0)
            throw new InvalidOperationException("No changed FPS rule ids recorded.");
    }

    public async Task<bool> VerifyAsync(CancellationToken ct = default)
    {
        if (_changedRuleIds.Count == 0) return false;
        var rules = await _firewall.GetRelevantRulesAsync(ct);
        if (!FirewallRuleScope.AllChangedSatisfy(rules, _changedRuleIds, FirewallRuleScope.IsScopedFilePrintShareRule))
            return false;
        // Public copies must not have been enabled as part of this repair
        var badPublic = rules.Any(r =>
            r.Enabled
            && (r.Profiles?.Contains("Public", StringComparison.OrdinalIgnoreCase) ?? false)
            && _changedRuleIds.Any(id => string.Equals(id, r.RuleId, StringComparison.OrdinalIgnoreCase)));
        return !badPublic;
    }

    public async Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
    {
        if (_changedRuleIds.Count == 0)
        {
            return new RollbackResult
            {
                Attempted = false,
                Succeeded = false,
                Verified = false,
                Message = "No changed rule ids in transaction — refusing to restore unrelated FPS rules."
            };
        }

        var payload = FirewallIcmpEchoRepair.FilterBackupToChanged(backup.PayloadJson ?? "[]", _changedRuleIds);
        var restored = await _firewall.RestoreFileAndPrinterSharingFromBackupAsync(payload, ct);
        // Never claim Verified unless re-read matched backup for every changed id.
        return new RollbackResult
        {
            Attempted = true,
            Succeeded = restored.Succeeded,
            Verified = restored.Verified && !restored.Partial,
            Partial = restored.Partial || !restored.Verified,
            Message = restored.Message
        };
    }
}
