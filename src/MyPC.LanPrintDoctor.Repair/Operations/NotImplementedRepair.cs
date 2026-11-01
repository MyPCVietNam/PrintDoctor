using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Repair;

namespace MyPC.LanPrintDoctor.Repair.Operations;

/// <summary>
/// Explicit stub: never reports success. Used when a RepairId exists in findings
/// but no safe Windows implementation is wired yet.
/// </summary>
public sealed class NotImplementedRepair : IRepairOperation
{
    public NotImplementedRepair(string operationId, string title)
    {
        OperationId = operationId;
        Title = title;
    }

    public string OperationId { get; }
    public string Title { get; }
    public bool IsImplemented => false;
    public bool SupportsRollback => false;
    public RepairOwnerRole OwnerRole => RepairOwnerRole.None;
    public RepairTargetMachine TargetMachine => RepairTargetMachine.Local;

    public Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPrerequisiteResult
        {
            CanProceed = false,
            NotImplemented = true,
            RequiresAdmin = false,
            Reason = $"NOT_IMPLEMENTED: '{OperationId}' has no real Apply/Verify. Repair disabled."
        });

    public Task CollectEvidenceAsync(CancellationToken ct = default) => Task.CompletedTask;

    public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPreview
        {
            OperationId = OperationId,
            Title = Title,
            Description = "NOT_IMPLEMENTED — no system changes will be made.",
            Reversible = false
        });

    public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
        => throw new InvalidOperationException("NOT_IMPLEMENTED");

    public Task ApplyAsync(CancellationToken ct = default)
        => throw new InvalidOperationException("NOT_IMPLEMENTED: Apply is forbidden.");

    public Task<bool> VerifyAsync(CancellationToken ct = default)
        => Task.FromResult(false);

    public Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
        => Task.FromResult(new RollbackResult { Attempted = false, Unsupported = true, Message = "NOT_IMPLEMENTED" });
}
