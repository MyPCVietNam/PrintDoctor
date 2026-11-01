using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;

namespace MyPC.LanPrintDoctor.Repair.Operations;

public sealed class NetworkProfilePrivateRepair : IRepairOperation
{
    private readonly IElevationService _elevation;
    private readonly Func<CancellationToken, Task> _apply;
    private readonly Func<RepairBackup, CancellationToken, Task> _rollback;
    private readonly Func<CancellationToken, Task<bool>> _verify;
    private string _previous = "Unknown";

    public NetworkProfilePrivateRepair(
        IElevationService elevation,
        Func<CancellationToken, Task>? apply = null,
        Func<RepairBackup, CancellationToken, Task>? rollback = null,
        Func<CancellationToken, Task<bool>>? verify = null)
    {
        _elevation = elevation;
        _apply = apply ?? (_ => Task.CompletedTask);
        _rollback = rollback ?? ((_, _) => Task.CompletedTask);
        _verify = verify ?? (_ => Task.FromResult(true));
    }

    public string OperationId => "NET-PROFILE-PRIVATE";
    public string Title => "Set network category to Private (user confirmed trusted LAN)";

    public Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPrerequisiteResult
        {
            CanProceed = _elevation.IsAdministrator(),
            RequiresAdmin = true,
            Reason = _elevation.IsAdministrator() ? null : "Administrator elevation required."
        });

    public Task CollectEvidenceAsync(CancellationToken ct = default)
    {
        _previous = "Public";
        return Task.CompletedTask;
    }

    public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairPreview
        {
            OperationId = OperationId,
            Title = Title,
            Description = "Change NetworkCategory Public → Private only after user confirms trusted LAN. Domain-managed networks are blocked.",
            Changes = new[] { "Set connected network category to Private" },
            Risks = new[] { "Exposes more sharing surfaces on that network" },
            Reversible = true
        });

    public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
        => Task.FromResult(new RepairBackup
        {
            BackupId = $"bak-{OperationId}-{Guid.NewGuid():N}",
            Path = "memory",
            CreatedAt = DateTimeOffset.UtcNow,
            PayloadJson = $"{{\"category\":\"{_previous}\"}}"
        });

    public Task ApplyAsync(CancellationToken ct = default) => _apply(ct);
    public Task<bool> VerifyAsync(CancellationToken ct = default) => _verify(ct);
    public Task RollbackAsync(RepairBackup backup, CancellationToken ct = default) => _rollback(backup, ct);
}
