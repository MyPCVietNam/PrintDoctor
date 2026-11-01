using MyPC.LanPrintDoctor.Abstractions.Diagnostics;

namespace MyPC.LanPrintDoctor.Abstractions.Repair;

public sealed class RepairPrerequisiteResult
{
    public bool CanProceed { get; init; }
    public string? Reason { get; init; }
    public bool RequiresAdmin { get; init; }
}

public sealed class RepairPreview
{
    public required string OperationId { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    public IReadOnlyList<string> Changes { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Risks { get; init; } = Array.Empty<string>();
    public bool Reversible { get; init; }
}

public sealed class RepairBackup
{
    public required string BackupId { get; init; }
    public required string Path { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public string? PayloadJson { get; init; }
}

public sealed class RepairResult
{
    public required string OperationId { get; init; }
    public bool Applied { get; init; }
    public bool Verified { get; init; }
    public DiagnosticStatus Status { get; init; }
    public string? Message { get; init; }
    public string? BackupId { get; init; }
    public bool RolledBack { get; init; }
}

public interface IRepairOperation
{
    string OperationId { get; }
    string Title { get; }
    Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default);
    Task CollectEvidenceAsync(CancellationToken ct = default);
    Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default);
    Task<RepairBackup> BackupAsync(CancellationToken ct = default);
    Task ApplyAsync(CancellationToken ct = default);
    Task<bool> VerifyAsync(CancellationToken ct = default);
    Task RollbackAsync(RepairBackup backup, CancellationToken ct = default);
}
