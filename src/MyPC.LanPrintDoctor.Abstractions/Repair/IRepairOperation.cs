using MyPC.LanPrintDoctor.Abstractions.Diagnostics;

namespace MyPC.LanPrintDoctor.Abstractions.Repair;

public enum RepairTargetMachine
{
    Local,
    RemoteUnsupported
}

public sealed class RepairPrerequisiteResult
{
    public bool CanProceed { get; init; }
    public string? Reason { get; init; }
    public bool RequiresAdmin { get; init; }
    public bool NotImplemented { get; init; }
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

public sealed class RollbackResult
{
    public bool Attempted { get; init; }
    public bool Succeeded { get; init; }
    public bool Verified { get; init; }
    public bool Unsupported { get; init; }
    public string? Message { get; init; }
}

public sealed class RepairResult
{
    public required string OperationId { get; init; }
    public string? TransactionId { get; init; }
    public bool Applied { get; init; }
    public bool Verified { get; init; }
    public DiagnosticStatus Status { get; init; }
    public string? Message { get; init; }
    public string? BackupId { get; init; }
    public bool RolledBack { get; init; }
    public bool RollbackAttempted { get; init; }
    public bool RollbackVerified { get; init; }
    public bool RollbackUnsupported { get; init; }
    public bool NotImplemented { get; init; }
    public bool UncertainState { get; init; }
    public bool ServerActionRequired { get; init; }
}

public interface IRepairOperation
{
    string OperationId { get; }
    string Title { get; }

    /// <summary>False when the operation has no real Apply/Verify implementation.</summary>
    bool IsImplemented { get; }

    /// <summary>False when rollback is inherently impossible (e.g. service already started).</summary>
    bool SupportsRollback { get; }

    /// <summary>Who must own this repair. Firewall inbound repairs are LocalServer.</summary>
    RepairOwnerRole OwnerRole { get; }

    RepairTargetMachine TargetMachine { get; }

    Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default);
    Task CollectEvidenceAsync(CancellationToken ct = default);
    Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default);
    Task<RepairBackup> BackupAsync(CancellationToken ct = default);
    Task ApplyAsync(CancellationToken ct = default);
    Task<bool> VerifyAsync(CancellationToken ct = default);
    Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default);
}
