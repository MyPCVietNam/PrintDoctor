namespace MyPC.LanPrintDoctor.Abstractions.Diagnostics;

/// <summary>Who must execute a repair. Remote admin is out of scope for P1.1 HF1.</summary>
public enum RepairOwnerRole
{
    LocalAny,
    LocalServer,
    LocalClient,
    ServerActionRequired,
    None
}

public sealed class Finding
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required Severity Severity { get; init; }
    public required DiagnosticStatus Status { get; init; }
    public required string Evidence { get; init; }
    public double Confidence { get; init; }
    public IReadOnlyList<string> PossibleCauses { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> RecommendedActions { get; init; } = Array.Empty<string>();
    public string? RepairId { get; init; }
    /// <summary>Machine role that owns the repair target. Client findings about server ICMP must be ServerActionRequired.</summary>
    public RepairOwnerRole RepairOwner { get; init; } = RepairOwnerRole.None;
    public string? VerificationMethod { get; init; }
    public string Category { get; init; } = "General";
}
