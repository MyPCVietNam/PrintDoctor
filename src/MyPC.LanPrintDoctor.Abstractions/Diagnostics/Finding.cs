namespace MyPC.LanPrintDoctor.Abstractions.Diagnostics;

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
    public string? VerificationMethod { get; init; }
    public string Category { get; init; } = "General";
}
