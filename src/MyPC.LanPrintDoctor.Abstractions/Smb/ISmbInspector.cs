using MyPC.LanPrintDoctor.Abstractions.Diagnostics;

namespace MyPC.LanPrintDoctor.Abstractions.Smb;

public sealed class SmbConfiguration
{
    public bool? EnableSMB1Protocol { get; init; }
    public bool? RequireSecuritySignature { get; init; }
    public bool? EnableInsecureGuestLogons { get; init; }
    public string? Notes { get; init; }
    public ProbeOutcome CollectionStatus { get; init; } = ProbeOutcome.Unknown;
}

public sealed class ShareInfo
{
    public required string Name { get; init; }
    public string? Path { get; init; }
    public string? Description { get; init; }
    public bool IsPrinter { get; init; }
}

public sealed class SmbProbeResult
{
    public required string Target { get; init; }
    public ProbeOutcome Tcp445 { get; init; } = ProbeOutcome.NotTested;
    public ProbeOutcome Tcp135 { get; init; } = ProbeOutcome.NotTested;
    public ProbeOutcome Unc { get; init; } = ProbeOutcome.NotTested;
    public string? Detail { get; init; }

    public bool Tcp445Open => Tcp445 == ProbeOutcome.Pass;
    public bool Tcp135Open => Tcp135 == ProbeOutcome.Pass;
}

public sealed class SharingToggleState
{
    public ProbeOutcome NetworkDiscovery { get; init; } = ProbeOutcome.Unknown;
    public ProbeOutcome FileAndPrinterSharing { get; init; } = ProbeOutcome.Unknown;
    public string? Detail { get; init; }
}

public interface ISmbInspector
{
    Task<SmbConfiguration> GetConfigurationAsync(CancellationToken ct = default);
    Task<IReadOnlyList<ShareInfo>> GetSharesAsync(CancellationToken ct = default);
    Task<SmbProbeResult> ProbeRemoteAsync(string host, CancellationToken ct = default);
    Task<SharingToggleState> GetSharingTogglesAsync(CancellationToken ct = default);
}
