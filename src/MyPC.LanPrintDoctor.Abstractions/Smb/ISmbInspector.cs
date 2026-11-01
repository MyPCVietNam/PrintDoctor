namespace MyPC.LanPrintDoctor.Abstractions.Smb;

public sealed class SmbConfiguration
{
    public bool? EnableSMB1Protocol { get; init; }
    public bool? RequireSecuritySignature { get; init; }
    public bool? EnableInsecureGuestLogons { get; init; }
    public string? Notes { get; init; }
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
    public bool Tcp445Open { get; init; }
    public bool Tcp135Open { get; init; }
    public bool UncReachable { get; init; }
    public string? Detail { get; init; }
}

public interface ISmbInspector
{
    Task<SmbConfiguration> GetConfigurationAsync(CancellationToken ct = default);
    Task<IReadOnlyList<ShareInfo>> GetSharesAsync(CancellationToken ct = default);
    Task<SmbProbeResult> ProbeRemoteAsync(string host, CancellationToken ct = default);
    Task<(bool NetworkDiscovery, bool FileAndPrinterSharing)> GetSharingTogglesAsync(CancellationToken ct = default);
}
