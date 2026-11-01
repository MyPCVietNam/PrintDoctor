using MyPC.LanPrintDoctor.Abstractions.Smb;

namespace MyPC.LanPrintDoctor.Platform.Fakes;

public sealed class FakeSmbInspector : ISmbInspector
{
    public SmbConfiguration Configuration { get; set; } = new();
    public List<ShareInfo> Shares { get; set; } = new();
    public SmbProbeResult? Probe { get; set; }
    public (bool NetworkDiscovery, bool FileAndPrinterSharing) Toggles { get; set; } = (true, true);

    public Task<SmbConfiguration> GetConfigurationAsync(CancellationToken ct = default) => Task.FromResult(Configuration);
    public Task<IReadOnlyList<ShareInfo>> GetSharesAsync(CancellationToken ct = default) => Task.FromResult((IReadOnlyList<ShareInfo>)Shares);
    public Task<SmbProbeResult> ProbeRemoteAsync(string host, CancellationToken ct = default)
        => Task.FromResult(Probe ?? new SmbProbeResult { Target = host, Tcp445Open = false, Tcp135Open = false, UncReachable = false });
    public Task<(bool NetworkDiscovery, bool FileAndPrinterSharing)> GetSharingTogglesAsync(CancellationToken ct = default)
        => Task.FromResult(Toggles);
}
