using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Smb;

namespace MyPC.LanPrintDoctor.Platform.Fakes;

public sealed class FakeSmbInspector : ISmbInspector
{
    public SmbConfiguration Configuration { get; set; } = new() { CollectionStatus = ProbeOutcome.Pass };
    public List<ShareInfo> Shares { get; set; } = new();
    public SmbProbeResult? Probe { get; set; }
    public SharingToggleState Toggles { get; set; } = new()
    {
        NetworkDiscovery = ProbeOutcome.Pass,
        FileAndPrinterSharing = ProbeOutcome.Pass
    };

    public Task<SmbConfiguration> GetConfigurationAsync(CancellationToken ct = default) => Task.FromResult(Configuration);
    public Task<IReadOnlyList<ShareInfo>> GetSharesAsync(CancellationToken ct = default) => Task.FromResult((IReadOnlyList<ShareInfo>)Shares);
    public Task<SmbProbeResult> ProbeRemoteAsync(string host, CancellationToken ct = default)
        => Task.FromResult(Probe ?? new SmbProbeResult { Target = host, Tcp445 = ProbeOutcome.Fail, Tcp135 = ProbeOutcome.Fail, Unc = ProbeOutcome.NotTested });
    public Task<SharingToggleState> GetSharingTogglesAsync(CancellationToken ct = default) => Task.FromResult(Toggles);
}
