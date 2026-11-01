using MyPC.LanPrintDoctor.Abstractions.ShaPrint;

namespace MyPC.LanPrintDoctor.Platform.Fakes;

public sealed class FakeShaPrintInspector : IShaPrintInspector
{
    public ShaPrintInstallInfo Install { get; set; } = new() { Installed = false };
    public ShaPrintConnectivity Connectivity { get; set; } = new();
    public List<string> FirewallRules { get; set; } = new();

    public Task<ShaPrintInstallInfo> GetInstallInfoAsync(CancellationToken ct = default) => Task.FromResult(Install);
    public Task<ShaPrintConnectivity> ProbeConnectivityAsync(string? serverHost, CancellationToken ct = default) => Task.FromResult(Connectivity);
    public Task<IReadOnlyList<string>> GetRelatedFirewallRulesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<string>)FirewallRules);
}
