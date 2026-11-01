using MyPC.LanPrintDoctor.Abstractions.Diagnostics;

namespace MyPC.LanPrintDoctor.Abstractions.ShaPrint;

public static class ShaPrintPorts
{
    public const int ServerTcp = 48631;
    public const int ClientLoopbackTcp = 48632;
    public const int DiscoveryUdp = 48633;
}

public sealed class ShaPrintInstallInfo
{
    public bool Installed { get; init; }
    public string? InstallPath { get; init; }
    public string? Version { get; init; }
    public bool ProcessRunning { get; init; }
    public int? ProcessId { get; init; }
    public bool StartsWithWindows { get; init; }
    public IReadOnlyList<string> ListeningEndpoints { get; init; } = Array.Empty<string>();
    public ProbeOutcome ListeningCollectionStatus { get; init; } = ProbeOutcome.Unknown;
}

public sealed class ShaPrintConnectivity
{
    public ProbeOutcome ServerEndpoint { get; init; } = ProbeOutcome.NotTested;
    public ProbeOutcome DiscoveryPort { get; init; } = ProbeOutcome.NotTested;
    public ProbeOutcome ClientProxy { get; init; } = ProbeOutcome.NotTested;
    public string? Detail { get; init; }

    public bool ServerEndpointReachable => ServerEndpoint == ProbeOutcome.Pass;
    public bool ClientProxyListening => ClientProxy == ProbeOutcome.Pass;
}

public interface IShaPrintInspector
{
    Task<ShaPrintInstallInfo> GetInstallInfoAsync(CancellationToken ct = default);
    Task<ShaPrintConnectivity> ProbeConnectivityAsync(string? serverHost, CancellationToken ct = default);
    Task<IReadOnlyList<string>> GetRelatedFirewallRulesAsync(CancellationToken ct = default);
}
