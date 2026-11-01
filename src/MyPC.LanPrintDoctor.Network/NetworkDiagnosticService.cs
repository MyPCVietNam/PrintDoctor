using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Core.Engine;

namespace MyPC.LanPrintDoctor.Network;

public sealed class NetworkDiagnosticService
{
    private readonly INetworkProbe _probe;

    public NetworkDiagnosticService(INetworkProbe probe) => _probe = probe;

    public async Task<bool> IsOnLinkAsync(string localIp, int prefix, string target, CancellationToken ct = default)
        => IpMath.SameSubnetPrefix(localIp, prefix, target);

    public Task<IReadOnlyList<NetworkAdapterInfo>> CollectAdaptersAsync(CancellationToken ct = default)
        => _probe.GetAdaptersAsync(ct);
}
