using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Core.Engine;

namespace MyPC.LanPrintDoctor.Platform.Fakes;

public sealed class FakeNetworkProbe : INetworkProbe
{
    public List<NetworkAdapterInfo> Adapters { get; set; } = new();
    public List<RouteEntry> Routes { get; set; } = new();
    public List<NeighborEntry> Neighbors { get; set; } = new();
    public Dictionary<string, bool> IcmpResults { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<(string Host, int Port), bool> TcpResults { get; set; } = new();
    public Dictionary<string, bool> DnsResults { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public Task<IReadOnlyList<NetworkAdapterInfo>> GetAdaptersAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<NetworkAdapterInfo>)Adapters);

    public Task<IReadOnlyList<RouteEntry>> GetRoutesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<RouteEntry>)Routes);

    public Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<NeighborEntry>)Neighbors);

    public Task<ConnectivityProbeResult> PingAsync(string target, CancellationToken ct = default)
    {
        var ok = IcmpResults.TryGetValue(target, out var v) ? v : false;
        return Task.FromResult(new ConnectivityProbeResult
        {
            Target = target,
            Protocol = ProbeProtocol.Icmp,
            Success = ok,
            Detail = ok ? "echo reply" : "timed out"
        });
    }

    public Task<ConnectivityProbeResult> TcpConnectAsync(string host, int port, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var ok = TcpResults.TryGetValue((host, port), out var v) && v;
        return Task.FromResult(new ConnectivityProbeResult
        {
            Target = host,
            Port = port,
            Protocol = ProbeProtocol.Tcp,
            Success = ok,
            Detail = ok ? "connected" : "refused/filtered"
        });
    }

    public Task<ConnectivityProbeResult> ResolveDnsAsync(string hostname, CancellationToken ct = default)
    {
        var ok = DnsResults.TryGetValue(hostname, out var v) && v;
        return Task.FromResult(new ConnectivityProbeResult
        {
            Target = hostname,
            Protocol = ProbeProtocol.Tcp,
            Success = ok,
            Detail = ok ? "resolved" : "NXDOMAIN"
        });
    }

    public Task<bool> AreSameSubnetAsync(string ipA, string maskA, string ipB, CancellationToken ct = default)
        => Task.FromResult(IpMath.SameSubnet(ipA, maskA, ipB));
}
