namespace MyPC.LanPrintDoctor.Abstractions.Network;

public interface INetworkProbe
{
    Task<IReadOnlyList<NetworkAdapterInfo>> GetAdaptersAsync(CancellationToken ct = default);
    Task<IReadOnlyList<RouteEntry>> GetRoutesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken ct = default);
    Task<ConnectivityProbeResult> PingAsync(string target, CancellationToken ct = default);
    Task<ConnectivityProbeResult> TcpConnectAsync(string host, int port, TimeSpan? timeout = null, CancellationToken ct = default);
    Task<ConnectivityProbeResult> ResolveDnsAsync(string hostname, CancellationToken ct = default);
    Task<bool> AreSameSubnetAsync(string ipA, string maskA, string ipB, CancellationToken ct = default);
}
