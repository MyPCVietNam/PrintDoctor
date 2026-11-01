using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Core.Engine;

namespace MyPC.LanPrintDoctor.Platform.Windows;

public sealed class WindowsNetworkProbe : INetworkProbe
{
    public Task<IReadOnlyList<NetworkAdapterInfo>> GetAdaptersAsync(CancellationToken ct = default)
    {
        var list = new List<NetworkAdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var props = nic.GetIPProperties();
            var ipv4 = props.UnicastAddresses
                .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(u => u.Address.ToString()).ToList();
            var ipv6 = props.UnicastAddresses
                .Where(u => u.Address.AddressFamily == AddressFamily.InterNetworkV6)
                .Select(u => u.Address.ToString()).ToList();
            var prefix = props.UnicastAddresses.FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork)?.PrefixLength;
            var gw = props.GatewayAddresses.FirstOrDefault()?.Address?.ToString();
            var dns = props.DnsAddresses.Select(d => d.ToString()).ToList();
            long? speed = null;
            try { speed = nic.Speed; } catch { }

            list.Add(new NetworkAdapterInfo
            {
                Name = nic.Name,
                Description = nic.Description,
                MacAddress = FormatMac(nic.GetPhysicalAddress()),
                IsUp = nic.OperationalStatus == OperationalStatus.Up,
                LinkSpeedBps = speed,
                IPv4Addresses = ipv4,
                IPv6Addresses = ipv6,
                PrefixLength = prefix,
                SubnetMask = prefix is int p ? IpMath.PrefixToMask(p) : null,
                DefaultGateway = gw,
                DnsServers = dns,
                DhcpEnabled = OperatingSystem.IsWindows() ? props.GetIPv4Properties()?.IsDhcpEnabled : null,
                InterfaceMetric = OperatingSystem.IsWindows() ? props.GetIPv4Properties()?.Index : null,
                InterfaceIndex = OperatingSystem.IsWindows() ? (props.GetIPv4Properties()?.Index ?? 0) : 0,
                Category = MapCategory(nic),
                Kind = Classify(nic)
            });
        }
        return Task.FromResult((IReadOnlyList<NetworkAdapterInfo>)list);
    }

    public Task<IReadOnlyList<RouteEntry>> GetRoutesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<RouteEntry>)Array.Empty<RouteEntry>()); // enriched via PowerShell on Windows CI when available

    public Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken ct = default)
    {
        // Cross-platform: empty; WindowsPowerShellNetworkEnricher can fill
        return Task.FromResult((IReadOnlyList<NeighborEntry>)Array.Empty<NeighborEntry>());
    }

    public async Task<ConnectivityProbeResult> PingAsync(string target, CancellationToken ct = default)
    {
        try
        {
            using var pinger = new Ping();
            var reply = await pinger.SendPingAsync(target, 2000);
            return new ConnectivityProbeResult
            {
                Target = target,
                Protocol = ProbeProtocol.Icmp,
                Success = reply.Status == IPStatus.Success,
                Latency = reply.Status == IPStatus.Success ? TimeSpan.FromMilliseconds(reply.RoundtripTime) : null,
                Detail = reply.Status.ToString()
            };
        }
        catch (Exception ex)
        {
            return new ConnectivityProbeResult { Target = target, Protocol = ProbeProtocol.Icmp, Success = false, Detail = ex.GetType().Name };
        }
    }

    public async Task<ConnectivityProbeResult> TcpConnectAsync(string host, int port, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(host, port);
            var delay = Task.Delay(timeout ?? TimeSpan.FromSeconds(3), ct);
            var done = await Task.WhenAny(connectTask, delay);
            if (done != connectTask || !client.Connected)
                return new ConnectivityProbeResult { Target = host, Port = port, Protocol = ProbeProtocol.Tcp, Success = false, Detail = "timeout/refused" };
            await connectTask;
            return new ConnectivityProbeResult { Target = host, Port = port, Protocol = ProbeProtocol.Tcp, Success = true, Detail = "connected" };
        }
        catch (Exception ex)
        {
            return new ConnectivityProbeResult { Target = host, Port = port, Protocol = ProbeProtocol.Tcp, Success = false, Detail = ex.GetType().Name };
        }
    }

    public async Task<ConnectivityProbeResult> ResolveDnsAsync(string hostname, CancellationToken ct = default)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(hostname, ct);
            return new ConnectivityProbeResult
            {
                Target = hostname,
                Protocol = ProbeProtocol.Tcp,
                Success = addresses.Length > 0,
                Detail = string.Join(",", addresses.Select(a => a.ToString()))
            };
        }
        catch (Exception ex)
        {
            return new ConnectivityProbeResult { Target = hostname, Protocol = ProbeProtocol.Tcp, Success = false, Detail = ex.GetType().Name };
        }
    }

    public Task<bool> AreSameSubnetAsync(string ipA, string maskA, string ipB, CancellationToken ct = default)
        => Task.FromResult(IpMath.SameSubnet(ipA, maskA, ipB));

    private static string? FormatMac(PhysicalAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (bytes.Length == 0) return null;
        return string.Join(":", bytes.Select(b => b.ToString("X2")));
    }

    private static AdapterKind Classify(NetworkInterface nic)
    {
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) return AdapterKind.Loopback;
        var d = (nic.Description + " " + nic.Name).ToLowerInvariant();
        if (d.Contains("hyper-v") || d.Contains("vethernet")) return AdapterKind.HyperV;
        if (d.Contains("vpn") || d.Contains("tap") || d.Contains("tunnel") || nic.NetworkInterfaceType == NetworkInterfaceType.Ppp)
            return AdapterKind.Vpn;
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) return AdapterKind.WiFi;
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet) return AdapterKind.Ethernet;
        if (d.Contains("virtual") || d.Contains("vmware") || d.Contains("virtualbox")) return AdapterKind.Virtual;
        return AdapterKind.Unknown;
    }

    private static NetworkCategory MapCategory(NetworkInterface nic)
    {
        // NetworkCategory requires Windows Network List Manager; default Unknown off-Windows.
        return NetworkCategory.Unknown;
    }
}
