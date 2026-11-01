using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Core.Engine;

namespace MyPC.LanPrintDoctor.Platform.Windows;

public sealed class WindowsNetworkProbe : INetworkProbe
{
    private readonly IProcessRunner? _runner;

    public WindowsNetworkProbe(IProcessRunner? runner = null) => _runner = runner;

    public async Task<IReadOnlyList<NetworkAdapterInfo>> GetAdaptersAsync(CancellationToken ct = default)
    {
        var list = new List<NetworkAdapterInfo>();
        var profiles = await LoadProfilesAsync(ct);
        var metrics = await LoadInterfaceMetricsAsync(ct);

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

            var ifIndex = 0;
            try
            {
                if (OperatingSystem.IsWindows())
                    ifIndex = props.GetIPv4Properties()?.Index ?? 0;
            }
            catch { /* ignore */ }

            string? profileName = null;
            string? profileCategory = null;
            if (profiles.TryGetValue(ifIndex, out var profile))
            {
                profileName = profile.Name;
                profileCategory = profile.Category;
            }
            int? metric = metrics.TryGetValue(ifIndex, out var m) ? m : null;

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
                InterfaceMetric = metric, // real metric from Get-NetIPInterface, NOT InterfaceIndex
                InterfaceIndex = ifIndex,
                Category = MapCategory(profileCategory),
                ProfileName = profileName,
                Kind = Classify(nic)
            });
        }

        return list;
    }

    public async Task<IReadOnlyList<RouteEntry>> GetRoutesAsync(CancellationToken ct = default)
    {
        if (_runner is null || !OperatingSystem.IsWindows())
            return Array.Empty<RouteEntry>();

        const string script = "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric,Publish | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<RouteEntry>();
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            return PowerShellJson.Enumerate(doc.RootElement).Select(el =>
            {
                var dest = PowerShellJson.GetString(el, "DestinationPrefix") ?? "0.0.0.0/0";
                var parts = dest.Split('/');
                var prefixLen = parts.Length > 1 && int.TryParse(parts[1], out var pl) ? pl : 0;
                return new RouteEntry
                {
                    Destination = parts[0],
                    Mask = IpMath.PrefixToMask(prefixLen),
                    Gateway = PowerShellJson.GetString(el, "NextHop"),
                    NextHop = PowerShellJson.GetString(el, "NextHop"),
                    InterfaceIndex = PowerShellJson.GetInt(el, "InterfaceIndex") ?? 0,
                    Metric = PowerShellJson.GetInt(el, "RouteMetric") ?? 0,
                    RouteMetric = PowerShellJson.GetInt(el, "RouteMetric")
                };
            }).ToList();
        }
        catch
        {
            return Array.Empty<RouteEntry>();
        }
    }

    public async Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken ct = default)
    {
        if (_runner is null || !OperatingSystem.IsWindows())
            return Array.Empty<NeighborEntry>();

        const string script = "Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias,InterfaceIndex | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<NeighborEntry>();
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            return PowerShellJson.Enumerate(doc.RootElement).Select(el => new NeighborEntry
            {
                IpAddress = PowerShellJson.GetString(el, "IPAddress") ?? "",
                MacAddress = PowerShellJson.GetString(el, "LinkLayerAddress"),
                State = PowerShellJson.GetString(el, "State"),
                InterfaceAlias = PowerShellJson.GetString(el, "InterfaceAlias"),
                InterfaceIndex = PowerShellJson.GetInt(el, "InterfaceIndex")
            }).Where(n => !string.IsNullOrWhiteSpace(n.IpAddress)).ToList();
        }
        catch
        {
            return Array.Empty<NeighborEntry>();
        }
    }

    public async Task<ConnectivityProbeResult> PingAsync(string target, CancellationToken ct = default)
    {
        try
        {
            using var pinger = new Ping();
            var reply = await pinger.SendPingAsync(target, 2000);
            var ok = reply.Status == IPStatus.Success;
            return new ConnectivityProbeResult
            {
                Target = target,
                Protocol = ProbeProtocol.Icmp,
                Outcome = ok ? ProbeOutcome.Pass : ProbeOutcome.Fail,
                Latency = ok ? TimeSpan.FromMilliseconds(reply.RoundtripTime) : null,
                Detail = reply.Status.ToString()
            };
        }
        catch (Exception ex)
        {
            return new ConnectivityProbeResult { Target = target, Protocol = ProbeProtocol.Icmp, Outcome = ProbeOutcome.Fail, Detail = ex.GetType().Name };
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
                return new ConnectivityProbeResult { Target = host, Port = port, Protocol = ProbeProtocol.Tcp, Outcome = ProbeOutcome.Fail, Detail = "timeout/refused" };
            await connectTask;
            return new ConnectivityProbeResult { Target = host, Port = port, Protocol = ProbeProtocol.Tcp, Outcome = ProbeOutcome.Pass, Detail = "connected" };
        }
        catch (Exception ex)
        {
            return new ConnectivityProbeResult { Target = host, Port = port, Protocol = ProbeProtocol.Tcp, Outcome = ProbeOutcome.Fail, Detail = ex.GetType().Name };
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
                Outcome = addresses.Length > 0 ? ProbeOutcome.Pass : ProbeOutcome.Fail,
                Detail = string.Join(",", addresses.Select(a => a.ToString()))
            };
        }
        catch (Exception ex)
        {
            return new ConnectivityProbeResult { Target = hostname, Protocol = ProbeProtocol.Tcp, Outcome = ProbeOutcome.Fail, Detail = ex.GetType().Name };
        }
    }

    public Task<bool> AreSameSubnetAsync(string ipA, string maskA, string ipB, CancellationToken ct = default)
        => Task.FromResult(IpMath.SameSubnet(ipA, maskA, ipB));

    private async Task<Dictionary<int, (string? Name, string? Category)>> LoadProfilesAsync(CancellationToken ct)
    {
        var map = new Dictionary<int, (string?, string?)>();
        if (_runner is null || !OperatingSystem.IsWindows()) return map;
        const string script = "Get-NetConnectionProfile | Select-Object Name,InterfaceIndex,NetworkCategory | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(20), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut)) return map;
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            foreach (var el in PowerShellJson.Enumerate(doc.RootElement))
            {
                var idx = PowerShellJson.GetInt(el, "InterfaceIndex") ?? -1;
                if (idx < 0) continue;
                var cat = PowerShellJson.GetString(el, "NetworkCategory") ?? "Unknown";
                cat = cat switch { "0" => "Public", "1" => "Private", "2" => "DomainAuthenticated", _ => cat };
                map[idx] = (PowerShellJson.GetString(el, "Name"), cat);
            }
        }
        catch { /* leave empty */ }
        return map;
    }

    private async Task<Dictionary<int, int?>> LoadInterfaceMetricsAsync(CancellationToken ct)
    {
        var map = new Dictionary<int, int?>();
        if (_runner is null || !OperatingSystem.IsWindows()) return map;
        const string script = "Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceIndex,InterfaceMetric | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(20), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut)) return map;
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            foreach (var el in PowerShellJson.Enumerate(doc.RootElement))
            {
                var idx = PowerShellJson.GetInt(el, "InterfaceIndex") ?? -1;
                if (idx < 0) continue;
                map[idx] = PowerShellJson.GetInt(el, "InterfaceMetric");
            }
        }
        catch { }
        return map;
    }

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

    private static NetworkCategory MapCategory(string? category)
        => category?.ToLowerInvariant() switch
        {
            "private" => NetworkCategory.Private,
            "public" => NetworkCategory.Public,
            "domainauthenticated" or "domain" => NetworkCategory.DomainAuthenticated,
            _ => NetworkCategory.Unknown
        };
}
