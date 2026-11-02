using MyPC.LanPrintDoctor.Abstractions.Diagnostics;

namespace MyPC.LanPrintDoctor.Abstractions.Network;

public enum AdapterKind
{
    Ethernet,
    WiFi,
    Vpn,
    HyperV,
    Loopback,
    Virtual,
    Unknown
}

public enum NetworkCategory
{
    Public,
    Private,
    DomainAuthenticated,
    Unknown
}

public sealed class NetworkAdapterInfo
{
    public required string Name { get; init; }
    public string? Description { get; init; }
    public string? MacAddress { get; init; }
    public bool IsUp { get; init; }
    public long? LinkSpeedBps { get; init; }
    public IReadOnlyList<string> IPv4Addresses { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> IPv6Addresses { get; init; } = Array.Empty<string>();
    public string? SubnetMask { get; init; }
    public int? PrefixLength { get; init; }
    public string? DefaultGateway { get; init; }
    public IReadOnlyList<string> DnsServers { get; init; } = Array.Empty<string>();
    public bool? DhcpEnabled { get; init; }
    public int? InterfaceMetric { get; init; }
    public NetworkCategory Category { get; init; } = NetworkCategory.Unknown;
    public AdapterKind Kind { get; init; } = AdapterKind.Unknown;
    public int InterfaceIndex { get; init; }
    public string? ProfileName { get; init; }
}

public sealed class RouteEntry
{
    public required string Destination { get; init; }
    public required string Mask { get; init; }
    public string? Gateway { get; init; }
    public int InterfaceIndex { get; init; }
    public int Metric { get; init; }
    public string? NextHop { get; init; }
    public int? RouteMetric { get; init; }
}

public sealed class NeighborEntry
{
    public required string IpAddress { get; init; }
    public string? MacAddress { get; init; }
    public string? State { get; init; }
    public string? InterfaceAlias { get; init; }
    public int? InterfaceIndex { get; init; }
}

public enum ProbeProtocol
{
    Icmp,
    Tcp,
    Udp
}

public sealed class ConnectivityProbeResult
{
    public required string Target { get; init; }
    public required ProbeProtocol Protocol { get; init; }
    public int? Port { get; init; }
    public ProbeOutcome Outcome { get; init; } = ProbeOutcome.NotTested;
    public string? Detail { get; init; }
    public TimeSpan? Latency { get; init; }

    public bool Success => Outcome == ProbeOutcome.Pass;

    public DiagnosticStatus Status => Outcome switch
    {
        ProbeOutcome.Pass => DiagnosticStatus.Pass,
        ProbeOutcome.Fail or ProbeOutcome.AuthDenied or ProbeOutcome.AccessDenied => DiagnosticStatus.Fail,
        ProbeOutcome.NotApplicable => DiagnosticStatus.NotApplicable,
        ProbeOutcome.NotTested => DiagnosticStatus.Unknown,
        _ => DiagnosticStatus.Unknown
    };
}

public sealed class CollectorStatus
{
    public ProbeOutcome Outcome { get; init; } = ProbeOutcome.Unknown;
    public string? Detail { get; init; }
}
