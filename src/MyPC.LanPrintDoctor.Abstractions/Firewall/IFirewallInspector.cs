namespace MyPC.LanPrintDoctor.Abstractions.Firewall;

public enum FirewallProfileKind
{
    Domain,
    Private,
    Public
}

public sealed class FirewallProfileState
{
    public required FirewallProfileKind Profile { get; init; }
    public bool Enabled { get; init; }
    public string? DefaultInboundAction { get; init; }
    public string? DefaultOutboundAction { get; init; }
    public bool? ManagedByPolicy { get; init; }
}

public sealed class FirewallRuleInfo
{
    public required string Name { get; init; }
    public bool Enabled { get; init; }
    public string Direction { get; init; } = "Inbound";
    public string Action { get; init; } = "Allow";
    public string? Protocol { get; init; }
    public string? LocalPorts { get; init; }
    public string? RemotePorts { get; init; }
    public string? RemoteAddresses { get; init; }
    public string? Profiles { get; init; }
    public string? Program { get; init; }
    public string? Grouping { get; init; }
}

public sealed class ThirdPartySecurityProduct
{
    public required string Name { get; init; }
    public string? Vendor { get; init; }
    public string? Kind { get; init; }
}

public interface IFirewallInspector
{
    Task<IReadOnlyList<FirewallProfileState>> GetProfilesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<FirewallRuleInfo>> GetRelevantRulesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<ThirdPartySecurityProduct>> DetectThirdPartySecurityAsync(CancellationToken ct = default);
}
