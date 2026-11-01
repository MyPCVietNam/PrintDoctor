using MyPC.LanPrintDoctor.Abstractions.Diagnostics;

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
    public string? DisplayName { get; init; }
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
    public string? RuleId { get; init; }
}

public sealed class ThirdPartySecurityProduct
{
    public required string Name { get; init; }
    public string? Vendor { get; init; }
    public string? Kind { get; init; }
    public ProbeOutcome CollectionStatus { get; init; } = ProbeOutcome.Pass;
}

public interface IFirewallInspector
{
    Task<IReadOnlyList<FirewallProfileState>> GetProfilesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<FirewallRuleInfo>> GetRelevantRulesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<ThirdPartySecurityProduct>> DetectThirdPartySecurityAsync(CancellationToken ct = default);
    Task<ProbeOutcome> GetThirdPartyCollectionStatusAsync(CancellationToken ct = default);

    /// <summary>Enable a scoped ICMP Echo inbound rule for Private/LocalSubnet. Returns false if not applied.</summary>
    Task<bool> EnableScopedIcmpEchoAsync(CancellationToken ct = default);

    /// <summary>Restore ICMP rule enablement from backup payload.</summary>
    Task<bool> RestoreIcmpEchoFromBackupAsync(string backupJson, CancellationToken ct = default);

    /// <summary>Enable File and Printer Sharing inbound group (language-independent group id).</summary>
    Task<bool> EnableFileAndPrinterSharingAsync(CancellationToken ct = default);

    Task<bool> RestoreFileAndPrinterSharingFromBackupAsync(string backupJson, CancellationToken ct = default);
}

public interface INetworkProfileService
{
    Task<IReadOnlyList<NetworkConnectionProfile>> GetConnectionProfilesAsync(CancellationToken ct = default);
    Task<bool> SetPrivateAsync(int interfaceIndex, CancellationToken ct = default);
    Task<bool> SetCategoryAsync(int interfaceIndex, string category, CancellationToken ct = default);
}

public sealed class NetworkConnectionProfile
{
    public int InterfaceIndex { get; init; }
    public string? Name { get; init; }
    public string? InterfaceAlias { get; init; }
    public string NetworkCategory { get; init; } = "Unknown";
    public bool IsDomainManaged { get; init; }
}
