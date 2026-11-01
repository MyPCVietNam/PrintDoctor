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
    public string? LocalAddresses { get; init; }
    public string? RemoteAddresses { get; init; }
    public string? Profiles { get; init; }
    public string? Program { get; init; }
    public string? Grouping { get; init; }
    public string? RuleId { get; init; }
    public string? PolicyStore { get; init; }
    public string? IcmpTypesAndCodes { get; init; }
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

    /// <summary>Enable a scoped ICMP Echo inbound rule for Private/LocalSubnet.</summary>
    Task<FirewallMutationResult> EnableScopedIcmpEchoAsync(CancellationToken ct = default);

    /// <summary>Restore ICMP rule attributes from backup and re-read verify.</summary>
    Task<FirewallRestoreResult> RestoreIcmpEchoFromBackupAsync(string backupJson, CancellationToken ct = default);

    /// <summary>Enable approved FPS inbound rules one-by-one (never -Group).</summary>
    Task<FirewallMutationResult> EnableFileAndPrinterSharingAsync(CancellationToken ct = default);

    Task<FirewallRestoreResult> RestoreFileAndPrinterSharingFromBackupAsync(string backupJson, CancellationToken ct = default);
}

public sealed class FirewallMutationResult
{
    public bool Success { get; init; }
    public IReadOnlyList<string> ChangedRuleIds { get; init; } = Array.Empty<string>();
    public string? Detail { get; init; }
}

public sealed class FirewallRestoreResult
{
    public bool Succeeded { get; init; }
    public bool Verified { get; init; }
    public bool Partial { get; init; }
    public string? Message { get; init; }
    public IReadOnlyList<string> RestoredRuleIds { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> FailedRuleIds { get; init; } = Array.Empty<string>();
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
