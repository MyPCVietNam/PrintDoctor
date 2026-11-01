using MyPC.LanPrintDoctor.Abstractions.Firewall;

namespace MyPC.LanPrintDoctor.Platform.Fakes;

public sealed class FakeFirewallInspector : IFirewallInspector
{
    public List<FirewallProfileState> Profiles { get; set; } = new();
    public List<FirewallRuleInfo> Rules { get; set; } = new();
    public List<ThirdPartySecurityProduct> ThirdParty { get; set; } = new();

    public Task<IReadOnlyList<FirewallProfileState>> GetProfilesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<FirewallProfileState>)Profiles);

    public Task<IReadOnlyList<FirewallRuleInfo>> GetRelevantRulesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<FirewallRuleInfo>)Rules);

    public Task<IReadOnlyList<ThirdPartySecurityProduct>> DetectThirdPartySecurityAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<ThirdPartySecurityProduct>)ThirdParty);
}
