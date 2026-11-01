using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;

namespace MyPC.LanPrintDoctor.Platform.Fakes;

public sealed class FakeFirewallInspector : IFirewallInspector
{
    public List<FirewallProfileState> Profiles { get; set; } = new();
    public List<FirewallRuleInfo> Rules { get; set; } = new();
    public List<ThirdPartySecurityProduct> ThirdParty { get; set; } = new();
    public ProbeOutcome ThirdPartyStatus { get; set; } = ProbeOutcome.Pass;
    public bool IcmpEnableResult { get; set; } = true;
    public bool SharingEnableResult { get; set; } = true;
    public int IcmpEnableCalls { get; private set; }
    public int SharingEnableCalls { get; private set; }

    public Task<IReadOnlyList<FirewallProfileState>> GetProfilesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<FirewallProfileState>)Profiles);

    public Task<IReadOnlyList<FirewallRuleInfo>> GetRelevantRulesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<FirewallRuleInfo>)Rules);

    public Task<IReadOnlyList<ThirdPartySecurityProduct>> DetectThirdPartySecurityAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<ThirdPartySecurityProduct>)ThirdParty);

    public Task<ProbeOutcome> GetThirdPartyCollectionStatusAsync(CancellationToken ct = default)
        => Task.FromResult(ThirdPartyStatus);

    public Task<bool> EnableScopedIcmpEchoAsync(CancellationToken ct = default)
    {
        IcmpEnableCalls++;
        if (IcmpEnableResult)
        {
            Rules.RemoveAll(r => (r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In"));
            Rules.Add(new FirewallRuleInfo
            {
                RuleId = "FPS-ICMP4-ERQ-In",
                Name = "File and Printer Sharing (Echo Request - ICMPv4-In)",
                DisplayName = "File and Printer Sharing (Echo Request - ICMPv4-In)",
                Enabled = true,
                Direction = "Inbound",
                Action = "Allow",
                Protocol = "ICMPv4",
                Profiles = "Private",
                RemoteAddresses = "LocalSubnet"
            });
        }
        return Task.FromResult(IcmpEnableResult);
    }

    public Task<bool> RestoreIcmpEchoFromBackupAsync(string backupJson, CancellationToken ct = default)
    {
        Rules.RemoveAll(r => (r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In"));
        return Task.FromResult(true);
    }

    public Task<bool> EnableFileAndPrinterSharingAsync(CancellationToken ct = default)
    {
        SharingEnableCalls++;
        if (SharingEnableResult)
        {
            Rules.Add(new FirewallRuleInfo
            {
                RuleId = "FPS-SMB-In-TCP",
                Name = "File and Printer Sharing (SMB-In)",
                Enabled = true,
                Direction = "Inbound",
                Grouping = "@FirewallAPI.dll,-28502",
                Protocol = "TCP",
                LocalPorts = "445",
                Profiles = "Private"
            });
        }
        return Task.FromResult(SharingEnableResult);
    }

    public Task<bool> RestoreFileAndPrinterSharingFromBackupAsync(string backupJson, CancellationToken ct = default)
        => Task.FromResult(true);
}
