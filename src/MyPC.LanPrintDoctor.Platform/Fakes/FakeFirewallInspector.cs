using System.Text.Json;
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
    public bool ThrowOnEnable { get; set; }
    public int IcmpEnableCalls { get; private set; }
    public int SharingEnableCalls { get; private set; }
    public int GroupEnableCalls { get; private set; } // must stay 0 — group enable forbidden

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
        if (ThrowOnEnable) throw new InvalidOperationException("PS failure");
        if (!IcmpEnableResult) return Task.FromResult(false);

        // Preserve Public rules untouched
        var existingPublic = Rules.Where(r => (r.Profiles ?? "").Contains("Public", StringComparison.OrdinalIgnoreCase)).ToList();

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
            RemoteAddresses = "LocalSubnet",
            PolicyStore = "ActiveStore",
            IcmpTypesAndCodes = "8"
        });

        // Ensure public copies still present
        foreach (var p in existingPublic.Where(r => !(r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In")))
        {
            if (!Rules.Any(x => x.RuleId == p.RuleId && x.Profiles == p.Profiles))
                Rules.Add(p);
        }

        return Task.FromResult(true);
    }

    public Task<bool> RestoreIcmpEchoFromBackupAsync(string backupJson, CancellationToken ct = default)
    {
        try
        {
            var priors = JsonSerializer.Deserialize<List<FirewallRuleInfo>>(string.IsNullOrWhiteSpace(backupJson) ? "[]" : backupJson)
                         ?? new();
            var prior = priors.FirstOrDefault(r => (r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In", StringComparison.OrdinalIgnoreCase));
            Rules.RemoveAll(r => (r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In"));
            if (prior is not null)
            {
                Rules.Add(new FirewallRuleInfo
                {
                    RuleId = prior.RuleId ?? "FPS-ICMP4-ERQ-In",
                    Name = prior.Name,
                    DisplayName = prior.DisplayName,
                    Enabled = prior.Enabled,
                    Direction = prior.Direction,
                    Action = prior.Action,
                    Protocol = prior.Protocol,
                    Profiles = prior.Profiles,
                    RemoteAddresses = prior.RemoteAddresses,
                    LocalPorts = prior.LocalPorts,
                    PolicyStore = prior.PolicyStore ?? "ActiveStore",
                    IcmpTypesAndCodes = prior.IcmpTypesAndCodes,
                    Grouping = prior.Grouping
                });
            }
            return Task.FromResult(true);
        }
        catch
        {
            return Task.FromResult(false);
        }
    }

    public Task<bool> EnableFileAndPrinterSharingAsync(CancellationToken ct = default)
    {
        SharingEnableCalls++;
        // Intentionally never increments GroupEnableCalls
        if (!SharingEnableResult) return Task.FromResult(false);

        void Upsert(string id, string ports)
        {
            // Never touch Public/Domain copies — only replace Private-scoped instance
            Rules.RemoveAll(r => r.RuleId == id && (r.Profiles ?? "").Contains("Private", StringComparison.OrdinalIgnoreCase));
            Rules.Add(new FirewallRuleInfo
            {
                RuleId = id,
                Name = id,
                Enabled = true,
                Direction = "Inbound",
                Action = "Allow",
                Grouping = "@FirewallAPI.dll,-28502",
                Protocol = "TCP",
                LocalPorts = ports,
                Profiles = "Private",
                RemoteAddresses = "LocalSubnet",
                PolicyStore = "ActiveStore"
            });
        }

        Upsert("FPS-SMB-In-TCP", "445");
        Upsert("FPS-SpoolSvc-In-TCP", "RPC");
        return Task.FromResult(true);
    }

    public Task<bool> RestoreFileAndPrinterSharingFromBackupAsync(string backupJson, CancellationToken ct = default)
    {
        try
        {
            var priors = JsonSerializer.Deserialize<List<FirewallRuleInfo>>(string.IsNullOrWhiteSpace(backupJson) ? "[]" : backupJson)
                         ?? new();
            foreach (var prior in priors.Where(r => (r.RuleId ?? "").StartsWith("FPS-", StringComparison.OrdinalIgnoreCase)
                                                    || (r.Grouping?.Contains("FirewallAPI.dll,-28502") ?? false)))
            {
                Rules.RemoveAll(r => string.Equals(r.RuleId, prior.RuleId, StringComparison.OrdinalIgnoreCase));
                Rules.Add(prior);
            }
            return Task.FromResult(true);
        }
        catch
        {
            return Task.FromResult(false);
        }
    }
}
