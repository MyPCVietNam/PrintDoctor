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
    /// <summary>Simulate Set-NetFirewallAddressFilter failure — Enable must not run.</summary>
    public bool FailRemoteAddressSet { get; set; }
    /// <summary>
    /// Set-NetFirewallRule (profile) succeeds, then address-filter fails.
    /// Intent is tracked before mutation; controlled rollback restores snapshot.
    /// </summary>
    public bool FailAddressFilterAfterProfileSet { get; set; }
    public bool FailControlledRollback { get; set; }
    public bool FailRemoteAddressRestore { get; set; }
    /// <summary>Change first FPS rule then fail — ChangedRuleIds must still be recorded.</summary>
    public bool FailMidApplyAfterFirst { get; set; }
    public int IcmpEnableCalls { get; private set; }
    public int SharingEnableCalls { get; private set; }
    public int GroupEnableCalls { get; private set; }
    public int EnableInvocationsAfterFailedScope { get; private set; }
    public List<string> LastRestoredRuleIds { get; } = new();
    public List<string> LastMutationIntentIds { get; } = new();

    public Task<IReadOnlyList<FirewallProfileState>> GetProfilesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<FirewallProfileState>)Profiles);

    public Task<IReadOnlyList<FirewallRuleInfo>> GetRelevantRulesAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<FirewallRuleInfo>)Rules);

    public Task<IReadOnlyList<ThirdPartySecurityProduct>> DetectThirdPartySecurityAsync(CancellationToken ct = default)
        => Task.FromResult((IReadOnlyList<ThirdPartySecurityProduct>)ThirdParty);

    public Task<ProbeOutcome> GetThirdPartyCollectionStatusAsync(CancellationToken ct = default)
        => Task.FromResult(ThirdPartyStatus);

    public Task<FirewallMutationResult> EnableScopedIcmpEchoAsync(CancellationToken ct = default)
    {
        const string id = "FPS-ICMP4-ERQ-In";
        LastMutationIntentIds.Clear();
        var prior = Rules.FirstOrDefault(r => (r.RuleId ?? "").Contains(id, StringComparison.OrdinalIgnoreCase));
        var snap = prior is null ? null : Clone(prior);

        if (FailAddressFilterAfterProfileSet)
        {
            EnableInvocationsAfterFailedScope = 0;
            LastMutationIntentIds.Add(id);
            if (prior is not null)
            {
                Rules.RemoveAll(r => (r.RuleId ?? "").Contains(id, StringComparison.OrdinalIgnoreCase)
                                     && !(r.Profiles ?? "").Contains("Public", StringComparison.OrdinalIgnoreCase));
                Rules.Add(new FirewallRuleInfo
                {
                    RuleId = prior.RuleId,
                    Name = prior.Name,
                    DisplayName = prior.DisplayName,
                    Enabled = false,
                    Direction = prior.Direction,
                    Action = prior.Action,
                    Protocol = prior.Protocol,
                    Profiles = "Private",
                    RemoteAddresses = prior.RemoteAddresses,
                    LocalPorts = prior.LocalPorts,
                    PolicyStore = prior.PolicyStore,
                    IcmpTypesAndCodes = prior.IcmpTypesAndCodes,
                    Grouping = prior.Grouping
                });
            }

            var rollbackOk = snap is not null && !FailControlledRollback;
            if (rollbackOk)
            {
                Rules.RemoveAll(r => (r.RuleId ?? "").Contains(id, StringComparison.OrdinalIgnoreCase)
                                     && !(r.Profiles ?? "").Contains("Public", StringComparison.OrdinalIgnoreCase));
                Rules.Add(Clone(snap!));
            }

            return Task.FromResult(new FirewallMutationResult
            {
                Success = false,
                ChangedRuleIds = new[] { id },
                Detail = rollbackOk
                    ? "PARTIAL_CHANGED:FPS-ICMP4-ERQ-In|ROLLBACK_OK|ERR:REMOTE_NOT_SET after Set-NetFirewallRule"
                    : "PARTIAL_CHANGED:FPS-ICMP4-ERQ-In|ROLLBACK_FAIL|UNCERTAIN_STATE|ERR:REMOTE_NOT_SET after Set-NetFirewallRule",
                ControlledRollbackSucceeded = rollbackOk,
                Uncertain = !rollbackOk
            });
        }

        if (FailRemoteAddressSet)
        {
            EnableInvocationsAfterFailedScope = 0;
            return Task.FromResult(new FirewallMutationResult
            {
                Success = false,
                Detail = "REMOTE_NOT_SET — Enable not called"
            });
        }

        if (!IcmpEnableResult)
            return Task.FromResult(new FirewallMutationResult { Success = false, Detail = "enable failed" });

        LastMutationIntentIds.Add(id);
        IcmpEnableCalls++;
        var preservedPublicOther = Rules
            .Where(r => (r.Profiles ?? "").Contains("Public", StringComparison.OrdinalIgnoreCase)
                        && !(r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Rules.RemoveAll(r => (r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In", StringComparison.OrdinalIgnoreCase));
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
        foreach (var p in preservedPublicOther)
            if (!Rules.Contains(p)) Rules.Add(p);

        return Task.FromResult(new FirewallMutationResult
        {
            Success = true,
            ChangedRuleIds = new[] { "FPS-ICMP4-ERQ-In" }
        });
    }

    public Task<FirewallRestoreResult> RestoreIcmpEchoFromBackupAsync(string backupJson, CancellationToken ct = default)
    {
        try
        {
            var priors = JsonSerializer.Deserialize<List<FirewallRuleInfo>>(string.IsNullOrWhiteSpace(backupJson) ? "[]" : backupJson)
                         ?? new();
            var prior = priors.FirstOrDefault(r => (r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In", StringComparison.OrdinalIgnoreCase));
            if (prior is null)
                return Task.FromResult(new FirewallRestoreResult { Succeeded = false, Verified = false, Message = "no backup" });

            if (FailRemoteAddressRestore)
            {
                Rules.RemoveAll(r => (r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In"));
                Rules.Add(new FirewallRuleInfo
                {
                    RuleId = prior.RuleId ?? "FPS-ICMP4-ERQ-In",
                    Name = prior.Name,
                    Enabled = prior.Enabled,
                    Direction = prior.Direction,
                    Action = prior.Action,
                    Protocol = prior.Protocol,
                    Profiles = prior.Profiles,
                    RemoteAddresses = "LocalSubnet",
                    PolicyStore = "ActiveStore",
                    IcmpTypesAndCodes = prior.IcmpTypesAndCodes
                });
                return Task.FromResult(new FirewallRestoreResult
                {
                    Succeeded = true,
                    Verified = false,
                    Partial = true,
                    FailedRuleIds = new[] { "FPS-ICMP4-ERQ-In" },
                    Message = "PARTIAL_ROLLBACK: RemoteAddress restore failed"
                });
            }

            Rules.RemoveAll(r => (r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In"));
            Rules.Add(Clone(prior));
            return Task.FromResult(new FirewallRestoreResult
            {
                Succeeded = true,
                Verified = true,
                RestoredRuleIds = new[] { prior.RuleId ?? "FPS-ICMP4-ERQ-In" },
                Message = "restored"
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(new FirewallRestoreResult { Succeeded = false, Verified = false, Message = ex.Message });
        }
    }

    public Task<FirewallMutationResult> EnableFileAndPrinterSharingAsync(CancellationToken ct = default)
    {
        if (FailRemoteAddressSet)
            return Task.FromResult(new FirewallMutationResult { Success = false, Detail = "REMOTE_NOT_SET — Enable not called" });

        SharingEnableCalls++;
        if (!SharingEnableResult)
            return Task.FromResult(new FirewallMutationResult { Success = false });

        var changed = new List<string>();
        foreach (var id in new[] { "FPS-SMB-In-TCP", "FPS-SpoolSvc-In-TCP" })
        {
            LastMutationIntentIds.Add(id);
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
                LocalPorts = id.Contains("SMB") ? "445" : "RPC",
                Profiles = "Private",
                RemoteAddresses = "LocalSubnet",
                PolicyStore = "ActiveStore"
            });
            changed.Add(id);
            if (FailMidApplyAfterFirst)
            {
                return Task.FromResult(new FirewallMutationResult
                {
                    Success = false,
                    ChangedRuleIds = changed.ToList(),
                    Detail = "PARTIAL_CHANGED mid-apply failure after " + id
                });
            }
        }
        return Task.FromResult(new FirewallMutationResult { Success = true, ChangedRuleIds = changed });
    }

    public Task<FirewallRestoreResult> RestoreFileAndPrinterSharingFromBackupAsync(string backupJson, CancellationToken ct = default)
    {
        try
        {
            var priors = JsonSerializer.Deserialize<List<FirewallRuleInfo>>(string.IsNullOrWhiteSpace(backupJson) ? "[]" : backupJson)
                         ?? new();
            var restored = new List<string>();
            foreach (var prior in priors.Where(r => (r.RuleId ?? "").StartsWith("FPS-", StringComparison.OrdinalIgnoreCase)))
            {
                Rules.RemoveAll(r => string.Equals(r.RuleId, prior.RuleId, StringComparison.OrdinalIgnoreCase)
                                     && (r.Profiles ?? "").Contains("Private", StringComparison.OrdinalIgnoreCase));
                Rules.Add(Clone(prior));
                restored.Add(prior.RuleId ?? prior.Name);
            }
            LastRestoredRuleIds.Clear();
            LastRestoredRuleIds.AddRange(restored);
            return Task.FromResult(new FirewallRestoreResult
            {
                Succeeded = true,
                Verified = true,
                RestoredRuleIds = restored
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(new FirewallRestoreResult { Succeeded = false, Verified = false, Message = ex.Message });
        }
    }

    private static FirewallRuleInfo Clone(FirewallRuleInfo p) => new()
    {
        RuleId = p.RuleId,
        Name = p.Name,
        DisplayName = p.DisplayName,
        Enabled = p.Enabled,
        Direction = p.Direction,
        Action = p.Action,
        Protocol = p.Protocol,
        Profiles = p.Profiles,
        RemoteAddresses = p.RemoteAddresses,
        LocalPorts = p.LocalPorts,
        PolicyStore = p.PolicyStore ?? "ActiveStore",
        IcmpTypesAndCodes = p.IcmpTypesAndCodes,
        Grouping = p.Grouping
    };
}
