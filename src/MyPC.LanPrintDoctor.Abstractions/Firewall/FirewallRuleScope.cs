namespace MyPC.LanPrintDoctor.Abstractions.Firewall;

/// <summary>
/// Strict scope checks for safe firewall repairs. Verify must require ALL conditions.
/// Empty RemoteAddresses is NEVER treated as LocalSubnet evidence.
/// </summary>
public static class FirewallRuleScope
{
    public static readonly string[] ApprovedFpsRuleIds =
    {
        "FPS-SMB-In-TCP",
        "FPS-NBSession-In-TCP",
        "FPS-RPCSS-In-TCP",
        "FPS-SpoolSvc-In-TCP"
    };

    public static bool IsGpoManaged(FirewallRuleInfo r)
        => (r.PolicyStore?.Contains("GP", StringComparison.OrdinalIgnoreCase) ?? false)
           || (r.PolicyStore?.Contains("GroupPolicy", StringComparison.OrdinalIgnoreCase) ?? false);

    public static bool IsInboundAllow(FirewallRuleInfo r)
        => r.Direction.Contains("In", StringComparison.OrdinalIgnoreCase)
           && r.Action.Contains("Allow", StringComparison.OrdinalIgnoreCase);

    public static bool IsPrivateOnly(FirewallRuleInfo r)
    {
        var p = r.Profiles ?? "";
        if (string.IsNullOrWhiteSpace(p) || p.Equals("Any", StringComparison.OrdinalIgnoreCase))
            return false;
        var tokens = p.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var hasPrivate = tokens.Any(t => t.Equals("Private", StringComparison.OrdinalIgnoreCase));
        var hasPublic = tokens.Any(t => t.Equals("Public", StringComparison.OrdinalIgnoreCase));
        var hasDomain = tokens.Any(t => t.Equals("Domain", StringComparison.OrdinalIgnoreCase));
        return hasPrivate && !hasPublic && !hasDomain;
    }

    public static bool IsLocalSubnetScoped(FirewallRuleInfo r)
    {
        var remote = r.RemoteAddresses ?? "";
        if (string.IsNullOrWhiteSpace(remote)) return false; // empty ≠ LocalSubnet
        if (remote.Equals("Any", StringComparison.OrdinalIgnoreCase) || remote == "*") return false;
        return remote.Contains("LocalSubnet", StringComparison.OrdinalIgnoreCase)
               || remote.Contains("Local subnet", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsScopedIcmpEcho(FirewallRuleInfo r)
    {
        if (!r.Enabled || !IsInboundAllow(r) || IsGpoManaged(r)) return false;
        if (!IsPrivateOnly(r) || !IsLocalSubnetScoped(r)) return false;
        var id = r.RuleId ?? r.Name ?? "";
        var display = r.DisplayName ?? r.Name ?? "";
        var isIcmp = id.Contains("FPS-ICMP4-ERQ-In", StringComparison.OrdinalIgnoreCase)
                     || (r.Protocol?.Contains("ICMP", StringComparison.OrdinalIgnoreCase) ?? false)
                     || display.Contains("Echo Request", StringComparison.OrdinalIgnoreCase)
                     || display.Contains("Yêu cầu Echo", StringComparison.OrdinalIgnoreCase);
        return isIcmp;
    }

    public static bool IsScopedFilePrintShareRule(FirewallRuleInfo r)
    {
        if (!r.Enabled || !IsInboundAllow(r) || IsGpoManaged(r)) return false;
        if (!IsPrivateOnly(r) || !IsLocalSubnetScoped(r)) return false;

        var id = r.RuleId ?? r.Name ?? "";
        if (!ApprovedFpsRuleIds.Any(a => id.Equals(a, StringComparison.OrdinalIgnoreCase))
            && !id.StartsWith("FPS-", StringComparison.OrdinalIgnoreCase))
            return false;

        var proto = r.Protocol ?? "";
        var ports = r.LocalPorts ?? "";
        if (proto.Contains("ICMP", StringComparison.OrdinalIgnoreCase)) return false;
        return ports.Contains("445") || ports.Contains("139") || ports.Contains("135")
               || ports.Equals("RPC", StringComparison.OrdinalIgnoreCase)
               || id.Contains("SMB", StringComparison.OrdinalIgnoreCase)
               || id.Contains("Spooler", StringComparison.OrdinalIgnoreCase)
               || id.Contains("NBSession", StringComparison.OrdinalIgnoreCase)
               || id.Contains("RPCSS", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Every changed rule id must satisfy the predicate — one bad rule ⇒ overall fail.</summary>
    public static bool AllChangedSatisfy(IEnumerable<FirewallRuleInfo> rules, IEnumerable<string> changedIds, Func<FirewallRuleInfo, bool> predicate)
    {
        var ids = changedIds.ToList();
        if (ids.Count == 0) return false;
        foreach (var id in ids)
        {
            var rule = rules.FirstOrDefault(r => string.Equals(r.RuleId ?? r.Name, id, StringComparison.OrdinalIgnoreCase));
            if (rule is null || !predicate(rule)) return false;
        }
        return true;
    }

    public static bool MatchesBackupSnapshot(FirewallRuleInfo current, FirewallRuleInfo expected)
        => string.Equals(current.RuleId ?? current.Name, expected.RuleId ?? expected.Name, StringComparison.OrdinalIgnoreCase)
           && current.Enabled == expected.Enabled
           && Eq(current.Profiles, expected.Profiles)
           && Eq(current.Direction, expected.Direction)
           && Eq(current.Action, expected.Action)
           && Eq(current.Protocol, expected.Protocol)
           && Eq(current.LocalPorts, expected.LocalPorts)
           && Eq(current.RemoteAddresses, expected.RemoteAddresses)
           && Eq(current.IcmpTypesAndCodes, expected.IcmpTypesAndCodes);

    private static bool Eq(string? a, string? b)
        => string.Equals(Normalize(a), Normalize(b), StringComparison.OrdinalIgnoreCase);

    private static string Normalize(string? s) => (s ?? "").Trim();
}
