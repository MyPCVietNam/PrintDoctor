namespace MyPC.LanPrintDoctor.Abstractions.Firewall;

/// <summary>
/// Strict scope checks for safe firewall repairs. Verify must require ALL conditions.
/// </summary>
public static class FirewallRuleScope
{
    public const string ApprovedRemote = "LocalSubnet";
    public const string ApprovedProfile = "Private";

    public static bool IsGpoManaged(FirewallRuleInfo r)
        => (r.PolicyStore?.Contains("GP", StringComparison.OrdinalIgnoreCase) ?? false)
           || (r.PolicyStore?.Contains("GroupPolicy", StringComparison.OrdinalIgnoreCase) ?? false)
           || (r.PolicyStore?.Contains("PersistentStore", StringComparison.OrdinalIgnoreCase) == false
               && r.PolicyStore is not null
               && !r.PolicyStore.Equals("ActiveStore", StringComparison.OrdinalIgnoreCase)
               && r.PolicyStore.Contains("Policy", StringComparison.OrdinalIgnoreCase));

    public static bool IsInboundAllow(FirewallRuleInfo r)
        => r.Direction.Contains("In", StringComparison.OrdinalIgnoreCase)
           && r.Action.Contains("Allow", StringComparison.OrdinalIgnoreCase);

    public static bool IsPrivateOnly(FirewallRuleInfo r)
    {
        var p = r.Profiles ?? "";
        if (string.IsNullOrWhiteSpace(p) || p.Equals("Any", StringComparison.OrdinalIgnoreCase))
            return false;
        // Must include Private and must NOT include Public or Domain unless Private-only listed
        var tokens = p.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var hasPrivate = tokens.Any(t => t.Equals("Private", StringComparison.OrdinalIgnoreCase));
        var hasPublic = tokens.Any(t => t.Equals("Public", StringComparison.OrdinalIgnoreCase));
        var hasDomain = tokens.Any(t => t.Equals("Domain", StringComparison.OrdinalIgnoreCase));
        return hasPrivate && !hasPublic && !hasDomain;
    }

    public static bool IsLocalSubnetScoped(FirewallRuleInfo r)
    {
        var remote = r.RemoteAddresses ?? "";
        if (string.IsNullOrWhiteSpace(remote)) return false;
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

    /// <summary>SMB-In / Spooler-related FPS inbound rules acceptable after FilePrintShare repair.</summary>
    public static bool IsScopedFilePrintShareRule(FirewallRuleInfo r)
    {
        if (!r.Enabled || !IsInboundAllow(r) || IsGpoManaged(r)) return false;
        if (!IsPrivateOnly(r)) return false;
        // Prefer LocalSubnet; accept if RemoteAddresses empty only when LocalPorts is SMB/printer set AND profiles private
        var remoteOk = IsLocalSubnetScoped(r)
                       || string.IsNullOrWhiteSpace(r.RemoteAddresses); // some stock FPS rules use default scope
        if (!remoteOk) return false;

        var group = r.Grouping ?? "";
        var id = r.RuleId ?? r.Name ?? "";
        var inGroup = group.Contains("FirewallAPI.dll,-28502", StringComparison.OrdinalIgnoreCase)
                      || group.Contains("File and Printer", StringComparison.OrdinalIgnoreCase)
                      || group.Contains("Tệp và máy in", StringComparison.OrdinalIgnoreCase)
                      || id.StartsWith("FPS-", StringComparison.OrdinalIgnoreCase);
        if (!inGroup) return false;

        // Must be a useful share rule (SMB 445 or RPC 135/139 or Spooler) — not ICMP-only
        var proto = r.Protocol ?? "";
        var ports = r.LocalPorts ?? "";
        if (proto.Contains("ICMP", StringComparison.OrdinalIgnoreCase)) return false;
        return ports.Contains("445") || ports.Contains("139") || ports.Contains("135")
               || ports.Equals("RPC", StringComparison.OrdinalIgnoreCase)
               || id.Contains("SMB", StringComparison.OrdinalIgnoreCase)
               || id.Contains("Spooler", StringComparison.OrdinalIgnoreCase)
               || id.Contains("NBSession", StringComparison.OrdinalIgnoreCase);
    }

    public static bool MatchesBackupSnapshot(FirewallRuleInfo current, FirewallRuleInfo expected)
        => string.Equals(current.RuleId ?? current.Name, expected.RuleId ?? expected.Name, StringComparison.OrdinalIgnoreCase)
           && current.Enabled == expected.Enabled
           && string.Equals(Normalize(current.Profiles), Normalize(expected.Profiles), StringComparison.OrdinalIgnoreCase)
           && string.Equals(Normalize(current.Direction), Normalize(expected.Direction), StringComparison.OrdinalIgnoreCase)
           && string.Equals(Normalize(current.Action), Normalize(expected.Action), StringComparison.OrdinalIgnoreCase)
           && string.Equals(Normalize(current.Protocol), Normalize(expected.Protocol), StringComparison.OrdinalIgnoreCase)
           && string.Equals(Normalize(current.LocalPorts), Normalize(expected.LocalPorts), StringComparison.OrdinalIgnoreCase)
           && string.Equals(Normalize(current.RemoteAddresses), Normalize(expected.RemoteAddresses), StringComparison.OrdinalIgnoreCase)
           && string.Equals(Normalize(current.IcmpTypesAndCodes), Normalize(expected.IcmpTypesAndCodes), StringComparison.OrdinalIgnoreCase);

    private static string Normalize(string? s) => (s ?? "").Trim();
}
