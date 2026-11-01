using MyPC.LanPrintDoctor.Abstractions.Firewall;

namespace MyPC.LanPrintDoctor.Firewall;

public sealed class FirewallDiagnosticService
{
    private readonly IFirewallInspector _inspector;
    public FirewallDiagnosticService(IFirewallInspector inspector) => _inspector = inspector;

    public Task<IReadOnlyList<FirewallProfileState>> GetProfilesAsync(CancellationToken ct = default)
        => _inspector.GetProfilesAsync(ct);

    public static bool IsIcmpEchoRule(FirewallRuleInfo rule)
        => (rule.Name?.Contains("Echo Request", StringComparison.OrdinalIgnoreCase) ?? false)
           || (rule.Protocol?.Equals("ICMPv4", StringComparison.OrdinalIgnoreCase) ?? false);
}
