namespace MyPC.LanPrintDoctor.Platform.Windows;

/// <summary>
/// Documented NetSecurity parameter sets used by PrintDoctor (Microsoft Learn).
/// Used by regression tests to fail closed on invalid parameter binding — not string-only smoke.
/// </summary>
public static class NetSecurityCommandCatalog
{
    /// <summary>Parameters valid on Set-NetFirewallAddressFilter (InputObject set). AssociatedNetFirewallRule is NOT valid here.</summary>
    public static readonly HashSet<string> SetNetFirewallAddressFilterParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "InputObject", "LocalAddress", "RemoteAddress", "PolicyStore", "GPOSession",
        "CimSession", "ThrottleLimit", "AsJob", "PassThru", "WhatIf", "Confirm"
    };

    /// <summary>Parameters valid on Get-NetFirewallAddressFilter including AssociatedNetFirewallRule.</summary>
    public static readonly HashSet<string> GetNetFirewallAddressFilterParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "AssociatedNetFirewallRule", "AssociatedNetIPsecRule", "AssociatedNetIPsecMainModeRule",
        "PolicyStore", "GPOSession", "All", "CimSession", "ThrottleLimit", "AsJob"
    };

    /// <summary>Set-NetFirewallRule supports -RemoteAddress directly (preferred mutation path).</summary>
    public static readonly HashSet<string> SetNetFirewallRuleParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "Name", "DisplayName", "Enabled", "Profile", "Direction", "Action", "RemoteAddress", "LocalAddress",
        "Protocol", "LocalPort", "RemotePort", "Program", "Service", "InterfaceAlias", "InterfaceType",
        "EdgeTraversalPolicy", "PolicyStore", "GPOSession", "CimSession", "PassThru", "WhatIf", "Confirm"
    };

    public static bool IsInvalidSetAddressFilterUsage(string script)
        => script.Contains("Set-NetFirewallAddressFilter", StringComparison.OrdinalIgnoreCase)
           && script.Contains("-AssociatedNetFirewallRule", StringComparison.OrdinalIgnoreCase);

    public static bool UsesPreferredRemoteAddressMutation(string script)
        => script.Contains("Set-NetFirewallRule", StringComparison.OrdinalIgnoreCase)
           && script.Contains("-RemoteAddress", StringComparison.OrdinalIgnoreCase)
           && !IsInvalidSetAddressFilterUsage(script);
}
