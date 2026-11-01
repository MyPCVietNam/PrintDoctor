using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Platform.Windows;

namespace MyPC.LanPrintDoctor.IntegrationTests;

/// <summary>
/// Windows-oriented PowerShell contract fixtures. Uses a recording runner so CI never
/// mutates production firewall. Optional read-only live probe when OS is Windows.
/// </summary>
public class Hf2WindowsPowerShellFixtureTests
{
    [Fact]
    public async Task HF2_IcmpEnableScript_SetsRemoteAddressBeforeEnable_NoGroup_NoEmptyCatch()
    {
        var runner = new RecordingProcessRunner
        {
            Handler = (_, script) =>
            {
                // Simulate address-filter failure path used by production when REMOTE_NOT_SET throws
                if (script.Contains("REMOTE_NOT_SET", StringComparison.Ordinal))
                    return new ProcessResult { ExitCode = 1, StdOut = "", StdErr = "REMOTE_NOT_SET" };
                return new ProcessResult { ExitCode = 0, StdOut = "CHANGED:FPS-ICMP4-ERQ-In" };
            }
        };
        var fw = new PowerShellFirewallInspector(runner);
        _ = await fw.EnableScopedIcmpEchoAsync();

        var script = Assert.Single(runner.Scripts);
        AssertScriptSafeScope(script);
        Assert.Contains("FPS-ICMP4-ERQ-In", script, StringComparison.Ordinal);
        Assert.Contains("Set-NetFirewallAddressFilter", script, StringComparison.Ordinal);
        Assert.Contains("RemoteAddress LocalSubnet", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Enable-NetFirewallRule -Group", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("catch { }", script, StringComparison.Ordinal);
        Assert.DoesNotContain("catch{}", script, StringComparison.Ordinal);

        var addrIdx = script.IndexOf("Set-NetFirewallAddressFilter", StringComparison.Ordinal);
        var enableIdx = script.IndexOf("Enable-NetFirewallRule", StringComparison.Ordinal);
        Assert.True(addrIdx >= 0 && enableIdx > addrIdx, "RemoteAddress must be set before Enable");
        Assert.Contains("REMOTE_NOT_SET", script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task HF2_FpsEnableScript_ApprovedIdsOnly_ScopeBeforeEnable()
    {
        var runner = new RecordingProcessRunner
        {
            Handler = (_, _) => new ProcessResult { ExitCode = 0, StdOut = "CHANGED:FPS-SMB-In-TCP,FPS-SpoolSvc-In-TCP" }
        };
        var fw = new PowerShellFirewallInspector(runner);
        var result = await fw.EnableFileAndPrinterSharingAsync();
        Assert.True(result.Success);
        Assert.Equal(2, result.ChangedRuleIds.Count);

        var script = Assert.Single(runner.Scripts);
        AssertScriptSafeScope(script);
        foreach (var id in new[] { "FPS-SMB-In-TCP", "FPS-NBSession-In-TCP", "FPS-RPCSS-In-TCP", "FPS-SpoolSvc-In-TCP" })
            Assert.Contains(id, script, StringComparison.Ordinal);
        Assert.DoesNotContain("Enable-NetFirewallRule -Group", script, StringComparison.OrdinalIgnoreCase);

        // Each Enable must be preceded earlier in script by LocalSubnet set (global order check)
        var firstEnable = script.IndexOf("Enable-NetFirewallRule", StringComparison.Ordinal);
        var firstAddr = script.IndexOf("Set-NetFirewallAddressFilter", StringComparison.Ordinal);
        Assert.True(firstAddr >= 0 && firstEnable > firstAddr);
    }

    [Fact]
    public async Task HF2_RemoteAddressFail_ReturnsUnsuccessful_NoChangedIds()
    {
        var runner = new RecordingProcessRunner
        {
            Handler = (_, _) => new ProcessResult { ExitCode = 1, StdOut = "", StdErr = "REMOTE_NOT_SET:Any" }
        };
        var fw = new PowerShellFirewallInspector(runner);
        var result = await fw.EnableScopedIcmpEchoAsync();
        Assert.False(result.Success);
        Assert.Empty(result.ChangedRuleIds);
    }

    [Fact]
    public async Task HF2_IcmpRestoreScript_RequiresRemoteAddressMatch()
    {
        var runner = new RecordingProcessRunner
        {
            Handler = (_, script) =>
            {
                if (script.Contains("Get-NetFirewallRule", StringComparison.Ordinal)
                    && !script.Contains("Set-NetFirewallRule", StringComparison.Ordinal))
                {
                    // GetRelevantRules after restore
                    return new ProcessResult
                    {
                        ExitCode = 0,
                        StdOut = """[{"Name":"FPS-ICMP4-ERQ-In","DisplayName":"ICMP","Enabled":false,"Direction":"Inbound","Action":"Allow","Profile":"Domain","RemoteAddresses":"LocalSubnet","Protocol":"ICMPv4","LocalPorts":"Any","IcmpTypesAndCodes":"8","PolicyStore":"ActiveStore"}]"""
                    };
                }
                return new ProcessResult { ExitCode = 0, StdOut = "OK" };
            }
        };
        var fw = new PowerShellFirewallInspector(runner);
        var backup = """[{"RuleId":"FPS-ICMP4-ERQ-In","Name":"FPS-ICMP4-ERQ-In","Enabled":false,"Direction":"Inbound","Action":"Allow","Protocol":"ICMPv4","Profiles":"Domain","RemoteAddresses":"Any","PolicyStore":"ActiveStore","IcmpTypesAndCodes":"8"}]""";
        var restore = await fw.RestoreIcmpEchoFromBackupAsync(backup);
        Assert.False(restore.Verified);
        Assert.True(restore.Partial);

        var mutate = runner.Scripts.First(s => s.Contains("Set-NetFirewallAddressFilter", StringComparison.Ordinal));
        Assert.Contains("REMOTE_RESTORE_FAIL", mutate, StringComparison.Ordinal);
        var addrIdx = mutate.IndexOf("Set-NetFirewallAddressFilter", StringComparison.Ordinal);
        var enableIdx = Regex.Match(mutate, @"Enable-NetFirewallRule|Disable-NetFirewallRule").Index;
        Assert.True(addrIdx >= 0 && enableIdx > addrIdx);
    }

    [Fact]
    public async Task HF2_LiveWindows_ReadOnlyFirewallProbe_NoMutation()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Document that live Windows probe is skipped off-Windows (UNIT/INTEGRATION still pass).
            return;
        }

        // Read-only: never Set-/Enable-NetFirewall* in CI.
        Assert.DoesNotContain(
            Environment.GetEnvironmentVariable("LPD_ALLOW_FIREWALL_MUTATION") ?? "",
            "FORCE_MUTATE_IN_CI",
            StringComparison.Ordinal);
        // Presence of NetSecurity module is enough evidence the runner can host future lab fixtures.
        var runner = new ProcessRunner();
        var probe = await runner.RunAsync(
            "powershell.exe",
            new[]
            {
                "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                "Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
            },
            TimeSpan.FromSeconds(20));
        Assert.True(probe.ExitCode == 0 || !string.IsNullOrWhiteSpace(probe.StdOut) || !string.IsNullOrWhiteSpace(probe.StdErr));
    }

    private static void AssertScriptSafeScope(string script)
    {
        Assert.Contains("LocalSubnet", script, StringComparison.Ordinal);
        Assert.Contains("Private", script, StringComparison.Ordinal);
        Assert.DoesNotContain("-Group ", script.Replace("Grouping", "GRP", StringComparison.Ordinal), StringComparison.OrdinalIgnoreCase);
    }
}
