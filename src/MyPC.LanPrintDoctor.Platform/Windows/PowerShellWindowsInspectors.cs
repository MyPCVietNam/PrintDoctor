using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Printing;
using MyPC.LanPrintDoctor.Abstractions.Security;
using MyPC.LanPrintDoctor.Abstractions.Services;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;
using MyPC.LanPrintDoctor.Abstractions.Smb;
using MyPC.LanPrintDoctor.Abstractions.Validation;

namespace MyPC.LanPrintDoctor.Platform.Windows;

public sealed class PowerShellWindowsServiceInspector : IWindowsServiceInspector
{
    private readonly IProcessRunner _runner;
    public PowerShellWindowsServiceInspector(IProcessRunner runner) => _runner = runner;

    public async Task<WindowsServiceInfo?> GetServiceAsync(string serviceName, CancellationToken ct = default)
        => (await GetServicesAsync(new[] { serviceName }, ct)).FirstOrDefault();

    public async Task<IReadOnlyList<WindowsServiceInfo>> GetServicesAsync(IEnumerable<string> serviceNames, CancellationToken ct = default)
    {
        var names = string.Join("','", serviceNames.Select(EscapePs));
        var script = $"Get-Service -Name @('{names}') -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return serviceNames.Select(n => new WindowsServiceInfo { Name = n, Status = "Unknown" }).ToList();
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            return PowerShellJson.Enumerate(doc.RootElement).Select(el => new WindowsServiceInfo
            {
                Name = PowerShellJson.GetString(el, "Name") ?? "",
                DisplayName = PowerShellJson.GetString(el, "DisplayName"),
                Status = PowerShellJson.NormalizeServiceStatus(el),
                StartType = PowerShellJson.NormalizeStartType(el)
            }).ToList();
        }
        catch
        {
            return serviceNames.Select(n => new WindowsServiceInfo { Name = n, Status = "Unknown" }).ToList();
        }
    }

    public async Task<bool> StartServiceAsync(string serviceName, CancellationToken ct = default)
    {
        var script = $"Start-Service -Name '{EscapePs(serviceName)}'; (Get-Service -Name '{EscapePs(serviceName)}').Status";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        return result.ExitCode == 0 && result.StdOut.Contains("Running", StringComparison.OrdinalIgnoreCase);
    }

    public async Task<bool> RestartServiceAsync(string serviceName, CancellationToken ct = default)
    {
        var script = $"Restart-Service -Name '{EscapePs(serviceName)}' -Force; (Get-Service -Name '{EscapePs(serviceName)}').Status";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        return result.ExitCode == 0 && result.StdOut.Contains("Running", StringComparison.OrdinalIgnoreCase);
    }

    private static string EscapePs(string value) => value.Replace("'", "''");
}

public sealed class PowerShellFirewallInspector : IFirewallInspector
{
    private readonly IProcessRunner _runner;
    private ProbeOutcome _thirdPartyStatus = ProbeOutcome.Unknown;

    public PowerShellFirewallInspector(IProcessRunner runner) => _runner = runner;

    public async Task<IReadOnlyList<FirewallProfileState>> GetProfilesAsync(CancellationToken ct = default)
    {
        const string script = "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress";
        var result = await Run(script, ct);
        if (result is null) return Array.Empty<FirewallProfileState>();
        using var doc = JsonDocument.Parse(result);
        return PowerShellJson.Enumerate(doc.RootElement).Select(el =>
        {
            var name = (PowerShellJson.GetString(el, "Name") ?? "").ToLowerInvariant();
            return new FirewallProfileState
            {
                Profile = name switch
                {
                    "domain" or "1" => FirewallProfileKind.Domain,
                    "private" or "2" => FirewallProfileKind.Private,
                    _ => FirewallProfileKind.Public
                },
                Enabled = el.TryGetProperty("Enabled", out var en) && PowerShellJson.IsTruthy(en),
                DefaultInboundAction = PowerShellJson.GetString(el, "DefaultInboundAction"),
                DefaultOutboundAction = PowerShellJson.GetString(el, "DefaultOutboundAction")
            };
        }).ToList();
    }

    public async Task<IReadOnlyList<FirewallRuleInfo>> GetRelevantRulesAsync(CancellationToken ct = default)
    {
        // Language-independent: rule Name (FPS-*) + group id + protocol/port filters
        const string script = @"
$rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -match 'FPS-|CoreNet-ICMP|SMB' -or $_.Group -eq '@FirewallAPI.dll,-28502' -or $_.DisplayName -match 'Echo|ICMP|ShaPrint|48631|48633|SMB|File and Printer|Tệp và máy in|Chia sẻ tệp'
} | Select-Object -First 120
$result = foreach ($r in $rules) {
  $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue | Select-Object -First 1
  $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue | Select-Object -First 1
  [pscustomobject]@{
    Name = $r.Name
    DisplayName = $r.DisplayName
    Enabled = [bool]$r.Enabled
    Direction = [string]$r.Direction
    Action = [string]$r.Action
    Profile = [string]$r.Profile
    Grouping = [string]$r.Group
    Protocol = [string]$port.Protocol
    LocalPorts = [string]$port.LocalPort
    RemoteAddresses = [string]$addr.RemoteAddress
  }
}
$result | ConvertTo-Json -Compress
";
        var raw = await Run(script, ct);
        if (raw is null) return Array.Empty<FirewallRuleInfo>();
        try
        {
            using var doc = JsonDocument.Parse(raw);
            return PowerShellJson.Enumerate(doc.RootElement).Select(el => new FirewallRuleInfo
            {
                RuleId = PowerShellJson.GetString(el, "Name"),
                Name = PowerShellJson.GetString(el, "DisplayName") ?? PowerShellJson.GetString(el, "Name") ?? "",
                DisplayName = PowerShellJson.GetString(el, "DisplayName"),
                Enabled = el.TryGetProperty("Enabled", out var en) && PowerShellJson.IsTruthy(en),
                Direction = PowerShellJson.GetString(el, "Direction") ?? "",
                Action = PowerShellJson.GetString(el, "Action") ?? "",
                Profiles = PowerShellJson.GetString(el, "Profile"),
                Grouping = PowerShellJson.GetString(el, "Grouping"),
                Protocol = PowerShellJson.GetString(el, "Protocol"),
                LocalPorts = PowerShellJson.GetString(el, "LocalPorts"),
                RemoteAddresses = PowerShellJson.GetString(el, "RemoteAddresses")
            }).ToList();
        }
        catch
        {
            return Array.Empty<FirewallRuleInfo>();
        }
    }

    public async Task<IReadOnlyList<ThirdPartySecurityProduct>> DetectThirdPartySecurityAsync(CancellationToken ct = default)
    {
        const string script = @"
try {
  $items = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct,FirewallProduct -ErrorAction Stop |
    Select-Object displayName, companyName, __CLASS
  if (-not $items) { '[]' } else { $items | ConvertTo-Json -Compress }
} catch { 'ERROR:' + $_.Exception.Message }
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        var stdout = result.StdOut.Trim();
        if (result.ExitCode != 0 || stdout.StartsWith("ERROR:", StringComparison.OrdinalIgnoreCase))
        {
            _thirdPartyStatus = ProbeOutcome.Unknown;
            return Array.Empty<ThirdPartySecurityProduct>();
        }

        if (string.IsNullOrWhiteSpace(stdout) || stdout == "[]")
        {
            _thirdPartyStatus = ProbeOutcome.Pass; // collected successfully, none found
            return Array.Empty<ThirdPartySecurityProduct>();
        }

        try
        {
            using var doc = JsonDocument.Parse(stdout);
            _thirdPartyStatus = ProbeOutcome.Pass;
            return PowerShellJson.Enumerate(doc.RootElement).Select(el => new ThirdPartySecurityProduct
            {
                Name = PowerShellJson.GetString(el, "displayName") ?? "Unknown",
                Vendor = PowerShellJson.GetString(el, "companyName"),
                Kind = PowerShellJson.GetString(el, "__CLASS"),
                CollectionStatus = ProbeOutcome.Pass
            }).Where(p => !p.Name.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase)
                          && !p.Name.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase)).ToList();
        }
        catch
        {
            _thirdPartyStatus = ProbeOutcome.Unknown;
            return Array.Empty<ThirdPartySecurityProduct>();
        }
    }

    public Task<ProbeOutcome> GetThirdPartyCollectionStatusAsync(CancellationToken ct = default)
        => Task.FromResult(_thirdPartyStatus);

    public async Task<bool> EnableScopedIcmpEchoAsync(CancellationToken ct = default)
    {
        const string script = @"
$r = Get-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -ErrorAction SilentlyContinue
if (-not $r) { throw 'FPS-ICMP4-ERQ-In not found' }
Enable-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In'
Set-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -Profile Private -ErrorAction SilentlyContinue
Set-NetFirewallAddressFilter -AssociatedNetFirewallRule (Get-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In') -RemoteAddress LocalSubnet -ErrorAction SilentlyContinue
$v = Get-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In'
if ($v.Enabled -ne $true) { throw 'verify failed' }
'OK'
";
        var raw = await Run(script, ct);
        return raw?.Contains("OK", StringComparison.Ordinal) == true;
    }

    public async Task<bool> RestoreIcmpEchoFromBackupAsync(string backupJson, CancellationToken ct = default)
    {
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(backupJson) ? "[]" : backupJson);
            var prior = PowerShellJson.Enumerate(doc.RootElement)
                .FirstOrDefault(el => (PowerShellJson.GetString(el, "RuleId") ?? PowerShellJson.GetString(el, "Name") ?? "")
                    .Contains("FPS-ICMP4-ERQ-In", StringComparison.OrdinalIgnoreCase)
                    || (PowerShellJson.GetString(el, "DisplayName") ?? "").Contains("Echo", StringComparison.OrdinalIgnoreCase));
            var wasEnabled = prior.ValueKind != JsonValueKind.Undefined
                             && prior.TryGetProperty("Enabled", out var en)
                             && PowerShellJson.IsTruthy(en);
            var script = wasEnabled
                ? "Enable-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In'; 'OK'"
                : "Disable-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In'; 'OK'";
            var raw = await Run(script, ct);
            return raw?.Contains("OK", StringComparison.Ordinal) == true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> EnableFileAndPrinterSharingAsync(CancellationToken ct = default)
    {
        // Language-independent group resource id for File and Printer Sharing
        const string script = @"
Enable-NetFirewallRule -Group '@FirewallAPI.dll,-28502' -ErrorAction SilentlyContinue
Get-NetFirewallRule -Group '@FirewallAPI.dll,-28502' -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' -and $_.Profile -match 'Private|Any' } | Enable-NetFirewallRule -ErrorAction SilentlyContinue
$enabled = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-28502' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true -and $_.Direction -eq 'Inbound' }).Count
if ($enabled -lt 1) { throw 'no rules enabled' }
'OK'
";
        var raw = await Run(script, ct);
        return raw?.Contains("OK", StringComparison.Ordinal) == true;
    }

    public async Task<bool> RestoreFileAndPrinterSharingFromBackupAsync(string backupJson, CancellationToken ct = default)
    {
        // Best-effort: re-apply Enabled flags from backup for FPS-* rules only
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(backupJson) ? "[]" : backupJson);
            foreach (var el in PowerShellJson.Enumerate(doc.RootElement))
            {
                var id = PowerShellJson.GetString(el, "RuleId") ?? PowerShellJson.GetString(el, "Name");
                if (string.IsNullOrWhiteSpace(id)) continue;
                if (!id.StartsWith("FPS-", StringComparison.OrdinalIgnoreCase)
                    && !(PowerShellJson.GetString(el, "Grouping")?.Contains("FirewallAPI.dll,-28502") ?? false))
                    continue;
                var enabled = el.TryGetProperty("Enabled", out var en) && PowerShellJson.IsTruthy(en);
                var script = enabled
                    ? $"Enable-NetFirewallRule -Name '{Escape(id)}'; 'OK'"
                    : $"Disable-NetFirewallRule -Name '{Escape(id)}'; 'OK'";
                await Run(script, ct);
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task<string?> Run(string script, CancellationToken ct)
    {
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(60), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut)) return null;
        return result.StdOut.Trim();
    }

    private static string Escape(string value) => value.Replace("'", "''");
}

public sealed class PowerShellNetworkProfileService : INetworkProfileService
{
    private readonly IProcessRunner _runner;
    public PowerShellNetworkProfileService(IProcessRunner runner) => _runner = runner;

    public async Task<IReadOnlyList<NetworkConnectionProfile>> GetConnectionProfilesAsync(CancellationToken ct = default)
    {
        const string script = "Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,InterfaceIndex,NetworkCategory | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<NetworkConnectionProfile>();
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            return PowerShellJson.Enumerate(doc.RootElement).Select(el =>
            {
                var cat = PowerShellJson.GetString(el, "NetworkCategory") ?? "Unknown";
                cat = cat switch { "0" => "Public", "1" => "Private", "2" => "DomainAuthenticated", _ => cat };
                return new NetworkConnectionProfile
                {
                    Name = PowerShellJson.GetString(el, "Name"),
                    InterfaceAlias = PowerShellJson.GetString(el, "InterfaceAlias"),
                    InterfaceIndex = PowerShellJson.GetInt(el, "InterfaceIndex") ?? 0,
                    NetworkCategory = cat,
                    IsDomainManaged = cat.Equals("DomainAuthenticated", StringComparison.OrdinalIgnoreCase)
                };
            }).ToList();
        }
        catch
        {
            return Array.Empty<NetworkConnectionProfile>();
        }
    }

    public async Task<bool> SetPrivateAsync(int interfaceIndex, CancellationToken ct = default)
        => await SetCategoryAsync(interfaceIndex, "Private", ct);

    public async Task<bool> SetCategoryAsync(int interfaceIndex, string category, CancellationToken ct = default)
    {
        if (category.Equals("DomainAuthenticated", StringComparison.OrdinalIgnoreCase))
            return false;
        var script = $"Set-NetConnectionProfile -InterfaceIndex {interfaceIndex} -NetworkCategory {category}; (Get-NetConnectionProfile -InterfaceIndex {interfaceIndex}).NetworkCategory";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        return result.ExitCode == 0 && result.StdOut.Contains(category, StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class PowerShellSmbInspector : ISmbInspector
{
    private readonly IProcessRunner _runner;
    private readonly INetworkProbe _probe;

    public PowerShellSmbInspector(IProcessRunner runner, INetworkProbe probe)
    {
        _runner = runner;
        _probe = probe;
    }

    public async Task<SmbConfiguration> GetConfigurationAsync(CancellationToken ct = default)
    {
        const string script = "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature,EnableInsecureGuestLogons | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return new SmbConfiguration { Notes = "Unable to read SMB configuration", CollectionStatus = ProbeOutcome.Unknown };
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            var el = doc.RootElement;
            return new SmbConfiguration
            {
                EnableSMB1Protocol = el.TryGetProperty("EnableSMB1Protocol", out var s1) ? PowerShellJson.IsTruthy(s1) : null,
                RequireSecuritySignature = el.TryGetProperty("RequireSecuritySignature", out var sig) ? PowerShellJson.IsTruthy(sig) : null,
                EnableInsecureGuestLogons = el.TryGetProperty("EnableInsecureGuestLogons", out var g) ? PowerShellJson.IsTruthy(g) : null,
                CollectionStatus = ProbeOutcome.Pass
            };
        }
        catch
        {
            return new SmbConfiguration { CollectionStatus = ProbeOutcome.Unknown, Notes = "JSON parse failed" };
        }
    }

    public async Task<IReadOnlyList<ShareInfo>> GetSharesAsync(CancellationToken ct = default)
    {
        const string script = "Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name,Path,Description | ConvertTo-Json -Compress";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(30), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
            return Array.Empty<ShareInfo>();
        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            return PowerShellJson.Enumerate(doc.RootElement).Select(el => new ShareInfo
            {
                Name = PowerShellJson.GetString(el, "Name") ?? "",
                Path = PowerShellJson.GetString(el, "Path"),
                Description = PowerShellJson.GetString(el, "Description")
            }).ToList();
        }
        catch
        {
            return Array.Empty<ShareInfo>();
        }
    }

    public async Task<SmbProbeResult> ProbeRemoteAsync(string host, CancellationToken ct = default)
    {
        if (!InputValidator.TryParseHost(host, out var safe))
            return new SmbProbeResult { Target = host, Tcp445 = ProbeOutcome.Fail, Detail = "invalid host" };

        var t445 = await _probe.TcpConnectAsync(safe, 445, TimeSpan.FromSeconds(3), ct);
        var t135 = await _probe.TcpConnectAsync(safe, 135, TimeSpan.FromSeconds(3), ct);
        var unc = ProbeOutcome.NotTested;
        var detail = $"445={t445.Outcome};135={t135.Outcome}";

        if (t445.Outcome == ProbeOutcome.Pass)
        {
            // Attempt non-destructive UNC probe; distinguish auth denied vs unreachable vs not tested
            var uncPath = $@"\\{safe}\IPC$";
            var script = $@"
$path = '{uncPath.Replace("'", "''")}'
try {{
  $r = Test-Path -LiteralPath $path -ErrorAction Stop
  if ($r) {{ 'PASS' }} else {{ 'FAIL' }}
}} catch {{
  $m = $_.Exception.Message
  if ($m -match 'Access is denied|Logon failure|AccessDenied|đăng nhập|từ chối') {{ 'AUTH_DENIED' }}
  elseif ($m -match 'network path was not found|The network name cannot be found|không tìm thấy') {{ 'FAIL' }}
  else {{ 'UNKNOWN:' + $m }}
}}
";
            var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(15), ct);
            var outp = result.StdOut.Trim();
            unc = outp switch
            {
                "PASS" => ProbeOutcome.Pass,
                "FAIL" => ProbeOutcome.Fail,
                "AUTH_DENIED" => ProbeOutcome.AuthDenied,
                _ when outp.StartsWith("UNKNOWN", StringComparison.OrdinalIgnoreCase) => ProbeOutcome.Unknown,
                _ when result.ExitCode != 0 => ProbeOutcome.Unknown,
                _ => ProbeOutcome.Unknown
            };
            detail += $";UNC={unc}:{outp}";
        }
        else
        {
            detail += ";UNC=NotTested(tcp445-not-open)";
        }

        return new SmbProbeResult
        {
            Target = safe,
            Tcp445 = t445.Outcome,
            Tcp135 = t135.Outcome,
            Unc = unc,
            Detail = detail
        };
    }

    public async Task<SharingToggleState> GetSharingTogglesAsync(CancellationToken ct = default)
    {
        // Use firewall group enablement + NetConnectionProfile — not hard-coded true/true
        const string script = @"
$fps = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-28502' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true -and $_.Direction -eq 'Inbound' }).Count
$nd = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-32752' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true -and $_.Direction -eq 'Inbound' }).Count
# Network Discovery group id @FirewallAPI.dll,-32752
[pscustomobject]@{ FilePrintEnabled = ($fps -gt 0); NetworkDiscoveryEnabled = ($nd -gt 0); FpsCount = $fps; NdCount = $nd } | ConvertTo-Json -Compress
";
        var result = await _runner.RunAsync("powershell.exe", new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script }, TimeSpan.FromSeconds(45), ct);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
        {
            return new SharingToggleState
            {
                NetworkDiscovery = ProbeOutcome.Unknown,
                FileAndPrinterSharing = ProbeOutcome.Unknown,
                Detail = "collector failed or insufficient rights"
            };
        }

        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            var el = doc.RootElement;
            var fps = el.TryGetProperty("FilePrintEnabled", out var f) && PowerShellJson.IsTruthy(f);
            var nd = el.TryGetProperty("NetworkDiscoveryEnabled", out var n) && PowerShellJson.IsTruthy(n);
            return new SharingToggleState
            {
                FileAndPrinterSharing = fps ? ProbeOutcome.Pass : ProbeOutcome.Fail,
                NetworkDiscovery = nd ? ProbeOutcome.Pass : ProbeOutcome.Fail,
                Detail = result.StdOut.Trim()
            };
        }
        catch
        {
            return new SharingToggleState { NetworkDiscovery = ProbeOutcome.Unknown, FileAndPrinterSharing = ProbeOutcome.Unknown, Detail = "parse error" };
        }
    }
}
